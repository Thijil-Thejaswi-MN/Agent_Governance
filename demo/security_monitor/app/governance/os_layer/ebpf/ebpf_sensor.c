#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sensor.h"
#include "sensor.skel.h"

#define VERSION "1.0.0"
#define MAX_CLIENTS 64

static volatile sig_atomic_t stop_requested = 0;
static unsigned long long g_seq = 0;
static unsigned long long g_events_total = 0;
static int g_num_cpus = 1;

static struct sensor_bpf *g_skel = NULL;
static struct ring_buffer *g_rb = NULL;

struct client_conn {
    int fd;
    uint64_t watched_cgroup;
    int is_active;
};

static struct client_conn g_clients[MAX_CLIENTS];

static void sig_handler(int sig) {
    (void)sig;
    stop_requested = 1;
}

static void now_iso(char *buf, size_t len, long long *ms_out) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_buf;
    gmtime_r(&ts.tv_sec, &tm_buf);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    snprintf(buf, len, "%s.%03ldZ", base, ts.tv_nsec / 1000000);
    *ms_out = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint64_t get_total_dropped(void) {
    if (!g_skel) return 0;
    int fd = bpf_map__fd(g_skel->maps.dropped_events);
    if (fd < 0) return 0;
    uint64_t vals[g_num_cpus];
    memset(vals, 0, sizeof(vals));
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals) != 0) {
        return 0;
    }
    uint64_t total = 0;
    for (int i = 0; i < g_num_cpus; i++) {
        total += vals[i];
    }
    return total;
}

static int register_cgroup(uint64_t cgid) {
    if (!g_skel || cgid == 0) return -1;
    int fd = bpf_map__fd(g_skel->maps.task_cgroups);
    if (fd < 0) return -1;
    uint32_t val = 1;
    return bpf_map_update_elem(fd, &cgid, &val, BPF_ANY);
}

static int unregister_cgroup(uint64_t cgid) {
    if (!g_skel || cgid == 0) return -1;
    int fd = bpf_map__fd(g_skel->maps.task_cgroups);
    if (fd < 0) return -1;
    return bpf_map_delete_elem(fd, &cgid);
}

static const char *op_to_name(uint32_t op) {
    switch (op) {
    case EBPF_OP_OPEN: return "open";
    case EBPF_OP_EXEC: return "exec";
    case EBPF_OP_CONNECT: return "connect";
    case EBPF_OP_BIND: return "bind";
    case EBPF_OP_LISTEN: return "listen";
    case EBPF_OP_ACCEPT: return "accept";
    case EBPF_OP_SEND: return "send";
    case EBPF_OP_UNLINK: return "unlink";
    case EBPF_OP_RENAME: return "rename";
    case EBPF_OP_MKDIR: return "mkdir";
    case EBPF_OP_CLONE: return "clone";
    case EBPF_OP_EXIT: return "exit";
    default: return "unknown";
    }
}

static const char *syscall_nr_to_name(int nr) {
    switch (nr) {
    case 2: return "open";
    case 42: return "connect";
    case 43: return "accept";
    case 44: return "sendto";
    case 46: return "sendmsg";
    case 49: return "bind";
    case 50: return "listen";
    case 56: return "clone";
    case 57: return "fork";
    case 58: return "vfork";
    case 59: return "execve";
    case 60: return "exit";
    case 82: return "rename";
    case 83: return "mkdir";
    case 87: return "unlink";
    case 231: return "exit_group";
    case 257: return "openat";
    case 258: return "mkdirat";
    case 263: return "unlinkat";
    case 264: return "renameat";
    case 288: return "accept4";
    case 316: return "renameat2";
    case 322: return "execveat";
    case 435: return "clone3";
    case 437: return "openat2";
    default: return "unknown";
    }
}

static void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (*p < 0x20 || *p >= 0x7f) {
                fprintf(f, "\\u%04x", *p);
            } else {
                fputc(*p, f);
            }
        }
    }
    fputc('"', f);
}

static void describe_sock(const char *raw, uint32_t len, char *out_buf, size_t out_len) {
    if (len < sizeof(sa_family_t)) {
        snprintf(out_buf, out_len, "sockaddr:unreadable");
        return;
    }
    sa_family_t family = *(const sa_family_t *)raw;
    if (family == AF_INET) {
        if (len < sizeof(struct sockaddr_in)) {
            snprintf(out_buf, out_len, "sockaddr:truncated");
            return;
        }
        const struct sockaddr_in *sin = (const struct sockaddr_in *)raw;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(out_buf, out_len, "inet:%s:%u", ip, ntohs(sin->sin_port));
    } else if (family == AF_INET6) {
        if (len < sizeof(struct sockaddr_in6)) {
            snprintf(out_buf, out_len, "sockaddr:truncated");
            return;
        }
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)raw;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(out_buf, out_len, "inet6:[%s]:%u", ip, ntohs(sin6->sin6_port));
    } else if (family == AF_UNIX) {
        const struct sockaddr_un *sun = (const struct sockaddr_un *)raw;
        size_t path_offset = (size_t)((const char *)sun->sun_path - (const char *)sun);
        if (len <= path_offset) {
            snprintf(out_buf, out_len, "unix:unnamed");
        } else if (sun->sun_path[0] == '\0') {
            size_t plen = len - path_offset;
            char abstract_name[108];
            size_t k = plen - 1 < sizeof(abstract_name) - 1 ? plen - 1 : sizeof(abstract_name) - 1;
            memcpy(abstract_name, sun->sun_path + 1, k);
            abstract_name[k] = '\0';
            snprintf(out_buf, out_len, "unix-abstract:@%s", abstract_name);
        } else {
            char name[108];
            size_t plen = len - path_offset;
            size_t k = plen < sizeof(name) - 1 ? plen : sizeof(name) - 1;
            memcpy(name, sun->sun_path, k);
            name[k] = '\0';
            snprintf(out_buf, out_len, "unix:%s", name);
        }
    } else {
        snprintf(out_buf, out_len, "sockaddr:family_%u", (unsigned int)family);
    }
}

static void resolve_abs_path(uint32_t pid, const char *rel, char *out_buf, size_t out_len) {
    if (!rel || rel[0] == '\0') {
        out_buf[0] = '\0';
        return;
    }
    if (rel[0] == '/') {
        snprintf(out_buf, out_len, "%s", rel);
        return;
    }
    char cwd_link[64];
    snprintf(cwd_link, sizeof(cwd_link), "/proc/%u/cwd", (unsigned int)pid);
    char cwd[PATH_MAX];
    ssize_t n = readlink(cwd_link, cwd, sizeof(cwd) - 1);
    if (n > 0) {
        cwd[n] = '\0';
        int w = snprintf(out_buf, out_len, "%s/%s", cwd, rel);
        if (w < 0 || (size_t)w >= out_len) {
            snprintf(out_buf, out_len, "%s", rel);
        }
    } else {
        snprintf(out_buf, out_len, "%s", rel);
    }
}

static void broadcast_line(const char *line, uint64_t cgid) {
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);

    size_t line_len = strlen(line);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].is_active && g_clients[i].fd >= 0) {
            if (cgid == 0 || g_clients[i].watched_cgroup == 0 || g_clients[i].watched_cgroup == cgid) {
                ssize_t w1 = write(g_clients[i].fd, line, line_len);
                ssize_t w2 = write(g_clients[i].fd, "\n", 1);
                (void)w1; (void)w2;
            }
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct ebpf_event)) return 0;
    const struct ebpf_event *e = (const struct ebpf_event *)data;

    g_seq++;
    g_events_total++;

    char ts[48];
    long long ms = 0;
    now_iso(ts, sizeof(ts), &ms);

    char target[PATH_MAX];
    char abs_target[PATH_MAX];
    target[0] = '\0';
    abs_target[0] = '\0';

    if (e->has_sock) {
        describe_sock(e->sock_addr, e->sock_len, target, sizeof(target));
        snprintf(abs_target, sizeof(abs_target), "%s", target);
    } else if (e->has_target) {
        snprintf(target, sizeof(target), "%s", e->target);
        resolve_abs_path(e->pid, e->target, abs_target, sizeof(abs_target));
    } else if (e->op == EBPF_OP_LISTEN || e->op == EBPF_OP_ACCEPT) {
        snprintf(target, sizeof(target), "fd:%d", e->dfd);
        snprintf(abs_target, sizeof(abs_target), "fd:%d", e->dfd);
    }

    char target2[PATH_MAX];
    char abs_target2[PATH_MAX];
    target2[0] = '\0';
    abs_target2[0] = '\0';
    if (e->has_target2) {
        snprintf(target2, sizeof(target2), "%s", e->target2);
        resolve_abs_path(e->pid, e->target2, abs_target2, sizeof(abs_target2));
    }

    const char *result_str = "ok";
    if (e->ret < 0 && e->ret > -4096) {
        const char *en = strerrorname_np((int)(-e->ret));
        result_str = en ? en : "EUNKNOWN";
    }

    const char *target_status_str = "ok";
    if (e->target_status == TARGET_STATUS_TRUNCATED) {
        target_status_str = "truncated";
    } else if (e->target_status == TARGET_STATUS_UNREADABLE) {
        target_status_str = "unreadable";
    }

    uint64_t dropped = get_total_dropped();

    char *line = NULL;
    size_t line_sz = 0;
    FILE *mem = open_memstream(&line, &line_sz);
    if (!mem) return 0;

    fprintf(mem, "{\"source\":\"ebpf_sensor\",\"type\":\"syscall\",\"seq\":%llu,\"timestamp\":\"%s\",\"ts_ms\":%lld,"
                 "\"pid\":%u,\"ppid\":%u,\"cgroup_id\":\"%llu\",\"syscall\":\"%s\",\"op\":\"%s\",\"target\":",
            g_seq, ts, ms, e->pid, e->ppid, (unsigned long long)e->cgroup_id,
            syscall_nr_to_name(e->syscall_nr), op_to_name(e->op));
    json_escape(mem, target);
    fputs(",\"abs_target\":", mem);
    json_escape(mem, abs_target);
    fprintf(mem, ",\"target_status\":\"%s\"", target_status_str);

    if (e->has_target2) {
        fputs(",\"target2\":", mem);
        json_escape(mem, target2);
        fputs(",\"abs_target2\":", mem);
        json_escape(mem, abs_target2);
    }

    if (e->flags) {
        fprintf(mem, ",\"flags\":%llu", (unsigned long long)e->flags);
    }
    if (e->aux) {
        fprintf(mem, ",\"aux\":%llu", (unsigned long long)e->aux);
    }

    fprintf(mem, ",\"ret\":%lld,\"result\":\"%s\",\"dropped\":%llu}",
            (long long)e->ret, result_str, (unsigned long long)dropped);

    fclose(mem);
    if (line) {
        broadcast_line(line, e->cgroup_id);
        free(line);
    }
    return 0;
}

static void emit_heartbeat(void) {
    g_seq++;
    char ts[48];
    long long ms = 0;
    now_iso(ts, sizeof(ts), &ms);
    uint64_t dropped = get_total_dropped();

    char line[512];
    snprintf(line, sizeof(line),
             "{\"source\":\"ebpf_sensor\",\"type\":\"heartbeat\",\"seq\":%llu,\"timestamp\":\"%s\",\"ts_ms\":%lld,"
             "\"events_total\":%llu,\"dropped_total\":%llu,\"version\":\"%s\"}",
             g_seq, ts, ms, (unsigned long long)g_events_total, (unsigned long long)dropped, VERSION);
    broadcast_line(line, 0);
}

static void process_cmd(char *cmd, int client_idx) {
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    char *nl = strchr(cmd, '\n');
    if (nl) *nl = '\0';
    char *cr = strchr(cmd, '\r');
    if (cr) *cr = '\0';
    if (!*cmd) return;

    if (strncmp(cmd, "REGISTER ", 9) == 0 || strncmp(cmd, "WATCH ", 6) == 0 || strncmp(cmd, "ADD ", 4) == 0) {
        char *arg = strchr(cmd, ' ');
        if (arg) {
            uint64_t cgid = strtoull(arg + 1, NULL, 0);
            if (cgid > 0) {
                register_cgroup(cgid);
                if (client_idx >= 0 && client_idx < MAX_CLIENTS) {
                    g_clients[client_idx].watched_cgroup = cgid;
                }
                char ack[128];
                snprintf(ack, sizeof(ack), "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"registered\",\"cgroup_id\":\"%llu\"}",
                         (unsigned long long)cgid);
                broadcast_line(ack, cgid);
                emit_heartbeat();
            }
        }
    } else if (strncmp(cmd, "UNREGISTER ", 11) == 0 || strncmp(cmd, "DEL ", 4) == 0) {
        char *arg = strchr(cmd, ' ');
        if (arg) {
            uint64_t cgid = strtoull(arg + 1, NULL, 0);
            if (cgid > 0) {
                unregister_cgroup(cgid);
                if (client_idx >= 0 && client_idx < MAX_CLIENTS && g_clients[client_idx].watched_cgroup == cgid) {
                    g_clients[client_idx].watched_cgroup = 0;
                }
                char ack[128];
                snprintf(ack, sizeof(ack), "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"unregistered\",\"cgroup_id\":\"%llu\"}",
                         (unsigned long long)cgid);
                broadcast_line(ack, cgid);
            }
        }
    } else if (strcmp(cmd, "PING") == 0) {
        char ack[] = "{\"source\":\"ebpf_sensor\",\"type\":\"pong\"}";
        broadcast_line(ack, 0);
    } else if (strcmp(cmd, "QUIT") == 0) {
        stop_requested = 1;
    }
}

int main(int argc, char **argv) {
    const char *sock_path = NULL;
    uint64_t initial_cgid = 0;
    int stdin_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            sock_path = argv[++i];
        } else if (strcmp(argv[i], "--cgroup") == 0 && i + 1 < argc) {
            initial_cgid = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--stdin") == 0) {
            stdin_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stderr, "Usage: %s [--socket <path>] [--cgroup <cgroup_id>] [--stdin]\n", argv[0]);
            return 0;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    g_num_cpus = libbpf_num_possible_cpus();
    if (g_num_cpus <= 0) g_num_cpus = 1;

    g_skel = sensor_bpf__open();
    if (!g_skel) {
        fprintf(stderr, "Failed to open eBPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    struct stat ns_st;
    if (stat("/proc/self/ns/pid", &ns_st) == 0) {
        g_skel->rodata->pidns_dev = ns_st.st_dev;
        g_skel->rodata->pidns_ino = ns_st.st_ino;
    }

    int load_err = sensor_bpf__load(g_skel);
    if (load_err) {
        fprintf(stderr, "Failed to load eBPF skeleton: %s\n", strerror(errno));
        sensor_bpf__destroy(g_skel);
        return 1;
    }

    int err = sensor_bpf__attach(g_skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF skeleton: %s\n", strerror(errno));
        sensor_bpf__destroy(g_skel);
        return 1;
    }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events_rb), handle_event, NULL, NULL);
    if (!g_rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        sensor_bpf__destroy(g_skel);
        return 1;
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].fd = -1;
        g_clients[i].is_active = 0;
        g_clients[i].watched_cgroup = 0;
    }

    int server_fd = -1;
    if (sock_path) {
        unlink(sock_path);
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd >= 0) {
            struct sockaddr_un sun;
            memset(&sun, 0, sizeof(sun));
            sun.sun_family = AF_UNIX;
            strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);
            if (bind(server_fd, (struct sockaddr *)&sun, sizeof(sun)) == 0 && listen(server_fd, 16) == 0) {
                chmod(sock_path, 0666);
            } else {
                fprintf(stderr, "Warning: failed to bind socket %s: %s\n", sock_path, strerror(errno));
                close(server_fd);
                server_fd = -1;
            }
        }
    }

    if (initial_cgid > 0) {
        register_cgroup(initial_cgid);
    }

    int rb_fd = ring_buffer__epoll_fd(g_rb);
    time_t last_hb = time(NULL);

    emit_heartbeat();

    while (!stop_requested) {
        struct pollfd pfds[MAX_CLIENTS + 3];
        int nfds = 0;

        pfds[nfds].fd = rb_fd;
        pfds[nfds].events = POLLIN;
        int rb_idx = nfds++;

        int srv_idx = -1;
        if (server_fd >= 0) {
            pfds[nfds].fd = server_fd;
            pfds[nfds].events = POLLIN;
            srv_idx = nfds++;
        }

        int stdin_idx = -1;
        if (stdin_mode) {
            pfds[nfds].fd = STDIN_FILENO;
            pfds[nfds].events = POLLIN;
            stdin_idx = nfds++;
        }

        int client_map[MAX_CLIENTS];
        for (int i = 0; i < MAX_CLIENTS; i++) {
            client_map[i] = -1;
            if (g_clients[i].is_active && g_clients[i].fd >= 0) {
                client_map[i] = nfds;
                pfds[nfds].fd = g_clients[i].fd;
                pfds[nfds].events = POLLIN;
                nfds++;
            }
        }

        int ret = poll(pfds, nfds, 200);
        if (ret < 0 && errno != EINTR) {
            break;
        }

        time_t now = time(NULL);
        if (now - last_hb >= 1) {
            emit_heartbeat();
            last_hb = now;
        }

        if (ret > 0) {
            if (pfds[rb_idx].revents & POLLIN) {
                ring_buffer__poll(g_rb, 0);
            }

            if (srv_idx >= 0 && (pfds[srv_idx].revents & POLLIN)) {
                int cfd = accept(server_fd, NULL, NULL);
                if (cfd >= 0) {
                    int slot = -1;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (!g_clients[i].is_active) {
                            slot = i;
                            break;
                        }
                    }
                    if (slot >= 0) {
                        g_clients[slot].fd = cfd;
                        g_clients[slot].is_active = 1;
                        g_clients[slot].watched_cgroup = 0;
                    } else {
                        close(cfd);
                    }
                }
            }

            if (stdin_idx >= 0 && (pfds[stdin_idx].revents & POLLIN)) {
                char buf[512];
                if (fgets(buf, sizeof(buf), stdin)) {
                    process_cmd(buf, -1);
                } else {
                    stdin_mode = 0;
                }
            }

            for (int i = 0; i < MAX_CLIENTS; i++) {
                int pidx = client_map[i];
                if (pidx >= 0 && (pfds[pidx].revents & (POLLIN | POLLHUP | POLLERR))) {
                    if (pfds[pidx].revents & POLLIN) {
                        char buf[512];
                        ssize_t n = read(g_clients[i].fd, buf, sizeof(buf) - 1);
                        if (n > 0) {
                            buf[n] = '\0';
                            process_cmd(buf, i);
                        } else {
                            if (g_clients[i].watched_cgroup > 0) {
                                unregister_cgroup(g_clients[i].watched_cgroup);
                            }
                            close(g_clients[i].fd);
                            g_clients[i].is_active = 0;
                            g_clients[i].fd = -1;
                        }
                    } else {
                        if (g_clients[i].watched_cgroup > 0) {
                            unregister_cgroup(g_clients[i].watched_cgroup);
                        }
                        close(g_clients[i].fd);
                        g_clients[i].is_active = 0;
                        g_clients[i].fd = -1;
                    }
                }
            }
        } else {
            /* timeout: drain ring buffer */
            ring_buffer__poll(g_rb, 0);
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].is_active && g_clients[i].fd >= 0) {
            close(g_clients[i].fd);
        }
    }
    if (server_fd >= 0) {
        close(server_fd);
        if (sock_path) unlink(sock_path);
    }
    ring_buffer__free(g_rb);
    sensor_bpf__destroy(g_skel);
    return 0;
}
