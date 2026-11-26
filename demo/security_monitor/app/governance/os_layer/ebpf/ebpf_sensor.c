#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
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
#include <pthread.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sensor.h"
#include "sensor.skel.h"

#define VERSION "1.0.0"
#define MAX_CLIENTS 256

static long long monotonic_ms(void);

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
    uid_t uid;
    pid_t pid;
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

static uint32_t g_discovery_enabled = 0;
static uint32_t g_rate_limit = 200;
static uint32_t g_dns_port = 53;

static uint64_t get_total_rate_limited(void) {
    if (!g_skel) return 0;
    int fd = bpf_map__fd(g_skel->maps.rate_limited_events);
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

static uint64_t get_total_filtered(void) {
    if (!g_skel) return 0;
    int fd = bpf_map__fd(g_skel->maps.filtered_events);
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

static void init_runtime_prefixes(struct sensor_bpf *skel) {
    static const char *prefixes[] = {
        "/usr/lib",
        "/lib",
        "/usr/share/zoneinfo",
        "/etc/ld.so.cache",
        "/lib64",
        "/usr/lib64",
        "/usr/share/locale",
        NULL
    };
    int map_fd = bpf_map__fd(skel->maps.runtime_prefixes);
    if (map_fd < 0) return;
    for (uint32_t i = 0; prefixes[i] != NULL && i < MAX_RUNTIME_PREFIXES; i++) {
        struct prefix_entry entry;
        memset(&entry, 0, sizeof(entry));
        entry.len = (uint32_t)strlen(prefixes[i]);
        strncpy(entry.prefix, prefixes[i], sizeof(entry.prefix) - 1);
        bpf_map_update_elem(map_fd, &i, &entry, BPF_ANY);
    }
}

static int set_discovery_config(uint32_t enabled, uint32_t rate_limit, uint32_t dns_port) {
    if (!g_skel) return -1;
    int fd = bpf_map__fd(g_skel->maps.discovery_cfg);
    if (fd < 0) return -1;
    uint32_t k0 = 0, v0 = enabled;
    uint32_t k1 = 1, v1 = rate_limit;
    uint32_t k2 = 2, v2 = dns_port;
    bpf_map_update_elem(fd, &k0, &v0, BPF_ANY);
    bpf_map_update_elem(fd, &k1, &v1, BPF_ANY);
    bpf_map_update_elem(fd, &k2, &v2, BPF_ANY);
    return 0;
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

struct dirfd_cache_entry {
    uint32_t pid;
    int32_t dfd;
    char path[PATH_MAX];
    uint64_t ts_ms;
};
#define DIRFD_CACHE_SIZE 512
static struct dirfd_cache_entry g_dirfd_cache[DIRFD_CACHE_SIZE];
static pthread_mutex_t g_dirfd_mutex = PTHREAD_MUTEX_INITIALIZER;

static void update_dirfd_cache(uint32_t pid, int32_t fd, const char *path) {
    if (fd < 0 || !path || path[0] == '\0') return;
    pthread_mutex_lock(&g_dirfd_mutex);
    uint32_t idx = ((pid * 31) ^ (uint32_t)fd) % DIRFD_CACHE_SIZE;
    g_dirfd_cache[idx].pid = pid;
    g_dirfd_cache[idx].dfd = fd;
    strncpy(g_dirfd_cache[idx].path, path, sizeof(g_dirfd_cache[idx].path) - 1);
    g_dirfd_cache[idx].path[sizeof(g_dirfd_cache[idx].path) - 1] = '\0';
    g_dirfd_cache[idx].ts_ms = (uint64_t)monotonic_ms();
    pthread_mutex_unlock(&g_dirfd_mutex);
}

static const char *lookup_dirfd_cache(uint32_t pid, int32_t fd) {
    if (fd < 0) return NULL;
    static __thread char result[PATH_MAX];
    pthread_mutex_lock(&g_dirfd_mutex);
    uint32_t idx = ((pid * 31) ^ (uint32_t)fd) % DIRFD_CACHE_SIZE;
    if (g_dirfd_cache[idx].pid == pid && g_dirfd_cache[idx].dfd == fd) {
        strncpy(result, g_dirfd_cache[idx].path, sizeof(result) - 1);
        result[sizeof(result) - 1] = '\0';
        pthread_mutex_unlock(&g_dirfd_mutex);
        return result;
    }
    pthread_mutex_unlock(&g_dirfd_mutex);
    return NULL;
}

static void resolve_abs_path(uint32_t pid, int32_t dfd, const char *rel,
                             const char *base_dir, uint8_t base_status,
                             char *out_buf, size_t out_len) {
    if (!rel || rel[0] == '\0') {
        if (base_status == BASE_STATUS_TRUNCATED) {
            out_buf[0] = '\0';
            return;
        }
        if (base_status == BASE_STATUS_OK && base_dir && base_dir[0] != '\0') {
            snprintf(out_buf, out_len, "%s", base_dir);
            return;
        }
        if (dfd >= 0) {
            char link[64];
            snprintf(link, sizeof(link), "/proc/%u/fd/%d", (unsigned int)pid, (int)dfd);
            ssize_t n = readlink(link, out_buf, out_len - 1);
            if (n > 0) {
                out_buf[n] = '\0';
                return;
            }
            const char *cached = lookup_dirfd_cache(pid, dfd);
            if (cached) {
                snprintf(out_buf, out_len, "%s", cached);
                return;
            }
        }
        out_buf[0] = '\0';
        return;
    }
    if (rel[0] == '/') {
        snprintf(out_buf, out_len, "%s", rel);
        return;
    }
    if (base_status == BASE_STATUS_TRUNCATED) {
        out_buf[0] = '\0';
        return;
    }
    if (base_status == BASE_STATUS_OK && base_dir && base_dir[0] != '\0') {
        int w;
        if (strcmp(base_dir, "/") == 0) {
            w = snprintf(out_buf, out_len, "/%s", rel);
        } else {
            w = snprintf(out_buf, out_len, "%s/%s", base_dir, rel);
        }
        if (w < 0 || (size_t)w >= out_len) {
            out_buf[0] = '\0';
        }
        return;
    }
    char link[64];
    if (dfd == -100 /* AT_FDCWD */ || dfd < 0) {
        snprintf(link, sizeof(link), "/proc/%u/cwd", (unsigned int)pid);
    } else {
        snprintf(link, sizeof(link), "/proc/%u/fd/%d", (unsigned int)pid, (int)dfd);
    }
    char base[PATH_MAX];
    ssize_t n = readlink(link, base, sizeof(base) - 1);
    if (n > 0) {
        base[n] = '\0';
        int w = snprintf(out_buf, out_len, "%s/%s", base, rel);
        if (w < 0 || (size_t)w >= out_len) {
            snprintf(out_buf, out_len, "%s", rel);
        }
    } else {
        if (dfd == -100 || dfd < 0) {
            char cwd_link[64];
            snprintf(cwd_link, sizeof(cwd_link), "/proc/%u/cwd", (unsigned int)pid);
            n = readlink(cwd_link, base, sizeof(base) - 1);
            if (n > 0) {
                base[n] = '\0';
                snprintf(out_buf, out_len, "%s/%s", base, rel);
            } else {
                snprintf(out_buf, out_len, "%s", rel);
            }
        } else {
            const char *cached = lookup_dirfd_cache(pid, dfd);
            if (cached) {
                snprintf(out_buf, out_len, "%s/%s", cached, rel);
            } else {
                out_buf[0] = '\0';
            }
        }
    }
}

static int parse_dns_qname(const char *payload, uint16_t len, char *out_domain, size_t out_sz) {
    if (!payload || len < 13 || out_sz < 2) return -1;
    out_domain[0] = '\0';

    uint16_t qdcount = ((uint8_t)payload[4] << 8) | (uint8_t)payload[5];
    if (qdcount == 0) return -1;

    size_t pos = 12;
    size_t out_pos = 0;

    while (pos < len) {
        uint8_t label_len = (uint8_t)payload[pos++];
        if (label_len == 0) {
            out_domain[out_pos] = '\0';
            return out_pos > 0 ? 0 : -1;
        }
        if (label_len > 63 || pos + label_len > len) {
            return -1;
        }
        if (out_pos > 0) {
            if (out_pos + 1 >= out_sz) return -1;
            out_domain[out_pos++] = '.';
        }
        for (uint8_t i = 0; i < label_len; i++) {
            unsigned char c = (unsigned char)payload[pos++];
            if (c >= 'A' && c <= 'Z') {
                c += ('a' - 'A');
            } else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return -1;
            }
            if (out_pos + 1 >= out_sz) return -1;
            out_domain[out_pos++] = (char)c;
        }
    }
    return -1;
}

struct cgroup_cache_entry {
    uint64_t cgid;
    char path[256];
    char unit[128];
    char container_id[128];
};

#define CGROUP_CACHE_SIZE 1024
static struct cgroup_cache_entry g_cgroup_cache[CGROUP_CACHE_SIZE];
static int g_cgroup_cache_count = 0;

static void extract_unit_and_container(const char *cg_path, char *unit, size_t unit_sz, char *cont_id, size_t cont_sz) {
    unit[0] = '\0';
    cont_id[0] = '\0';
    if (!cg_path || !cg_path[0]) return;

    char copy[256];
    strncpy(copy, cg_path, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(copy, "/", &saveptr);
    while (token) {
        size_t tlen = strlen(token);
        if (tlen > 8 && strcmp(token + tlen - 8, ".service") == 0) {
            strncpy(unit, token, unit_sz - 1);
            unit[unit_sz - 1] = '\0';
        } else if (tlen > 6 && strcmp(token + tlen - 6, ".scope") == 0) {
            strncpy(unit, token, unit_sz - 1);
            unit[unit_sz - 1] = '\0';
        } else if (!unit[0] && tlen > 6 && strcmp(token + tlen - 6, ".slice") == 0) {
            strncpy(unit, token, unit_sz - 1);
            unit[unit_sz - 1] = '\0';
        }

        if (tlen == 64) {
            int is_hex = 1;
            for (size_t i = 0; i < 64; i++) {
                char c = token[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                    is_hex = 0;
                    break;
                }
            }
            if (is_hex) {
                strncpy(cont_id, token, cont_sz - 1);
                cont_id[cont_sz - 1] = '\0';
            }
        } else if (tlen > 7 && strncmp(token, "docker-", 7) == 0 && tlen >= 71) {
            char hex_cand[65];
            strncpy(hex_cand, token + 7, 64);
            hex_cand[64] = '\0';
            int is_hex = 1;
            for (size_t i = 0; i < 64; i++) {
                char c = hex_cand[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                    is_hex = 0;
                    break;
                }
            }
            if (is_hex) {
                strncpy(cont_id, hex_cand, cont_sz - 1);
                cont_id[cont_sz - 1] = '\0';
            }
        }

        token = strtok_r(NULL, "/", &saveptr);
    }
}

static void add_cgroup_cache(uint64_t cgid, const char *path) {
    if (cgid == 0 || !path) return;
    for (int i = 0; i < g_cgroup_cache_count; i++) {
        if (g_cgroup_cache[i].cgid == cgid) {
            strncpy(g_cgroup_cache[i].path, path, sizeof(g_cgroup_cache[i].path) - 1);
            g_cgroup_cache[i].path[sizeof(g_cgroup_cache[i].path) - 1] = '\0';
            extract_unit_and_container(path, g_cgroup_cache[i].unit, sizeof(g_cgroup_cache[i].unit),
                                       g_cgroup_cache[i].container_id, sizeof(g_cgroup_cache[i].container_id));
            return;
        }
    }
    int idx;
    if (g_cgroup_cache_count < CGROUP_CACHE_SIZE) {
        idx = g_cgroup_cache_count++;
    } else {
        idx = (int)(cgid % CGROUP_CACHE_SIZE);
    }
    g_cgroup_cache[idx].cgid = cgid;
    strncpy(g_cgroup_cache[idx].path, path, sizeof(g_cgroup_cache[idx].path) - 1);
    g_cgroup_cache[idx].path[sizeof(g_cgroup_cache[idx].path) - 1] = '\0';
    extract_unit_and_container(path, g_cgroup_cache[idx].unit, sizeof(g_cgroup_cache[idx].unit),
                               g_cgroup_cache[idx].container_id, sizeof(g_cgroup_cache[idx].container_id));
}

static int lookup_cgroup_cache(uint64_t cgid, char *path, size_t path_sz, char *unit, size_t unit_sz, char *cont_id, size_t cont_sz) {
    if (cgid == 0) return 0;
    for (int i = 0; i < g_cgroup_cache_count; i++) {
        if (g_cgroup_cache[i].cgid == cgid) {
            if (path) {
                strncpy(path, g_cgroup_cache[i].path, path_sz - 1);
                path[path_sz - 1] = '\0';
            }
            if (unit) {
                strncpy(unit, g_cgroup_cache[i].unit, unit_sz - 1);
                unit[unit_sz - 1] = '\0';
            }
            if (cont_id) {
                strncpy(cont_id, g_cgroup_cache[i].container_id, cont_sz - 1);
                cont_id[cont_sz - 1] = '\0';
            }
            return 1;
        }
    }
    return 0;
}

static void walk_cgroup_tree(const char *rel_base, int depth) {
    // Direct-mode per-call cgroups sit at depth 7 (.../agent-governance-parent/task_X/call_NNN), deeper under containers.
    if (depth > 16) return;
    char full[1024];
    snprintf(full, sizeof(full), "/sys/fs/cgroup%s", rel_base);

    DIR *d = opendir(full);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        if (ent->d_type == DT_DIR) {
            char sub_rel[512];
            if (strcmp(rel_base, "/") == 0 || rel_base[0] == '\0') {
                snprintf(sub_rel, sizeof(sub_rel), "/%s", ent->d_name);
            } else {
                snprintf(sub_rel, sizeof(sub_rel), "%s/%s", rel_base, ent->d_name);
            }
            char sub_full[1024];
            snprintf(sub_full, sizeof(sub_full), "/sys/fs/cgroup%s", sub_rel);
            struct stat st;
            if (stat(sub_full, &st) == 0) {
                add_cgroup_cache(st.st_ino, sub_rel);
            }
            walk_cgroup_tree(sub_rel, depth + 1);
        }
    }
    closedir(d);
}

static void resolve_cgroup_info(uint64_t cgid, pid_t pid, char *path, size_t path_sz, char *unit, size_t unit_sz, char *cont_id, size_t cont_sz) {
    path[0] = '\0';
    unit[0] = '\0';
    cont_id[0] = '\0';

    if (lookup_cgroup_cache(cgid, path, path_sz, unit, unit_sz, cont_id, cont_sz)) {
        return;
    }

    if (pid > 0) {
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", (int)pid);
        FILE *f = fopen(proc_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                char *cr = strchr(line, '\r');
                if (cr) *cr = '\0';
                if (strncmp(line, "0::", 3) == 0) {
                    snprintf(path, path_sz, "%.*s", (int)(path_sz - 1), line + 3);
                    break;
                }
            }
            fclose(f);
            if (path[0] != '\0') {
                add_cgroup_cache(cgid, path);
                lookup_cgroup_cache(cgid, path, path_sz, unit, unit_sz, cont_id, cont_sz);
                return;
            }
        }
    }

    walk_cgroup_tree("", 0);
    if (lookup_cgroup_cache(cgid, path, path_sz, unit, unit_sz, cont_id, cont_sz)) {
        return;
    }

    snprintf(path, path_sz, "cgroup:%llu", (unsigned long long)cgid);
}

static int is_cgroup_owned_by_calling_uid(uint64_t cgid) {
    char cg_path[PATH_MAX];
    cg_path[0] = '\0';
    resolve_cgroup_info(cgid, 0, cg_path, sizeof(cg_path), NULL, 0, NULL, 0);
    if (!cg_path[0] || strncmp(cg_path, "cgroup:", 7) == 0) {
        return 0;
    }
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "/sys/fs/cgroup%s", cg_path);
    struct stat st;
    if (stat(full_path, &st) != 0) {
        return 0;
    }
    return (st.st_uid == getuid());
}

static void broadcast_line(const char *line, uint64_t cgid) {
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);

    size_t line_len = strlen(line);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].is_active && g_clients[i].fd >= 0) {
            if (cgid == 0 || g_clients[i].watched_cgroup == cgid || (g_discovery_enabled && g_clients[i].watched_cgroup == 0)) {
                ssize_t w1 = write(g_clients[i].fd, line, line_len);
                ssize_t w2 = 0;
                if (w1 > 0) {
                    w2 = write(g_clients[i].fd, "\n", 1);
                }
                if (w1 < 0 || w2 < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EPIPE || errno == ECONNRESET) {
                        close(g_clients[i].fd);
                        g_clients[i].fd = -1;
                        g_clients[i].is_active = 0;
                        g_clients[i].watched_cgroup = 0;
                    }
                }
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
        resolve_abs_path(e->pid, e->dfd, e->target, e->base_dir, e->base_status, abs_target, sizeof(abs_target));
        if (target[0] == '\0' && abs_target[0] != '\0') {
            snprintf(target, sizeof(target), "%s", abs_target);
        }
        if (e->op == EBPF_OP_OPEN && e->ret >= 0 && abs_target[0] != '\0') {
            update_dirfd_cache(e->pid, (int32_t)e->ret, abs_target);
        }
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
        const char *b2 = (e->dfd2 == e->dfd) ? e->base_dir : NULL;
        uint8_t bs2 = (e->dfd2 == e->dfd) ? e->base_status : BASE_STATUS_NONE;
        resolve_abs_path(e->pid, e->dfd2, e->target2, b2, bs2, abs_target2, sizeof(abs_target2));
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
    uint64_t rate_limited = get_total_rate_limited();

    char cgroup_path[256] = "";
    char unit[128] = "";
    char container_id[128] = "";
    char dns_question[256] = "";

    /* Resolve the cgroup the process is really in, not the registered ancestor: otherwise every
       event from a per-call child cgroup (call_NNN) is reported as the task cgroup, and the
       pid-based lookup below caches a child's path under the task's id. */
    uint64_t path_cgid = e->cur_cgroup_id ? e->cur_cgroup_id : e->cgroup_id;
    resolve_cgroup_info(path_cgid, (pid_t)e->pid, cgroup_path, sizeof(cgroup_path),
                        unit, sizeof(unit), container_id, sizeof(container_id));
    if (e->is_discovery && e->dns_payload_len > 0) {
        parse_dns_qname(e->dns_payload, e->dns_payload_len, dns_question, sizeof(dns_question));
    }

    char *line = NULL;
    size_t line_sz = 0;
    FILE *mem = open_memstream(&line, &line_sz);
    if (!mem) return 0;

    fprintf(mem, "{\"source\":\"ebpf_sensor\",\"type\":\"syscall\"");
    if (e->is_discovery) {
        fputs(",\"mode\":\"discovery\"", mem);
    }
    fprintf(mem, ",\"seq\":%llu,\"timestamp\":\"%s\",\"ts_ms\":%lld,"
                 "\"pid\":%u,\"ppid\":%u",
            g_seq, ts, ms, e->pid, e->ppid);

    fputs(",\"cgroup_id\":", mem);
    json_escape(mem, cgroup_path[0] ? cgroup_path : "");
    fprintf(mem, ",\"cgroup_status\":\"ok\"");

    fputs(",\"cgroup_path\":", mem);
    json_escape(mem, cgroup_path);
    if (unit[0]) {
        fputs(",\"unit\":", mem);
        json_escape(mem, unit);
    }
    if (container_id[0]) {
        fputs(",\"container_id\":", mem);
        json_escape(mem, container_id);
    }

    fprintf(mem, ",\"syscall\":\"%s\",\"op\":\"%s\",\"target\":",
            syscall_nr_to_name(e->syscall_nr), op_to_name(e->op));
    json_escape(mem, target);
    fputs(",\"abs_target\":", mem);
    json_escape(mem, abs_target);
    fprintf(mem, ",\"target_status\":\"%s\"", target_status_str);
    if (e->base_dir[0] != '\0') {
        fputs(",\"base_dir\":", mem);
        json_escape(mem, e->base_dir);
    }
    if (e->base_status == BASE_STATUS_TRUNCATED && e->has_target && e->target[0] != '/') {
        fputs(",\"base_truncated\":true", mem);
    }

    if (e->op == EBPF_OP_OPEN) {
        const char *acc = "read";
        if ((e->flags & 3) == 1) acc = "write";
        else if ((e->flags & 3) == 2) acc = "read_write";
        fprintf(mem, ",\"access\":\"%s\",\"creat\":%s", acc, (e->flags & 0x40) ? "true" : "false");
    }

    if (e->has_target2) {
        fputs(",\"target2\":", mem);
        json_escape(mem, target2);
        fputs(",\"abs_target2\":", mem);
        json_escape(mem, abs_target2);
    }

    if (e->is_discovery && e->argv_count > 0) {
        fputs(",\"argv\":[", mem);
        for (int i = 0; i < e->argv_count && i < ARGV_MAX_COUNT; i++) {
            if (i > 0) fputc(',', mem);
            json_escape(mem, e->argv[i]);
        }
        fputc(']', mem);
    }

    if (e->is_discovery && dns_question[0]) {
        fputs(",\"dns_question\":", mem);
        json_escape(mem, dns_question);
    }

    if (e->flags) {
        fprintf(mem, ",\"flags\":%llu", (unsigned long long)e->flags);
    }
    if (e->aux) {
        fprintf(mem, ",\"aux\":%llu", (unsigned long long)e->aux);
    }

    fprintf(mem, ",\"ret\":%lld,\"result\":\"%s\",\"dropped\":%llu,\"rate_limited\":%llu}",
            (long long)e->ret, result_str, (unsigned long long)dropped, (unsigned long long)rate_limited);

    fclose(mem);
    if (line) {
        broadcast_line(line, e->cgroup_id);
        free(line);
    }
    return 0;
}

static long long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void emit_heartbeat(void) {
    g_seq++;
    char ts[48];
    long long ms = 0;
    now_iso(ts, sizeof(ts), &ms);
    uint64_t dropped = get_total_dropped();
    uint64_t rate_limited = get_total_rate_limited();
    uint64_t filtered = get_total_filtered();

    char line[512];
    snprintf(line, sizeof(line),
             "{\"source\":\"ebpf_sensor\",\"type\":\"heartbeat\",\"seq\":%llu,\"timestamp\":\"%s\",\"ts_ms\":%lld,"
             "\"events_total\":%llu,\"dropped_total\":%llu,\"rate_limited_total\":%llu,\"filtered_total\":%llu,\"version\":\"%s\"}",
             g_seq, ts, ms, (unsigned long long)g_events_total, (unsigned long long)dropped, (unsigned long long)rate_limited, (unsigned long long)filtered, VERSION);
    broadcast_line(line, 0);
}

static int is_peer_in_registered_cgroup(pid_t pid) {
    if (!g_skel || pid <= 0) return 0;
    int map_fd = bpf_map__fd(g_skel->maps.task_cgroups);
    if (map_fd < 0) return 0;

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", (int)pid);
    FILE *f = fopen(proc_path, "r");
    if (!f) return 0;

    char line[512];
    char cg_rel[512] = {0};
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr) *cr = '\0';
        if (strncmp(line, "0::", 3) == 0) {
            strncpy(cg_rel, line + 3, sizeof(cg_rel) - 1);
            break;
        }
    }
    fclose(f);

    if (cg_rel[0] == '\0') {
        return 0;
    }

    struct stat root_st;
    if (stat("/sys/fs/cgroup", &root_st) != 0) {
        return 0;
    }

    char cur_path[1024];
    snprintf(cur_path, sizeof(cur_path), "/sys/fs/cgroup%s", cg_rel);

    while (1) {
        struct stat st;
        if (stat(cur_path, &st) == 0) {
            uint64_t cgid = st.st_ino;
            if (st.st_ino != root_st.st_ino) {
                uint32_t val = 0;
                if (bpf_map_lookup_elem(map_fd, &cgid, &val) == 0) {
                    return 1;
                }
            }
        }
        if (strcmp(cur_path, "/sys/fs/cgroup") == 0 || strcmp(cur_path, "/sys/fs/cgroup/") == 0) {
            break;
        }
        char *slash = strrchr(cur_path, '/');
        if (!slash || slash <= cur_path + strlen("/sys/fs/cgroup")) {
            break;
        }
        *slash = '\0';
    }
    return 0;
}

static void process_cmd(char *cmd, int client_idx) {
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    char *nl = strchr(cmd, '\n');
    if (nl) *nl = '\0';
    char *cr = strchr(cmd, '\r');
    if (cr) *cr = '\0';
    if (!*cmd) return;

    if (client_idx >= 0 && client_idx < MAX_CLIENTS) {
        uid_t my_uid = getuid();
        uid_t peer_uid = g_clients[client_idx].uid;
        pid_t peer_pid = g_clients[client_idx].pid;

        int rejected = 0;
        const char *reason = NULL;

        if (peer_uid != my_uid) {
            rejected = 1;
            reason = "peer uid differs from loader uid";
        } else if (is_peer_in_registered_cgroup(peer_pid)) {
            rejected = 1;
            reason = "peer pid is inside or under a registered task cgroup";
        }

        if (rejected) {
            fprintf(stderr, "ebpf_sensor: rejecting command '%s' from pid %d (uid %d): %s\n",
                    cmd, (int)peer_pid, (int)peer_uid, reason);
            if (g_clients[client_idx].fd >= 0) {
                char err_buf[256];
                snprintf(err_buf, sizeof(err_buf),
                         "{\"source\":\"ebpf_sensor\",\"type\":\"error\",\"error\":\"permission_denied\",\"reason\":\"%s\"}\n",
                         reason);
                ssize_t w = write(g_clients[client_idx].fd, err_buf, strlen(err_buf));
                (void)w;
            }
            return;
        }
    }

    if (strncmp(cmd, "REGISTER ", 9) == 0 || strncmp(cmd, "WATCH ", 6) == 0 || strncmp(cmd, "ADD ", 4) == 0) {
        char *arg = strchr(cmd, ' ');
        if (arg) {
            uint64_t cgid = strtoull(arg + 1, NULL, 0);
            if (cgid > 0) {
                if (client_idx < 0 && !is_cgroup_owned_by_calling_uid(cgid)) {
                    fprintf(stderr, "ebpf_sensor: cgroup %llu directory not owned by caller\n",
                            (unsigned long long)cgid);
                    return;
                }
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
                uint64_t filtered_count = 0;
                if (g_skel) {
                    int f_map_fd = bpf_map__fd(g_skel->maps.cgroup_filtered_reads);
                    if (f_map_fd >= 0) {
                        bpf_map_lookup_elem(f_map_fd, &cgid, &filtered_count);
                        bpf_map_delete_elem(f_map_fd, &cgid);
                    }
                }
                unregister_cgroup(cgid);
                if (client_idx >= 0 && client_idx < MAX_CLIENTS && g_clients[client_idx].watched_cgroup == cgid) {
                    g_clients[client_idx].watched_cgroup = 0;
                }
                char ack[256];
                snprintf(ack, sizeof(ack), "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"unregistered\",\"cgroup_id\":\"%llu\",\"filtered_runtime_reads\":%llu}",
                         (unsigned long long)cgid, (unsigned long long)filtered_count);
                broadcast_line(ack, cgid);
            }
        }
    } else if (strncmp(cmd, "FILTERED ", 9) == 0) {
        char *arg = strchr(cmd, ' ');
        if (arg) {
            uint64_t cgid = strtoull(arg + 1, NULL, 0);
            uint64_t fc = 0;
            if (g_skel) {
                int f_map_fd = bpf_map__fd(g_skel->maps.cgroup_filtered_reads);
                if (f_map_fd >= 0) {
                    bpf_map_lookup_elem(f_map_fd, &cgid, &fc);
                }
            }
            char ack[128];
            snprintf(ack, sizeof(ack), "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"filtered_reads\",\"cgroup_id\":\"%llu\",\"filtered_runtime_reads\":%llu}", (unsigned long long)cgid, (unsigned long long)fc);
            broadcast_line(ack, cgid);
        }
    } else if (strcmp(cmd, "STATUS") == 0) {
        uint64_t dropped = get_total_dropped();
        uint64_t rate_limited = get_total_rate_limited();
        uint64_t filtered = get_total_filtered();
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"source\":\"ebpf_sensor\",\"type\":\"status\",\"status\":\"healthy\","
                 "\"events_total\":%llu,\"dropped_total\":%llu,\"rate_limited_total\":%llu,\"filtered_total\":%llu,\"version\":\"%s\"}",
                 (unsigned long long)g_events_total, (unsigned long long)dropped, (unsigned long long)rate_limited, (unsigned long long)filtered, VERSION);
        broadcast_line(resp, 0);
    } else if (strncmp(cmd, "DISCOVERY ON", 12) == 0) {
        uint32_t limit = g_rate_limit;
        char *arg = strchr(cmd + 12, ' ');
        if (arg) {
            uint32_t parsed = (uint32_t)strtoul(arg + 1, NULL, 0);
            if (parsed > 0) limit = parsed;
        }
        g_discovery_enabled = 1;
        g_rate_limit = limit;
        set_discovery_config(1, limit, g_dns_port);
        char ack[128];
        snprintf(ack, sizeof(ack), "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"discovery_on\",\"rate_limit\":%u}", limit);
        broadcast_line(ack, 0);
    } else if (strcmp(cmd, "DISCOVERY OFF") == 0) {
        g_discovery_enabled = 0;
        set_discovery_config(0, g_rate_limit, g_dns_port);
        char ack[] = "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"discovery_off\"}";
        broadcast_line(ack, 0);
    } else if (strncmp(cmd, "RATE_LIMIT ", 11) == 0) {
        char *arg = strchr(cmd, ' ');
        if (arg) {
            uint32_t limit = (uint32_t)strtoul(arg + 1, NULL, 0);
            if (limit > 0) {
                g_rate_limit = limit;
                set_discovery_config(g_discovery_enabled, limit, g_dns_port);
                char ack[128];
                snprintf(ack, sizeof(ack), "{\"source\":\"ebpf_sensor\",\"type\":\"ack\",\"action\":\"rate_limit_set\",\"rate_limit\":%u}", limit);
                broadcast_line(ack, 0);
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
        } else if (strcmp(argv[i], "--discovery") == 0) {
            g_discovery_enabled = 1;
        } else if (strcmp(argv[i], "--rate-limit") == 0 && i + 1 < argc) {
            g_rate_limit = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--dns-port") == 0 && i + 1 < argc) {
            g_dns_port = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--stdin") == 0) {
            stdin_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stderr, "Usage: %s [--socket <path>] [--cgroup <cgroup_id>] [--discovery] [--rate-limit <n>] [--dns-port <p>] [--stdin]\n", argv[0]);
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

    set_discovery_config(g_discovery_enabled, g_rate_limit, g_dns_port);
    init_runtime_prefixes(g_skel);

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
        char dir_buf[PATH_MAX];
        strncpy(dir_buf, sock_path, sizeof(dir_buf) - 1);
        dir_buf[sizeof(dir_buf) - 1] = '\0';
        char *last_slash = strrchr(dir_buf, '/');
        if (last_slash && last_slash != dir_buf) {
            *last_slash = '\0';
            mkdir(dir_buf, 0700);
            chmod(dir_buf, 0700);
        }
        unlink(sock_path);
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd >= 0) {
            struct sockaddr_un sun;
            memset(&sun, 0, sizeof(sun));
            sun.sun_family = AF_UNIX;
            strncpy(sun.sun_path, sock_path, sizeof(sun.sun_path) - 1);
            if (bind(server_fd, (struct sockaddr *)&sun, sizeof(sun)) == 0 && listen(server_fd, 256) == 0) {
                chmod(sock_path, 0600);
            } else {
                fprintf(stderr, "Warning: failed to bind socket %s: %s\n", sock_path, strerror(errno));
                close(server_fd);
                server_fd = -1;
            }
        }
    }

    if (initial_cgid > 0) {
        if (!is_cgroup_owned_by_calling_uid(initial_cgid)) {
            fprintf(stderr, "ebpf_sensor: cgroup %llu directory not owned by caller\n",
                    (unsigned long long)initial_cgid);
            return 1;
        }
        register_cgroup(initial_cgid);
    }

    int rb_fd = ring_buffer__epoll_fd(g_rb);
    long long last_hb = monotonic_ms();

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

        int ret = poll(pfds, nfds, 100);
        if (ret < 0 && errno != EINTR) {
            break;
        }

        long long now = monotonic_ms();
        if (now - last_hb >= 500) {
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
                    struct ucred cred;
                    socklen_t cred_len = sizeof(cred);
                    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0 || cred.uid != getuid()) {
                        close(cfd);
                        continue;
                    }
                    int fl = fcntl(cfd, F_GETFL, 0);
                    if (fl >= 0) {
                        fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
                    }
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
                        g_clients[slot].uid = cred.uid;
                        g_clients[slot].pid = cred.pid;
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
