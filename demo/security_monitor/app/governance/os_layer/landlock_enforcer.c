/*
 * Landlock Task Sandbox Enforcer (C Implementation)
 *
 * Usage (legacy M4 workspace-layout mode):
 *   landlock_enforcer --workspace /path/to/ws [--proxy-port 8080] [--mode enforce|observe] [--simulate-unshare-fail] -- cmd arg1 arg2 ...
 *
 * Usage (M6 boundary-compiled mode):
 *   landlock_enforcer --rules rules.json [--status-fd N] [--mode enforce|observe] [--simulate-unshare-fail] -- cmd ...
 *
 *   The rules file is JSON compiled from the Task Boundary by sandbox_spec.py:
 *     {"version": 1,
 *      "task_tmp": "/abs/ws/tmp",
 *      "tcp_connect_ports": [12345],
 *      "rules": [{"path": "/abs/path", "access": ["read_file", ...], "optional": false}, ...]}
 *   Nothing outside the listed rules is granted. A missing non-optional path,
 *   a rejected rule or a malformed file aborts (fail closed).
 *   After landlock_restrict_self succeeds, a JSON status line (isolation level,
 *   ABI, rule counts, kernel-reported Seccomp_filters) is written to --status-fd.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, __u32 flags) {
    return syscall(SYS_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static int landlock_restrict_self(int ruleset_fd, __u32 flags) {
    return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

static int add_path_rule(int ruleset_fd, const char *path, __u64 access_mask) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        return 0; /* Path does not exist on host; ignore */
    }
    struct landlock_path_beneath_attr attr = {
        .allowed_access = access_mask,
        .parent_fd = fd,
    };
    int res = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);
    return res;
}

static int add_net_rule(int ruleset_fd, __u64 port, __u64 access_mask) {
    struct landlock_net_port_attr attr = {
        .allowed_access = access_mask,
        .port = port,
    };
    return landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &attr, 0);
}

static int isolate_user_and_mounts(uid_t host_uid, gid_t host_gid, int enforce_mode, int simulate_fail) {
    if (simulate_fail) {
        errno = EPERM;
        if (enforce_mode) {
            fprintf(stderr, "SECURITY_ERROR: unshare(CLONE_NEWUSER|CLONE_NEWNS) simulated failure: %s. Aborting in ENFORCE mode.\n", strerror(errno));
            return -1;
        } else {
            fprintf(stderr, "WARNING: unshare simulated failure: %s. Continuing in OBSERVE mode (isolation_level=landlock_only).\n", strerror(errno));
            setenv("GOVERNANCE_ISOLATION_LEVEL", "landlock_only", 1);
            return 0;
        }
    }

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
        if (enforce_mode) {
            fprintf(stderr, "SECURITY_ERROR: unshare(CLONE_NEWUSER|CLONE_NEWNS) failed: %s. Aborting in ENFORCE mode.\n", strerror(errno));
            return -1;
        } else {
            fprintf(stderr, "WARNING: unshare failed: %s. Continuing in OBSERVE mode (isolation_level=landlock_only).\n", strerror(errno));
            setenv("GOVERNANCE_ISOLATION_LEVEL", "landlock_only", 1);
            return 0;
        }
    }

    // Setgroups deny
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "deny", 4) < 0 && enforce_mode) {
            fprintf(stderr, "SECURITY_ERROR: failed to write /proc/self/setgroups\n");
            close(fd);
            return -1;
        }
        close(fd);
    }

    // uid_map: map host_uid -> host_uid (agent runs as non-root UID inside user namespace)
    char map_buf[128];
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd >= 0) {
        snprintf(map_buf, sizeof(map_buf), "%u %u 1\n", host_uid, host_uid);
        if (write(fd, map_buf, strlen(map_buf)) < 0 && enforce_mode) {
            fprintf(stderr, "SECURITY_ERROR: failed to write /proc/self/uid_map\n");
            close(fd);
            return -1;
        }
        close(fd);
    } else if (enforce_mode) {
        fprintf(stderr, "SECURITY_ERROR: failed to open /proc/self/uid_map\n");
        return -1;
    }

    // gid_map: map host_gid -> host_gid
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd >= 0) {
        snprintf(map_buf, sizeof(map_buf), "%u %u 1\n", host_gid, host_gid);
        if (write(fd, map_buf, strlen(map_buf)) < 0 && enforce_mode) {
            fprintf(stderr, "SECURITY_ERROR: failed to write /proc/self/gid_map\n");
            close(fd);
            return -1;
        }
        close(fd);
    } else if (enforce_mode) {
        fprintf(stderr, "SECURITY_ERROR: failed to open /proc/self/gid_map\n");
        return -1;
    }

    // 1. Primary Security Guarantee: Mask /run/user/<host_uid> with an empty tmpfs
    // Hides the host session D-Bus socket (/run/user/<uid>/bus) and systemd private socket
    char run_user_path[256];
    snprintf(run_user_path, sizeof(run_user_path), "/run/user/%u", host_uid);
    struct stat st;
    if (stat(run_user_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (mount("none", run_user_path, "tmpfs", 0, "") != 0 && enforce_mode) {
            fprintf(stderr, "SECURITY_ERROR: failed to mount tmpfs over %s: %s\n", run_user_path, strerror(errno));
            return -1;
        }
    }

    // 2. Defense-in-depth: Bind /bin/false over IPC escape binaries
    // Note: The primary guarantee rests on user-session sockets being unreachable above;
    // these bind mounts provide an additional layer of defense.
    const char *escape_bins[] = {
        "/usr/bin/systemd-run",
        "/bin/systemd-run",
        "/usr/bin/busctl",
        "/bin/busctl",
        "/usr/bin/dbus-send",
        "/bin/dbus-send",
        NULL
    };
    for (int i = 0; escape_bins[i]; i++) {
        if (stat(escape_bins[i], &st) == 0) {
            mount("/bin/false", escape_bins[i], NULL, MS_BIND, NULL);
        }
    }

    setenv("GOVERNANCE_ISOLATION_LEVEL", "landlock+ns", 1);
    return 0;
}

static int legacy_main(int argc, char **argv) {
    const char *workspace = NULL;
    int proxy_port = 0;
    int enforce_mode = 1; // Default: 1 (ENFORCE mode: fail-closed)
    int simulate_fail = 0;
    int cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--workspace") == 0 && i + 1 < argc) {
            workspace = argv[++i];
        } else if (strcmp(argv[i], "--proxy-port") == 0 && i + 1 < argc) {
            proxy_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (strcmp(m, "observe") == 0) {
                enforce_mode = 0;
            } else {
                enforce_mode = 1;
            }
        } else if (strcmp(argv[i], "--simulate-unshare-fail") == 0) {
            simulate_fail = 1;
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        }
    }

    if (!workspace || cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "Usage: %s --workspace <path> [--proxy-port <port>] [--mode enforce|observe] [--simulate-unshare-fail] -- <cmd> [args...]\n", argv[0]);
        return 1;
    }

    uid_t uid = getuid();
    gid_t gid = getgid();

    // Setup per-task tmp directory
    char task_tmp[4096];
    snprintf(task_tmp, sizeof(task_tmp), "%s/tmp", workspace);
    mkdir(task_tmp, 0700);
    setenv("TMPDIR", task_tmp, 1);
    setenv("TEMP", task_tmp, 1);
    setenv("TMP", task_tmp, 1);

    // Isolate mount and user namespaces (Fail-closed in ENFORCE mode)
    if (isolate_user_and_mounts(uid, gid, enforce_mode, simulate_fail) != 0) {
        fprintf(stderr, "Task execution aborted due to namespace isolation failure in ENFORCE mode.\n");
        return 1;
    }

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        fprintf(stderr, "Landlock is not supported by kernel (abi=%d)\n", abi);
        return 1;
    }

    struct landlock_ruleset_attr_full {
        __u64 handled_access_fs;
        __u64 handled_access_net;
        __u64 scoped_access;
    };

    __u64 all_fs = (1ULL << 16) - 1; /* ABI 5-7 rights */
    __u64 all_net = (abi >= 4) ? (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP) : 0;
    __u64 all_scope = (abi >= 6) ? (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL) : 0;

    struct landlock_ruleset_attr_full attr = {
        .handled_access_fs = all_fs,
        .handled_access_net = all_net,
        .scoped_access = all_scope,
    };

    size_t attr_size = (abi >= 6) ? sizeof(struct landlock_ruleset_attr_full) : (sizeof(__u64) * 2);
    int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, attr_size, 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }

    /* 1. Read + Exec for system binaries */
    __u64 rx = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    add_path_rule(ruleset_fd, "/usr", rx);
    add_path_rule(ruleset_fd, "/lib", rx);
    add_path_rule(ruleset_fd, "/lib64", rx);
    add_path_rule(ruleset_fd, "/bin", rx);
    add_path_rule(ruleset_fd, "/sbin", rx);

    /* 2. Read-only for config, devices, proc */
    __u64 ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    add_path_rule(ruleset_fd, "/etc", ro);
    add_path_rule(ruleset_fd, "/proc", ro);
    add_path_rule(ruleset_fd, "/dev/urandom", ro);
    add_path_rule(ruleset_fd, "/dev/null", ro);
    add_path_rule(ruleset_fd, "/dev/zero", ro);

    /* 3. Task input directory (read-only) */
    char input_path[4096];
    snprintf(input_path, sizeof(input_path), "%s/input", workspace);
    add_path_rule(ruleset_fd, input_path, ro);

    /* Task workspace root (for reading directory metadata and accessing proxy.sock) */
    add_path_rule(ruleset_fd, workspace, ro);

    /* Task proxy socket if exists */
    char sock_path[4096];
    snprintf(sock_path, sizeof(sock_path), "%s/proxy.sock", workspace);
    add_path_rule(ruleset_fd, sock_path, ro | LANDLOCK_ACCESS_FS_WRITE_FILE);

    /* 4. Task output directory (read-write) */
    char output_path[4096];
    snprintf(output_path, sizeof(output_path), "%s/output", workspace);
    __u64 rw = ro | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
               LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
               LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_SYM |
               LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_REFER;
    add_path_rule(ruleset_fd, output_path, rw);

    /* 5. Task scratch directory (read-write) */
    char scratch_path[4096];
    snprintf(scratch_path, sizeof(scratch_path), "%s/scratch", workspace);
    add_path_rule(ruleset_fd, scratch_path, rw);

    /* 6. Task-isolated tmp directory (read-write) - /tmp is strictly excluded! */
    add_path_rule(ruleset_fd, task_tmp, rw);

    /* 7. Port rule for egress proxy */
    if (proxy_port > 0 && abi >= 4) {
        add_net_rule(ruleset_fd, proxy_port, LANDLOCK_ACCESS_NET_CONNECT_TCP);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl PR_SET_NO_NEW_PRIVS");
        close(ruleset_fd);
        return 1;
    }

    if (landlock_restrict_self(ruleset_fd, 0) != 0) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return 1;
    }
    close(ruleset_fd);

    execvp(argv[cmd_idx], &argv[cmd_idx]);
    perror("execvp");
    return 1;
}

/* ===================== M6 boundary-compiled rules mode ===================== */

#define MAX_RULES 512
#define MAX_PORTS 16

typedef struct {
    char *path;
    __u64 access;
    int optional;
} rule_t;

typedef struct {
    rule_t rules[MAX_RULES];
    int n_rules;
    __u64 ports[MAX_PORTS];
    int n_ports;
    char *task_tmp;
} ruleset_spec_t;

/* Minimal strict JSON reader for the fixed rules schema. */
typedef struct {
    const char *s;
    size_t i;
    size_t n;
    const char *err;
} jp_t;

static void jp_ws(jp_t *p) {
    while (p->i < p->n && (p->s[p->i] == ' ' || p->s[p->i] == '\n' || p->s[p->i] == '\r' || p->s[p->i] == '\t')) p->i++;
}

static int jp_expect(jp_t *p, char c) {
    jp_ws(p);
    if (p->i < p->n && p->s[p->i] == c) {
        p->i++;
        return 0;
    }
    p->err = "unexpected character";
    return -1;
}

static int jp_peek(jp_t *p, char c) {
    jp_ws(p);
    return p->i < p->n && p->s[p->i] == c;
}

static char *jp_string(jp_t *p) {
    if (jp_expect(p, '"') != 0) return NULL;
    size_t cap = 64, len = 0;
    char *out = malloc(cap);
    if (!out) return NULL;
    while (p->i < p->n) {
        char c = p->s[p->i++];
        if (c == '"') {
            out[len] = '\0';
            return out;
        }
        if ((unsigned char)c < 0x20) break;
        if (c == '\\') {
            if (p->i >= p->n) break;
            char e = p->s[p->i++];
            switch (e) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'u': {
                if (p->i + 4 > p->n) goto fail;
                unsigned v = 0;
                for (int k = 0; k < 4; k++) {
                    char h = p->s[p->i++];
                    v <<= 4;
                    if (h >= '0' && h <= '9') v |= h - '0';
                    else if (h >= 'a' && h <= 'f') v |= h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') v |= h - 'A' + 10;
                    else goto fail;
                }
                if (v == 0 || v > 0x7f) goto fail; /* paths are emitted ASCII-only */
                c = (char)v;
                break;
            }
            default: goto fail;
            }
        }
        if (len + 2 > cap) {
            cap *= 2;
            char *nb = realloc(out, cap);
            if (!nb) goto fail;
            out = nb;
        }
        out[len++] = c;
    }
fail:
    free(out);
    p->err = "bad string";
    return NULL;
}

static int jp_uint(jp_t *p, __u64 *v) {
    jp_ws(p);
    size_t start = p->i;
    __u64 x = 0;
    while (p->i < p->n && p->s[p->i] >= '0' && p->s[p->i] <= '9') {
        x = x * 10 + (p->s[p->i] - '0');
        if (x > 0xffffffffULL) {
            p->err = "number too large";
            return -1;
        }
        p->i++;
    }
    if (p->i == start) {
        p->err = "expected number";
        return -1;
    }
    *v = x;
    return 0;
}

static int jp_bool(jp_t *p, int *v) {
    jp_ws(p);
    if (p->n - p->i >= 4 && strncmp(p->s + p->i, "true", 4) == 0) {
        p->i += 4;
        *v = 1;
        return 0;
    }
    if (p->n - p->i >= 5 && strncmp(p->s + p->i, "false", 5) == 0) {
        p->i += 5;
        *v = 0;
        return 0;
    }
    p->err = "expected boolean";
    return -1;
}

static const struct {
    const char *name;
    __u64 bit;
} access_names[] = {
    {"execute", LANDLOCK_ACCESS_FS_EXECUTE},
    {"write_file", LANDLOCK_ACCESS_FS_WRITE_FILE},
    {"read_file", LANDLOCK_ACCESS_FS_READ_FILE},
    {"read_dir", LANDLOCK_ACCESS_FS_READ_DIR},
    {"remove_dir", LANDLOCK_ACCESS_FS_REMOVE_DIR},
    {"remove_file", LANDLOCK_ACCESS_FS_REMOVE_FILE},
    {"make_char", LANDLOCK_ACCESS_FS_MAKE_CHAR},
    {"make_dir", LANDLOCK_ACCESS_FS_MAKE_DIR},
    {"make_reg", LANDLOCK_ACCESS_FS_MAKE_REG},
    {"make_sock", LANDLOCK_ACCESS_FS_MAKE_SOCK},
    {"make_fifo", LANDLOCK_ACCESS_FS_MAKE_FIFO},
    {"make_block", LANDLOCK_ACCESS_FS_MAKE_BLOCK},
    {"make_sym", LANDLOCK_ACCESS_FS_MAKE_SYM},
    {"refer", LANDLOCK_ACCESS_FS_REFER},
    {"truncate", LANDLOCK_ACCESS_FS_TRUNCATE},
    {"ioctl_dev", (1ULL << 15)},
    {NULL, 0},
};

static int parse_rule(jp_t *p, rule_t *r) {
    memset(r, 0, sizeof(*r));
    if (jp_expect(p, '{') != 0) return -1;
    int first = 1;
    while (!jp_peek(p, '}')) {
        if (!first && jp_expect(p, ',') != 0) return -1;
        first = 0;
        char *key = jp_string(p);
        if (!key || jp_expect(p, ':') != 0) {
            free(key);
            return -1;
        }
        int rc = 0;
        if (strcmp(key, "path") == 0) {
            r->path = jp_string(p);
            if (!r->path || r->path[0] != '/') {
                p->err = "rule path must be absolute";
                rc = -1;
            }
        } else if (strcmp(key, "access") == 0) {
            if (jp_expect(p, '[') != 0) rc = -1;
            int afirst = 1;
            while (rc == 0 && !jp_peek(p, ']')) {
                if (!afirst && jp_expect(p, ',') != 0) {
                    rc = -1;
                    break;
                }
                afirst = 0;
                char *a = jp_string(p);
                if (!a) {
                    rc = -1;
                    break;
                }
                __u64 bit = 0;
                for (int k = 0; access_names[k].name; k++) {
                    if (strcmp(a, access_names[k].name) == 0) bit = access_names[k].bit;
                }
                free(a);
                if (!bit) {
                    p->err = "unknown access right";
                    rc = -1;
                    break;
                }
                r->access |= bit;
            }
            if (rc == 0) rc = jp_expect(p, ']');
        } else if (strcmp(key, "optional") == 0) {
            rc = jp_bool(p, &r->optional);
        } else {
            p->err = "unknown rule key";
            rc = -1;
        }
        free(key);
        if (rc != 0) return -1;
    }
    if (jp_expect(p, '}') != 0) return -1;
    if (!r->path || !r->access) {
        p->err = "rule requires path and non-empty access";
        return -1;
    }
    return 0;
}

static int parse_rules_file(const char *file, ruleset_spec_t *spec, const char **err) {
    memset(spec, 0, sizeof(*spec));
    FILE *f = fopen(file, "r");
    if (!f) {
        *err = "cannot open rules file";
        return -1;
    }
    char *buf = NULL;
    size_t cap = 0, len = 0;
    char chunk[4096];
    size_t k;
    while ((k = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (len + k + 1 > cap) {
            cap = (len + k + 1) * 2;
            char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                fclose(f);
                *err = "out of memory";
                return -1;
            }
            buf = nb;
        }
        memcpy(buf + len, chunk, k);
        len += k;
        if (len > (1 << 20)) {
            free(buf);
            fclose(f);
            *err = "rules file too large";
            return -1;
        }
    }
    fclose(f);
    if (!buf) {
        *err = "empty rules file";
        return -1;
    }
    buf[len] = '\0';

    jp_t p = {.s = buf, .i = 0, .n = len, .err = NULL};
    int version_seen = 0;
    if (jp_expect(&p, '{') != 0) goto bad;
    int first = 1;
    while (!jp_peek(&p, '}')) {
        if (!first && jp_expect(&p, ',') != 0) goto bad;
        first = 0;
        char *key = jp_string(&p);
        if (!key || jp_expect(&p, ':') != 0) {
            free(key);
            goto bad;
        }
        int rc = 0;
        if (strcmp(key, "version") == 0) {
            __u64 v;
            rc = jp_uint(&p, &v);
            if (rc == 0 && v != 1) {
                p.err = "unsupported rules version";
                rc = -1;
            }
            version_seen = 1;
        } else if (strcmp(key, "task_tmp") == 0) {
            spec->task_tmp = jp_string(&p);
            if (!spec->task_tmp || spec->task_tmp[0] != '/') rc = -1;
        } else if (strcmp(key, "tcp_connect_ports") == 0) {
            rc = jp_expect(&p, '[');
            int pf = 1;
            while (rc == 0 && !jp_peek(&p, ']')) {
                if (!pf && jp_expect(&p, ',') != 0) {
                    rc = -1;
                    break;
                }
                pf = 0;
                if (spec->n_ports >= MAX_PORTS) {
                    p.err = "too many ports";
                    rc = -1;
                    break;
                }
                __u64 port;
                rc = jp_uint(&p, &port);
                if (rc == 0 && (port == 0 || port > 65535)) {
                    p.err = "invalid port";
                    rc = -1;
                }
                if (rc == 0) spec->ports[spec->n_ports++] = port;
            }
            if (rc == 0) rc = jp_expect(&p, ']');
        } else if (strcmp(key, "rules") == 0) {
            rc = jp_expect(&p, '[');
            int rf = 1;
            while (rc == 0 && !jp_peek(&p, ']')) {
                if (!rf && jp_expect(&p, ',') != 0) {
                    rc = -1;
                    break;
                }
                rf = 0;
                if (spec->n_rules >= MAX_RULES) {
                    p.err = "too many rules";
                    rc = -1;
                    break;
                }
                rc = parse_rule(&p, &spec->rules[spec->n_rules]);
                if (rc == 0) spec->n_rules++;
            }
            if (rc == 0) rc = jp_expect(&p, ']');
        } else {
            p.err = "unknown top-level key";
            rc = -1;
        }
        free(key);
        if (rc != 0) goto bad;
    }
    if (jp_expect(&p, '}') != 0) goto bad;
    jp_ws(&p);
    if (p.i != p.n) {
        p.err = "trailing data";
        goto bad;
    }
    if (!version_seen || !spec->task_tmp) {
        p.err = "rules file requires version and task_tmp";
        goto bad;
    }
    free(buf);
    return 0;
bad:
    *err = p.err ? p.err : "malformed rules file";
    free(buf);
    return -1;
}

static int read_seccomp_filter_count(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    int count = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp_filters:", 16) == 0) {
            count = atoi(line + 16);
            break;
        }
    }
    fclose(f);
    return count;
}

static void write_status(int fd, const char *json) {
    if (fd < 0) return;
    size_t len = strlen(json);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, json + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)w;
    }
    close(fd);
}

static int rules_main(int argc, char **argv) {
    const char *rules_file = NULL;
    int status_fd = -1;
    int enforce_mode = 1;
    int simulate_fail = 0;
    int cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rules") == 0 && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (strcmp(argv[i], "--status-fd") == 0 && i + 1 < argc) {
            status_fd = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            enforce_mode = strcmp(argv[++i], "observe") == 0 ? 0 : 1;
        } else if (strcmp(argv[i], "--simulate-unshare-fail") == 0) {
            simulate_fail = 1;
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        } else {
            fprintf(stderr, "SECURITY_ERROR: unknown argument '%s'\n", argv[i]);
            return 1;
        }
    }
    if (!rules_file || cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "Usage: %s --rules <file> [--status-fd N] [--mode enforce|observe] -- <cmd> [args...]\n", argv[0]);
        return 1;
    }
    if (status_fd >= 0) fcntl(status_fd, F_SETFD, FD_CLOEXEC);

    ruleset_spec_t spec;
    const char *perr = NULL;
    if (parse_rules_file(rules_file, &spec, &perr) != 0) {
        /* A malformed rules file is fatal in both modes: there is no safe default. */
        fprintf(stderr, "SECURITY_ERROR: invalid rules file %s: %s\n", rules_file, perr);
        return 1;
    }

    setenv("TMPDIR", spec.task_tmp, 1);
    setenv("TEMP", spec.task_tmp, 1);
    setenv("TMP", spec.task_tmp, 1);

    if (isolate_user_and_mounts(getuid(), getgid(), enforce_mode, simulate_fail) != 0) {
        fprintf(stderr, "Task execution aborted due to namespace isolation failure in ENFORCE mode.\n");
        return 1;
    }
    const char *iso = getenv("GOVERNANCE_ISOLATION_LEVEL");
    char isolation[64];
    snprintf(isolation, sizeof(isolation), "%s", iso ? iso : "unknown");
    unsetenv("GOVERNANCE_ISOLATION_LEVEL");

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        fprintf(stderr, "SECURITY_ERROR: Landlock is not supported by kernel (abi=%d)\n", abi);
        return 1;
    }

    struct landlock_ruleset_attr_full {
        __u64 handled_access_fs;
        __u64 handled_access_net;
        __u64 scoped_access;
    } attr = {
        .handled_access_fs = (abi >= 5) ? ((1ULL << 16) - 1) : (abi >= 3 ? ((1ULL << 15) - 1) : ((1ULL << 14) - 1)),
        .handled_access_net = (abi >= 4) ? (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP) : 0,
        .scoped_access = (abi >= 6) ? (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL) : 0,
    };
    if (enforce_mode && abi < 6) {
        fprintf(stderr, "SECURITY_ERROR: ENFORCE requires Landlock ABI >= 6 (signal/abstract-socket scoping), have %d\n", abi);
        return 1;
    }
    size_t attr_size = (abi >= 6) ? sizeof(attr) : (sizeof(__u64) * 2);
    int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, attr_size, 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }

    int applied = 0, skipped = 0;
    for (int r = 0; r < spec.n_rules; r++) {
        rule_t *rule = &spec.rules[r];
        int fd = open(rule->path, O_PATH | O_CLOEXEC);
        if (fd < 0) {
            if (rule->optional) {
                skipped++;
                continue;
            }
            fprintf(stderr, "SECURITY_ERROR: rule path %s unavailable: %s\n", rule->path, strerror(errno));
            close(ruleset_fd);
            return 1;
        }
        struct landlock_path_beneath_attr pb = {
            .allowed_access = rule->access & attr.handled_access_fs,
            .parent_fd = fd,
        };
        int res = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
        int saved = errno;
        close(fd);
        if (res != 0) {
            fprintf(stderr, "SECURITY_ERROR: landlock_add_rule(%s) failed: %s\n", rule->path, strerror(saved));
            close(ruleset_fd);
            return 1;
        }
        applied++;
    }
    for (int k = 0; k < spec.n_ports && abi >= 4; k++) {
        if (add_net_rule(ruleset_fd, spec.ports[k], LANDLOCK_ACCESS_NET_CONNECT_TCP) != 0) {
            fprintf(stderr, "SECURITY_ERROR: landlock net rule for port %llu failed: %s\n",
                    (unsigned long long)spec.ports[k], strerror(errno));
            close(ruleset_fd);
            return 1;
        }
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl PR_SET_NO_NEW_PRIVS");
        close(ruleset_fd);
        return 1;
    }
    if (landlock_restrict_self(ruleset_fd, 0) != 0) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return 1;
    }
    close(ruleset_fd);

    char status[512];
    snprintf(status, sizeof(status),
             "{\"isolation_level\":\"%s\",\"landlock_abi\":%d,\"landlock_applied\":true,\"rules_applied\":%d,"
             "\"rules_skipped_optional\":%d,\"tcp_connect_ports\":%d,\"net_restricted\":%s,\"scoped\":%s,"
             "\"seccomp_filters\":%d,\"mode\":\"%s\",\"pid\":%d}\n",
             isolation, abi, applied, skipped, spec.n_ports, abi >= 4 ? "true" : "false",
             abi >= 6 ? "true" : "false", read_seccomp_filter_count(), enforce_mode ? "enforce" : "observe",
             getpid());
    write_status(status_fd, status);

    execvp(argv[cmd_idx], &argv[cmd_idx]);
    perror("execvp");
    return 127;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) break;
        if (strcmp(argv[i], "--rules") == 0) return rules_main(argc, argv);
    }
    return legacy_main(argc, argv);
}
