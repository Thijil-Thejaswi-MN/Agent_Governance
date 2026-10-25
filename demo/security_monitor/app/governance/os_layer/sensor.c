/*
 * OS Sensor: ptrace + SECCOMP_RET_TRACE Syscall Observer (observation only)
 *
 * Captures the traced process tree's syscalls in these families:
 *   open:     open, openat, openat2
 *   exec:     execve, execveat
 *   fs-mod:   rename, renameat, renameat2, unlink, unlinkat, rmdir, mkdir, mkdirat,
 *             link, linkat, symlink, symlinkat, truncate, ftruncate (fd resolved to path)
 *   network:  connect, bind, sendto (only with a destination address),
 *             sendmsg / sendmmsg (emitted only when msg_name carries an address) For every event it records pid, ppid, syscall, target,
 * return value and the cgroup v2 path read at event time (/proc/<pid>/cgroup).
 * The sensor never blocks or alters a syscall: Phase 0 showed a ptrace tracer
 * must not be used as the enforcer.
 *
 * Usage:
 *   sensor [--events-fd N] [--gate-fd N] [--] <command> [args...]
 *
 *   --events-fd N  write JSON event lines to fd N instead of stdout
 *   --gate-fd N    after the child is stopped and tracing is configured, block
 *                  until one byte is read from fd N before letting the child
 *                  run (lets the launcher record task identity first). EOF or
 *                  error on the gate kills the child (fail closed).
 *
 * Output (one JSON object per line, all lines start with {"source":"os_sensor"):
 *   type=start    sensor pid, traced child pid
 *   type=syscall  one observed syscall (entry data + return value)
 *   type=exit     emitted only on orderly exit; its absence means the sensor
 *                 died early.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#define TARGET_MAX PATH_MAX

static FILE *out = NULL;
static unsigned long long seq = 0;

/* ---------- JSON helpers ---------- */

static void json_str(FILE *f, const char *s) {
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

/* ---------- tracee memory / proc helpers ---------- */

/* Returns 0 on success, 1 if truncated, -1 on read failure. */
static int read_tracee_string(pid_t pid, unsigned long addr, char *buffer, size_t max_len) {
    size_t i = 0;
    buffer[0] = '\0';
    if (addr == 0) return -1;
    while (i + sizeof(long) <= max_len) {
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) {
            buffer[i] = '\0';
            return i == 0 ? -1 : 1;
        }
        memcpy(buffer + i, &val, sizeof(long));
        for (size_t j = 0; j < sizeof(long); j++) {
            if (buffer[i + j] == '\0') {
                return 0;
            }
        }
        i += sizeof(long);
    }
    buffer[max_len - 1] = '\0';
    return 1;
}

static int read_tracee_bytes(pid_t pid, unsigned long addr, void *dst, size_t len) {
    size_t i = 0;
    unsigned char *d = dst;
    while (i < len) {
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) return -1;
        size_t n = len - i < sizeof(long) ? len - i : sizeof(long);
        memcpy(d + i, &val, n);
        i += n;
    }
    return 0;
}

/*
 * Reads the tracee's cgroup v2 path at event time.
 * Returns CG_OK, CG_UNKNOWN (no /proc entry / unreadable) or CG_TRUNCATED.
 * A truncated path is never emitted: it could match no task and make the
 * event look UNATTRIBUTED, so truncation is reported explicitly instead.
 */
enum { CG_OK = 0, CG_UNKNOWN = 1, CG_TRUNCATED = 2 };

static int read_tracee_cgroup(pid_t pid, char *cgroup_buf, size_t max_len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    cgroup_buf[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) {
        return CG_UNKNOWN;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, f);
    fclose(f);
    if (n <= 0) {
        free(line);
        return CG_UNKNOWN;
    }
    if (line[n - 1] == '\n') line[--n] = '\0';
    /* cgroup v2 line format: "0::/path" */
    char *colon = strrchr(line, ':');
    const char *src = colon ? colon + 1 : line;
    size_t len = strlen(src);
    if (len >= max_len) {
        free(line);
        return CG_TRUNCATED;
    }
    memcpy(cgroup_buf, src, len + 1);
    free(line);
    return CG_OK;
}

static const char *cgroup_status_name(int st) {
    switch (st) {
    case CG_OK: return "ok";
    case CG_TRUNCATED: return "truncated";
    default: return "unknown";
    }
}

static pid_t read_ppid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *rp = strrchr(buf, ')');
    if (!rp) return -1;
    char state;
    int ppid = -1;
    if (sscanf(rp + 1, " %c %d", &state, &ppid) != 2) return -1;
    return ppid;
}

/* Resolves the directory a relative path is evaluated against (cwd or dirfd). */
static int resolve_base_dir(pid_t pid, long dirfd, char *buf, size_t len) {
    char link[64];
    if (dirfd == AT_FDCWD) {
        snprintf(link, sizeof(link), "/proc/%d/cwd", pid);
    } else {
        snprintf(link, sizeof(link), "/proc/%d/fd/%ld", pid, dirfd);
    }
    ssize_t n = readlink(link, buf, len - 1);
    if (n < 0 || (size_t)n >= len - 1) return -1;
    buf[n] = '\0';
    return 0;
}

/* ---------- pending syscall table (entry data awaiting the return value) ---------- */

typedef struct {
    pid_t pid;
    int in_use;
    int seen;
    const char *syscall;
    char target[TARGET_MAX];
    char abs_target[TARGET_MAX];
    int target_status; /* 0 ok, 1 truncated, -1 unreadable */
    char target2[TARGET_MAX];     /* second path: rename/link destination, symlink link path */
    char abs_target2[TARGET_MAX];
    int has_target2;
    long long aux;                /* unlinkat/renameat2/linkat flags */
    int has_aux;
    long long flags;
    int has_flags;
    pid_t ppid;
    char cgroup[PATH_MAX];
    int cg_status;
} pending_t;

#define MAX_TRACKED 512
static pending_t table[MAX_TRACKED];

static pending_t *slot_for(pid_t pid, int create) {
    pending_t *free_slot = NULL;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (table[i].pid == pid && (table[i].in_use || table[i].seen)) return &table[i];
        if (!free_slot && !table[i].in_use && !table[i].seen) free_slot = &table[i];
    }
    if (create && free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->pid = pid;
        return free_slot;
    }
    return NULL;
}

static void forget_pid(pid_t pid) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (table[i].pid == pid) {
            table[i].in_use = 0;
            table[i].seen = 0;
            table[i].pid = 0;
        }
    }
}

static const char *access_name(long long flags) {
    switch (flags & O_ACCMODE) {
    case O_WRONLY: return "write";
    case O_RDWR: return "read_write";
    default: return "read";
    }
}

static void emit_syscall(pending_t *p, long long ret) {
    char ts[48];
    long long ms;
    now_iso(ts, sizeof(ts), &ms);
    fprintf(out, "{\"source\":\"os_sensor\",\"type\":\"syscall\",\"seq\":%llu,\"timestamp\":\"%s\",\"ts_ms\":%lld,"
                 "\"pid\":%d,\"ppid\":%d,\"cgroup_id\":",
            ++seq, ts, ms, p->pid, p->ppid);
    json_str(out, p->cgroup);
    fprintf(out, ",\"cgroup_status\":\"%s\",\"syscall\":\"%s\",\"target\":", cgroup_status_name(p->cg_status), p->syscall);
    json_str(out, p->target);
    fputs(",\"abs_target\":", out);
    json_str(out, p->abs_target);
    fprintf(out, ",\"target_status\":\"%s\"",
            p->target_status == 0 ? "ok" : (p->target_status == 1 ? "truncated" : "unreadable"));
    if (p->has_target2) {
        fputs(",\"target2\":", out);
        json_str(out, p->target2);
        fputs(",\"abs_target2\":", out);
        json_str(out, p->abs_target2);
    }
    if (p->has_aux) fprintf(out, ",\"aux_flags\":%lld", p->aux);
    if (p->has_flags) {
        fprintf(out, ",\"flags\":%lld,\"access\":\"%s\",\"creat\":%s", p->flags, access_name(p->flags),
                (p->flags & O_CREAT) ? "true" : "false");
    }
    if (ret < 0 && ret > -4096) {
        const char *en = strerrorname_np((int)-ret);
        fprintf(out, ",\"ret\":%lld,\"result\":\"%s\"}\n", ret, en ? en : "EUNKNOWN");
    } else {
        fprintf(out, ",\"ret\":%lld,\"result\":\"ok\"}\n", ret);
    }
    fflush(out);
}

static void join_path(char *dst, size_t len, const char *base, const char *rel) {
    if (rel[0] == '/') {
        snprintf(dst, len, "%s", rel);
    } else if (base[0]) {
        if (snprintf(dst, len, "%s/%s", base, rel) >= (int)len) dst[0] = '\0';
    } else {
        dst[0] = '\0';
    }
}

static void describe_sockaddr(pid_t pid, unsigned long addr, unsigned long addrlen, char *dst, size_t len) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    size_t n = addrlen < sizeof(ss) ? addrlen : sizeof(ss);
    if (n < sizeof(sa_family_t) || read_tracee_bytes(pid, addr, &ss, n) != 0) {
        snprintf(dst, len, "sockaddr:unreadable");
        return;
    }
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        snprintf(dst, len, "inet:%s:%u", ip, ntohs(in->sin_port));
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
        snprintf(dst, len, "inet6:[%s]:%u", ip, ntohs(in6->sin6_port));
    } else if (ss.ss_family == AF_UNIX) {
        struct sockaddr_un *un = (struct sockaddr_un *)&ss;
        size_t plen = n - offsetof(struct sockaddr_un, sun_path);
        if (plen == 0) {
            snprintf(dst, len, "unix:unnamed");
        } else if (un->sun_path[0] == '\0') {
            char name[sizeof(un->sun_path)];
            size_t k = plen - 1 < sizeof(name) - 1 ? plen - 1 : sizeof(name) - 1;
            memcpy(name, un->sun_path + 1, k);
            name[k] = '\0';
            snprintf(dst, len, "unix-abstract:@%s", name);
        } else {
            char name[sizeof(un->sun_path) + 1];
            memcpy(name, un->sun_path, sizeof(un->sun_path));
            name[sizeof(un->sun_path)] = '\0';
            char base[PATH_MAX];
            if (name[0] != '/' && resolve_base_dir(pid, AT_FDCWD, base, sizeof(base)) == 0) {
                /* relative socket path: resolve against the caller's cwd, like file paths.
                 * An over-long result is reported explicitly, never cut. */
                int w = snprintf(dst, len, "unix:%s/%s", base, name);
                if (w < 0 || (size_t)w >= len) snprintf(dst, len, "unix-unresolved:%s", name);
            } else {
                snprintf(dst, len, "unix:%s", name);
            }
        }
    } else {
        snprintf(dst, len, "family:%u", ss.ss_family);
    }
}

/* Reads a path argument and its absolute form (relative paths resolved via dirfd/cwd). */
static int read_path_arg(pid_t pid, long dirfd, unsigned long addr, char *raw, char *abs, size_t len) {
    raw[0] = '\0';
    abs[0] = '\0';
    int st = read_tracee_string(pid, addr, raw, len);
    if (st == 0) {
        char base[PATH_MAX];
        base[0] = '\0';
        if (raw[0] != '/') {
            if (resolve_base_dir(pid, dirfd, base, sizeof(base)) != 0) base[0] = '\0';
        }
        join_path(abs, len, base, raw);
    }
    return st;
}

/* Resolves the destination address of sendmsg/sendmmsg (msg_name of the first msghdr). */
static int msghdr_dest(pid_t pid, unsigned long msghdr_addr, char *dst, size_t len) {
    struct {
        unsigned long name;
        unsigned int namelen;
    } h;
    if (msghdr_addr == 0 || read_tracee_bytes(pid, msghdr_addr, &h, sizeof(h)) != 0) return -1;
    if (h.name == 0 || h.namelen == 0) return -1; /* connected socket: no explicit destination */
    describe_sockaddr(pid, h.name, h.namelen, dst, len);
    return 0;
}

/* Fills a pending record from a seccomp-stop. Returns 0 if the syscall is one we emit. */
static int capture_entry(pid_t pid, pending_t *p) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) return -1;
    unsigned long nr = regs.orig_rax;

    p->has_flags = 0;
    p->has_target2 = 0;
    p->has_aux = 0;
    p->target[0] = p->abs_target[0] = '\0';
    p->target2[0] = p->abs_target2[0] = '\0';
    p->target_status = 0;
    const size_t L = TARGET_MAX;

#define PATH1(dfd, a) (p->target_status = read_path_arg(pid, (dfd), (a), p->target, p->abs_target, L))
#define PATH2(dfd, a) (p->has_target2 = 1, read_path_arg(pid, (dfd), (a), p->target2, p->abs_target2, L))

    switch (nr) {
    case 2: /* open(path, flags, mode) */
        p->syscall = "open";
        PATH1(AT_FDCWD, regs.rdi);
        p->flags = (long long)regs.rsi;
        p->has_flags = 1;
        break;
    case 257: /* openat(dfd, path, flags, mode) */
        p->syscall = "openat";
        PATH1((int)regs.rdi, regs.rsi);
        p->flags = (long long)regs.rdx;
        p->has_flags = 1;
        break;
    case __NR_openat2: { /* openat2(dfd, path, how, size); how->flags is the first u64 */
        p->syscall = "openat2";
        PATH1((int)regs.rdi, regs.rsi);
        uint64_t how_flags = 0;
        if (read_tracee_bytes(pid, regs.rdx, &how_flags, sizeof(how_flags)) == 0) {
            p->flags = (long long)how_flags;
            p->has_flags = 1;
        }
        break;
    }
    case 59: /* execve(path, argv, envp) */
        p->syscall = "execve";
        PATH1(AT_FDCWD, regs.rdi);
        break;
    case 322: /* execveat(dfd, path, argv, envp, flags) */
        p->syscall = "execveat";
        PATH1((int)regs.rdi, regs.rsi);
        break;
    case 82: /* rename(old, new) */
        p->syscall = "rename";
        PATH1(AT_FDCWD, regs.rdi);
        PATH2(AT_FDCWD, regs.rsi);
        break;
    case 264: /* renameat(olddfd, old, newdfd, new) */
    case 316: /* renameat2(olddfd, old, newdfd, new, flags) */
        p->syscall = nr == 264 ? "renameat" : "renameat2";
        PATH1((int)regs.rdi, regs.rsi);
        PATH2((int)regs.rdx, regs.r10);
        if (nr == 316) {
            p->aux = (long long)regs.r8;
            p->has_aux = 1;
        }
        break;
    case 87: /* unlink(path) */
        p->syscall = "unlink";
        PATH1(AT_FDCWD, regs.rdi);
        break;
    case 84: /* rmdir(path) */
        p->syscall = "rmdir";
        PATH1(AT_FDCWD, regs.rdi);
        break;
    case 263: /* unlinkat(dfd, path, flags) */
        p->syscall = "unlinkat";
        PATH1((int)regs.rdi, regs.rsi);
        p->aux = (long long)regs.rdx;
        p->has_aux = 1;
        break;
    case 83: /* mkdir(path, mode) */
        p->syscall = "mkdir";
        PATH1(AT_FDCWD, regs.rdi);
        break;
    case 258: /* mkdirat(dfd, path, mode) */
        p->syscall = "mkdirat";
        PATH1((int)regs.rdi, regs.rsi);
        break;
    case 86: /* link(old, new) */
        p->syscall = "link";
        PATH1(AT_FDCWD, regs.rdi);
        PATH2(AT_FDCWD, regs.rsi);
        break;
    case 265: /* linkat(olddfd, old, newdfd, new, flags) */
        p->syscall = "linkat";
        PATH1((int)regs.rdi, regs.rsi);
        PATH2((int)regs.rdx, regs.r10);
        p->aux = (long long)regs.r8;
        p->has_aux = 1;
        break;
    case 88: /* symlink(target, linkpath): target is link content, not resolved */
        p->syscall = "symlink";
        p->target_status = read_tracee_string(pid, regs.rdi, p->target, L);
        snprintf(p->abs_target, L, "%s", p->target);
        PATH2(AT_FDCWD, regs.rsi);
        break;
    case 266: /* symlinkat(target, newdfd, linkpath) */
        p->syscall = "symlinkat";
        p->target_status = read_tracee_string(pid, regs.rdi, p->target, L);
        snprintf(p->abs_target, L, "%s", p->target);
        PATH2((int)regs.rsi, regs.rdx);
        break;
    case 76: /* truncate(path, len) */
        p->syscall = "truncate";
        PATH1(AT_FDCWD, regs.rdi);
        break;
    case 77: { /* ftruncate(fd, len): resolve the fd to its path */
        p->syscall = "ftruncate";
        char link[64];
        snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, (int)regs.rdi);
        ssize_t n = readlink(link, p->abs_target, L - 1);
        if (n < 0) {
            p->abs_target[0] = '\0';
            p->target_status = -1;
        } else {
            p->abs_target[n] = '\0';
        }
        snprintf(p->target, L, "fd:%d", (int)regs.rdi);
        break;
    }
    case 42: /* connect(fd, sockaddr, len) */
        p->syscall = "connect";
        describe_sockaddr(pid, regs.rsi, regs.rdx, p->target, L);
        snprintf(p->abs_target, L, "%s", p->target);
        break;
    case 49: /* bind(fd, sockaddr, len) */
        p->syscall = "bind";
        describe_sockaddr(pid, regs.rsi, regs.rdx, p->target, L);
        snprintf(p->abs_target, L, "%s", p->target);
        break;
    case 44: /* sendto(fd, buf, len, flags, dest, addrlen); BPF only traps dest != NULL */
        if (regs.r8 == 0) return -1;
        p->syscall = "sendto";
        describe_sockaddr(pid, regs.r8, regs.r9, p->target, L);
        snprintf(p->abs_target, L, "%s", p->target);
        break;
    case 46: /* sendmsg(fd, msghdr, flags) */
        if (msghdr_dest(pid, regs.rsi, p->target, L) != 0) return -1;
        p->syscall = "sendmsg";
        snprintf(p->abs_target, L, "%s", p->target);
        break;
    case 307: /* sendmmsg(fd, mmsghdr[], vlen, flags): destination of the first message */
        if (msghdr_dest(pid, regs.rsi, p->target, L) != 0) return -1;
        p->syscall = "sendmmsg";
        snprintf(p->abs_target, L, "%s", p->target);
        break;
    default:
        return -1;
    }
#undef PATH1
#undef PATH2

    p->ppid = read_ppid(pid);
    p->cg_status = read_tracee_cgroup(pid, p->cgroup, sizeof(p->cgroup));
    return 0;
}

static int observe_child_setup(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1;
    int rc = 0;
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(openat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(open), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(openat2), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SCMP_SYS(execve), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SCMP_SYS(execveat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(connect), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(bind), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(sendto), 1, SCMP_A4(SCMP_CMP_NE, 0));
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(sendmsg), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(sendmmsg), 0);
    static const int fsmod[] = {
        SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2), SCMP_SYS(unlink), SCMP_SYS(unlinkat),
        SCMP_SYS(rmdir), SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(link), SCMP_SYS(linkat),
        SCMP_SYS(symlink), SCMP_SYS(symlinkat), SCMP_SYS(truncate), SCMP_SYS(ftruncate),
    };
    for (size_t k = 0; k < sizeof(fsmod) / sizeof(fsmod[0]); k++) {
        rc |= seccomp_rule_add(ctx, SCMP_ACT_TRACE(4), fsmod[k], 0);
    }
    if (rc == 0) rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc;
}

int main(int argc, char **argv) {
    int events_fd = -1;
    int gate_fd = -1;
    int cmd_idx = 1;
    while (cmd_idx < argc) {
        if (strcmp(argv[cmd_idx], "--events-fd") == 0 && cmd_idx + 1 < argc) {
            events_fd = atoi(argv[cmd_idx + 1]);
            cmd_idx += 2;
        } else if (strcmp(argv[cmd_idx], "--gate-fd") == 0 && cmd_idx + 1 < argc) {
            gate_fd = atoi(argv[cmd_idx + 1]);
            cmd_idx += 2;
        } else if (strcmp(argv[cmd_idx], "--") == 0) {
            cmd_idx++;
            break;
        } else {
            break;
        }
    }
    if (cmd_idx >= argc) {
        fprintf(stderr, "Usage: %s [--events-fd N] [--gate-fd N] [--] <command> [args...]\n", argv[0]);
        return 1;
    }

    if (events_fd >= 0) {
        out = fdopen(events_fd, "w");
        if (!out) {
            perror("fdopen events-fd");
            return 1;
        }
        fcntl(events_fd, F_SETFD, FD_CLOEXEC);
    } else {
        out = stdout;
    }
    if (gate_fd >= 0) fcntl(gate_fd, F_SETFD, FD_CLOEXEC);

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Child: the sensor's events/gate fds must not leak into the traced tree. */
        if (events_fd >= 0) close(events_fd);
        if (gate_fd >= 0) close(gate_fd);

        /* Allow parent tracing under ptrace_scope=1 */
        prctl(PR_SET_PTRACER, getppid(), 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace TRACEME");
            _exit(1);
        }
        /* Stop so the parent can configure PTRACE_SETOPTIONS (and hold the gate). */
        raise(SIGSTOP);

        if (observe_child_setup() != 0) {
            fprintf(stderr, "sensor: failed to install SECCOMP_RET_TRACE filter\n");
            _exit(1);
        }
        execvp(argv[cmd_idx], &argv[cmd_idx]);
        perror("execvp");
        _exit(127);
    }

    /* Parent tracer */
    int status;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        fprintf(stderr, "sensor: child did not stop for tracing setup\n");
        return 1;
    }
    ptrace(PTRACE_SETOPTIONS, child, 0,
           PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD);

    pending_t *root = slot_for(child, 1);
    if (root) root->seen = 1;

    {
        char ts[48];
        long long ms;
        now_iso(ts, sizeof(ts), &ms);
        fprintf(out, "{\"source\":\"os_sensor\",\"type\":\"start\",\"timestamp\":\"%s\",\"ts_ms\":%lld,"
                     "\"sensor_pid\":%d,\"child_pid\":%d}\n",
                ts, ms, getpid(), child);
        fflush(out);
    }

    if (gate_fd >= 0) {
        char b;
        ssize_t n;
        do {
            n = read(gate_fd, &b, 1);
        } while (n < 0 && errno == EINTR);
        close(gate_fd);
        if (n != 1) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            fprintf(stderr, "sensor: gate closed before release; child killed (fail closed)\n");
            return 125;
        }
    }

    ptrace(PTRACE_CONT, child, 0, 0);

    int child_exit = -1;
    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == ECHILD) break;
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == child) {
                child_exit = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            }
            forget_pid(pid);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        int event = (status >> 16) & 0xff;
        pending_t *p = slot_for(pid, 1);

        if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
            if (p && capture_entry(pid, p) == 0) {
                p->in_use = 1;
                p->seen = 1;
                /* Resume to the syscall-exit stop to read the return value. */
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            } else {
                ptrace(PTRACE_CONT, pid, 0, 0);
            }
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) { /* syscall-exit stop (TRACESYSGOOD) */
            if (p && p->in_use) {
                struct user_regs_struct regs;
                long long ret = -1;
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) ret = (long long)regs.rax;
                emit_syscall(p, ret);
                p->in_use = 0;
            }
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }

        if (sig == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            /* A non-leader thread exec takes over the leader's pid. */
            unsigned long former = 0;
            ptrace(PTRACE_GETEVENTMSG, pid, 0, &former);
            if ((pid_t)former != pid) {
                pending_t *old = slot_for((pid_t)former, 0);
                if (old && old->in_use && p) {
                    pid_t keep = p->pid;
                    memcpy(p, old, sizeof(*p));
                    p->pid = keep;
                    old->in_use = 0;
                }
            }
            if (p && p->in_use) {
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            } else {
                ptrace(PTRACE_CONT, pid, 0, 0);
            }
            continue;
        }

        if (sig == SIGTRAP && (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                               event == PTRACE_EVENT_CLONE)) {
            if (p) p->seen = 1;
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }

        /* Signal-delivery stop. The first SIGSTOP of a newly auto-attached task is
         * the attach stop and is suppressed; every other signal is re-injected so
         * the sensor does not change the tracee's signal semantics. */
        if (p && !p->seen && sig == SIGSTOP) {
            p->seen = 1;
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }
        if (p) p->seen = 1;
        ptrace(PTRACE_CONT, pid, 0, sig == SIGTRAP ? 0 : sig);
    }

    {
        char ts[48];
        long long ms;
        now_iso(ts, sizeof(ts), &ms);
        fprintf(out, "{\"source\":\"os_sensor\",\"type\":\"exit\",\"timestamp\":\"%s\",\"ts_ms\":%lld,"
                     "\"child_exit\":%d,\"events\":%llu}\n",
                ts, ms, child_exit, seq);
        fflush(out);
    }
    return child_exit < 0 ? 1 : child_exit;
}
