/*
 * OS Sensor: ptrace + SECCOMP_RET_TRACE Syscall Interceptor
 *
 * Captures openat, execve, and connect syscalls at the kernel boundary.
 * Attributes each event to a task via /proc/<pid>/cgroup.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

static void read_tracee_string(pid_t pid, unsigned long addr, char *buffer, size_t max_len) {
    size_t i = 0;
    while (i + sizeof(long) <= max_len) {
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) {
            break;
        }
        memcpy(buffer + i, &val, sizeof(long));
        for (size_t j = 0; j < sizeof(long); j++) {
            if (buffer[i + j] == '\0') {
                return;
            }
        }
        i += sizeof(long);
    }
    buffer[max_len - 1] = '\0';
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

static void log_governance_event(pid_t pid, const char *syscall_name, const char *target, const char *cgroup_id, int cg_status, int verdict) {
    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    /* Output JSON line for ingestion by security monitor / storage */
    printf("{\"source\":\"os_sensor\",\"timestamp\":\"%s\",\"pid\":%d,\"cgroup_id\":\"%s\",\"cgroup_status\":\"%s\",\"syscall\":\"%s\",\"target\":\"%s\",\"verdict\":\"%s\"}\n",
           time_str, pid, cgroup_id, cgroup_status_name(cg_status), syscall_name, target, verdict ? "ALLOWED" : "PREVENTED");
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Child: Allow parent tracing under ptrace_scope=1 */
        pid_t ppid = getppid();
        prctl(PR_SET_PTRACER, ppid, 0, 0, 0);

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace TRACEME");
            return 1;
        }

        /* Raise SIGSTOP so parent can configure PTRACE_SETOPTIONS */
        raise(SIGSTOP);

        /* Apply seccomp filter setting SECCOMP_RET_TRACE on openat, execve, connect */
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (ctx) {
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(openat), 0);
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(open), 0);
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SCMP_SYS(execve), 0);
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(connect), 0);
            seccomp_load(ctx);
            seccomp_release(ctx);
        }

        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(1);
    }

    /* Parent Tracer */
    int status;
    waitpid(child, &status, 0);

    /* Configure options to trace across fork/clone/exec and seccomp */
    ptrace(PTRACE_SETOPTIONS, child, 0,
           PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);

    ptrace(PTRACE_CONT, child, 0, 0);

    while (1) {
        pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0) {
            if (errno == ECHILD) break;
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == child) {
                return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            }
            continue;
        }

        /* Check for SECCOMP event */
        if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, 0, &regs);

            char cgroup[PATH_MAX];
            int cg_status = read_tracee_cgroup(pid, cgroup, sizeof(cgroup));

            unsigned long syscall_nr = regs.orig_rax;
            char target_buf[1024] = {0};

            if (syscall_nr == 257) { /* openat(dfd, filename, flags, mode) */
                read_tracee_string(pid, regs.rsi, target_buf, sizeof(target_buf));
                log_governance_event(pid, "openat", target_buf, cgroup, cg_status, 1);
            } else if (syscall_nr == 2) { /* open(filename, flags, mode) */
                read_tracee_string(pid, regs.rdi, target_buf, sizeof(target_buf));
                log_governance_event(pid, "open", target_buf, cgroup, cg_status, 1);
            } else if (syscall_nr == 59) { /* execve(filename, argv, envp) */
                read_tracee_string(pid, regs.rdi, target_buf, sizeof(target_buf));
                log_governance_event(pid, "execve", target_buf, cgroup, cg_status, 1);
            } else if (syscall_nr == 42) { /* connect(fd, sockaddr, len) */
                snprintf(target_buf, sizeof(target_buf), "tcp_connect(fd=%lld)", (long long)regs.rdi);
                log_governance_event(pid, "connect", target_buf, cgroup, cg_status, 1);
            }
        }

        ptrace(PTRACE_CONT, pid, 0, 0);
    }

    return 0;
}
