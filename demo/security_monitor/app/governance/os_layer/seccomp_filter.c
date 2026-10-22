/*
 * Seccomp BPF Filter for Agent Sandboxing
 *
 * Denies io_uring_setup, io_uring_enter, io_uring_register (EPERM),
 * and prohibits non-native 32-bit compatibility syscall ABIs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

int apply_seccomp_filter(int trace_openat, int trace_execve, int trace_connect) {
    /* Initialize default allow */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init");
        return -1;
    }

    /* Enforce strict native x86_64 architecture (deny x86 32-bit compat ABI) */
    int rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
    if (rc < 0 && rc != -EEXIST) {
        fprintf(stderr, "seccomp_arch_add failed: %d\n", rc);
        seccomp_release(ctx);
        return -1;
    }

    /* Block io_uring family with EPERM */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_setup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_enter), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_register), 0);

    /* If OS sensor tracing is requested, set SECCOMP_RET_TRACE on monitored syscalls */
    if (trace_openat) {
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(openat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(open), 0);
    }
    if (trace_execve) {
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SCMP_SYS(execve), 0);
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SCMP_SYS(execveat), 0);
    }
    if (trace_connect) {
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(connect), 0);
    }

    rc = seccomp_load(ctx);
    if (rc < 0) {
        fprintf(stderr, "seccomp_load failed: %d\n", rc);
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cmd> [args...]\n", argv[0]);
        return 1;
    }

    if (apply_seccomp_filter(0, 0, 0) != 0) {
        fprintf(stderr, "Failed to apply seccomp filter\n");
        return 1;
    }

    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
