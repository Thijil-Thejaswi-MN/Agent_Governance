/*
 * Landlock Task Sandbox Enforcer (C Implementation)
 *
 * Usage:
 *   landlock_enforcer --workspace /path/to/ws [--proxy-port 8080] -- cmd arg1 arg2 ...
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv) {
    const char *workspace = NULL;
    int proxy_port = 0;
    int cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--workspace") == 0 && i + 1 < argc) {
            workspace = argv[++i];
        } else if (strcmp(argv[i], "--proxy-port") == 0 && i + 1 < argc) {
            proxy_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        }
    }

    if (!workspace || cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "Usage: %s --workspace <path> [--proxy-port <port>] -- <cmd> [args...]\n", argv[0]);
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

    /* 5. Scratch & tmp directory */
    char scratch_path[4096];
    snprintf(scratch_path, sizeof(scratch_path), "%s/scratch", workspace);
    add_path_rule(ruleset_fd, scratch_path, rw);
    add_path_rule(ruleset_fd, "/tmp", rw);

    /* 6. Port rule for egress proxy */
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
