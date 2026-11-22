#ifndef __SENSOR_H__
#define __SENSOR_H__

#define TARGET_PATH_MAX 256
#define SOCK_ADDR_MAX 128
#define ARGV_MAX_COUNT 4
#define ARGV_ITEM_MAX 128
#define DNS_PAYLOAD_MAX 256

#define RUNTIME_PREFIX_MAX 64
#define MAX_RUNTIME_PREFIXES 16

struct prefix_entry {
    __u32 len;
    char prefix[RUNTIME_PREFIX_MAX];
};

enum {
    TARGET_STATUS_OK = 0,
    TARGET_STATUS_TRUNCATED = 1,
    TARGET_STATUS_UNREADABLE = 2,
    TARGET_STATUS_NONE = 3,
};

enum ebpf_syscall_op {
    EBPF_OP_UNKNOWN = 0,
    EBPF_OP_OPEN = 1,
    EBPF_OP_EXEC = 2,
    EBPF_OP_CONNECT = 3,
    EBPF_OP_BIND = 4,
    EBPF_OP_LISTEN = 5,
    EBPF_OP_ACCEPT = 6,
    EBPF_OP_SEND = 7,
    EBPF_OP_UNLINK = 8,
    EBPF_OP_RENAME = 9,
    EBPF_OP_MKDIR = 10,
    EBPF_OP_CLONE = 11,
    EBPF_OP_EXIT = 12,
};

struct ebpf_event {
    __u64 seq;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __s32 syscall_nr;
    __u32 op;
    __s64 ret;
    __s32 dfd;
    __s32 dfd2;
    __u64 flags;
    __u64 aux;
    __u8 has_target;
    __u8 target_status;
    __u8 has_target2;
    __u8 has_sock;
    __u32 sock_len;
    char target[TARGET_PATH_MAX];
    char target2[TARGET_PATH_MAX];
    char sock_addr[SOCK_ADDR_MAX];

    /* Discovery Mode additions */
    __u8 is_discovery;
    __u8 argv_count;
    char argv[ARGV_MAX_COUNT][ARGV_ITEM_MAX];
    __u16 dns_payload_len;
    char dns_payload[DNS_PAYLOAD_MAX];
    __u16 _pad;
};

#endif /* __SENSOR_H__ */
