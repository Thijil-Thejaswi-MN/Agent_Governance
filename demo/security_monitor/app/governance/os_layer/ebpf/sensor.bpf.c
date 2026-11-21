#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "sensor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Syscall numbers on x86_64 */
#define SYS_OPEN 2
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
#define SYS_SENDTO 44
#define SYS_SENDMSG 46
#define SYS_BIND 49
#define SYS_LISTEN 50
#define SYS_CLONE 56
#define SYS_FORK 57
#define SYS_VFORK 58
#define SYS_EXECVE 59
#define SYS_EXIT 60
#define SYS_RENAME 82
#define SYS_MKDIR 83
#define SYS_UNLINK 87
#define SYS_EXIT_GROUP 231
#define SYS_OPENAT 257
#define SYS_MKDIRAT 258
#define SYS_UNLINKAT 263
#define SYS_RENAMEAT 264
#define SYS_ACCEPT4 288
#define SYS_RENAMEAT2 316
#define SYS_EXECVEAT 322
#define SYS_CLONE3 435
#define SYS_OPENAT2 437

#define AT_FDCWD_VAL -100

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Monitored task cgroup IDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} task_cgroups SEC(".maps");

/* Active in-flight syscalls awaiting exit paired by thread id */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct ebpf_event);
} active_syscalls SEC(".maps");

/* Per-CPU scratch space to prepare event record within verifier stack budget */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ebpf_event);
} scratch_map SEC(".maps");

/* Per-CPU counter tracking ring buffer reserve drops */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

/* Discovery mode configuration: 0=enabled, 1=rate_limit, 2=dns_port */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} discovery_cfg SEC(".maps");

/* Per-cgroup rate limiting */
struct cgroup_rate_limit {
    __u64 window_start_ns;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct cgroup_rate_limit);
} cgroup_rates SEC(".maps");

/* Rate limited event drop counter */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rate_limited_events SEC(".maps");

/* Ring buffer delivering event records to user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events_rb SEC(".maps");

volatile const __u64 pidns_dev = 0;
volatile const __u64 pidns_ino = 0;

static __always_inline void record_drop(void) {
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&dropped_events, &key);
    if (cnt) {
        *cnt += 1;
    }
}

static __always_inline void bpf_fast_copy(void *dst, const void *src) {
    __u64 *d = (__u64 *)dst;
    const __u64 *s = (const __u64 *)src;
    #pragma unroll
    for (int i = 0; i < (int)(sizeof(struct ebpf_event) / sizeof(__u64)); i++) {
        d[i] = s[i];
    }
}

static __always_inline void bpf_fast_zero(void *dst) {
    volatile __u64 *d = (volatile __u64 *)dst;
    #pragma unroll
    for (int i = 0; i < (int)(sizeof(struct ebpf_event) / sizeof(__u64)); i++) {
        d[i] = 0;
    }
}

static __always_inline __u32 get_current_pid(void) {
    if (pidns_dev && pidns_ino) {
        struct bpf_pidns_info nsdata = {};
        if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &nsdata, sizeof(nsdata)) == 0) {
            if (nsdata.tgid != 0) {
                return nsdata.tgid;
            }
        }
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct pid *tpid = BPF_CORE_READ(task, thread_pid);
        if (tpid) {
            unsigned int level = BPF_CORE_READ(tpid, level);
            if (level < 32) {
                __u32 nr = BPF_CORE_READ(tpid, numbers[level].nr);
                if (nr != 0) {
                    return nr;
                }
            }
        }
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    return pid_tgid >> 32;
}

static __always_inline __u64 get_monitored_cgroup_id(void) {
    __u64 cgid = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&task_cgroups, &cgid)) {
        return cgid;
    }
    for (int lvl = 10; lvl >= 1; lvl--) {
        __u64 anc = bpf_get_current_ancestor_cgroup_id(lvl);
        if (anc && bpf_map_lookup_elem(&task_cgroups, &anc)) {
            return anc;
        }
    }
    return 0;
}

static __always_inline __u32 get_parent_pid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task) return 0;
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return 0;
    struct pid *tpid = BPF_CORE_READ(task, thread_pid);
    if (tpid) {
        unsigned int level = BPF_CORE_READ(tpid, level);
        if (level < 32) {
            struct pid *ppid_struct = BPF_CORE_READ(parent, thread_pid);
            if (ppid_struct) {
                unsigned int plevel = BPF_CORE_READ(ppid_struct, level);
                if (plevel >= level) {
                    __u32 pnr = BPF_CORE_READ(ppid_struct, numbers[level].nr);
                    if (pnr != 0) return pnr;
                }
            }
        }
    }
    return BPF_CORE_READ(parent, tgid);
}

static __always_inline void copy_str(char *dst, const char *src, __u32 max_len, __u8 *status) {
    long ret = bpf_probe_read_user_str(dst, max_len, src);
    if (ret < 0) {
        *status = TARGET_STATUS_UNREADABLE;
        dst[0] = '\0';
    } else if (ret >= (long)max_len) {
        *status = TARGET_STATUS_TRUNCATED;
    } else {
        *status = TARGET_STATUS_OK;
    }
}

SEC("raw_tp/sys_enter")
int BPF_PROG(raw_tp_sys_enter, struct pt_regs *regs, long id) {
    if (!regs) {
        return 0;
    }
    __u64 cgid = get_monitored_cgroup_id();
    __u8 is_disc = 0;

    if (!cgid) {
        /* Check if host-wide discovery mode is active */
        __u32 cfg_k = 0;
        __u32 *en = bpf_map_lookup_elem(&discovery_cfg, &cfg_k);
        if (!en || *en == 0) {
            return 0;
        }

        /* In discovery mode, only monitor execve/execveat, connect, and sendto/sendmsg */
        long s_nr = id;
        if (s_nr != SYS_EXECVE && s_nr != SYS_EXECVEAT &&
            s_nr != SYS_CONNECT &&
            s_nr != SYS_SENDTO && s_nr != SYS_SENDMSG) {
            return 0;
        }

        /* Check per-cgroup rate limit */
        __u64 curr_cgid = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();
        __u32 limit = 200;
        __u32 limit_k = 1;
        __u32 *limit_ptr = bpf_map_lookup_elem(&discovery_cfg, &limit_k);
        if (limit_ptr && *limit_ptr > 0) {
            limit = *limit_ptr;
        }

        struct cgroup_rate_limit *rl = bpf_map_lookup_elem(&cgroup_rates, &curr_cgid);
        if (!rl) {
            struct cgroup_rate_limit init_rl = {};
            init_rl.window_start_ns = now;
            init_rl.count = 1;
            bpf_map_update_elem(&cgroup_rates, &curr_cgid, &init_rl, BPF_ANY);
        } else {
            if (now - rl->window_start_ns >= 1000000000ULL) {
                rl->window_start_ns = now;
                rl->count = 1;
            } else {
                if (rl->count >= limit) {
                    __u32 rk = 0;
                    __u64 *rcnt = bpf_map_lookup_elem(&rate_limited_events, &rk);
                    if (rcnt) {
                        *rcnt += 1;
                    }
                    return 0;
                }
                rl->count += 1;
            }
        }

        cgid = curr_cgid;
        is_disc = 1;
    }

    long nr = id;
    unsigned long args[6];
    args[0] = (unsigned long)PT_REGS_PARM1_CORE_SYSCALL(regs);
    args[1] = (unsigned long)PT_REGS_PARM2_CORE_SYSCALL(regs);
    args[2] = (unsigned long)PT_REGS_PARM3_CORE_SYSCALL(regs);
    args[3] = (unsigned long)PT_REGS_PARM4_CORE_SYSCALL(regs);
    args[4] = (unsigned long)PT_REGS_PARM5_CORE_SYSCALL(regs);
    args[5] = (unsigned long)PT_REGS_PARM6_CORE_SYSCALL(regs);
    __u32 op = EBPF_OP_UNKNOWN;

    switch (nr) {
    case SYS_OPENAT:
    case SYS_OPENAT2:
    case SYS_OPEN:
        op = EBPF_OP_OPEN;
        break;
    case SYS_EXECVE:
    case SYS_EXECVEAT:
        op = EBPF_OP_EXEC;
        break;
    case SYS_CONNECT:
        op = EBPF_OP_CONNECT;
        break;
    case SYS_BIND:
        op = EBPF_OP_BIND;
        break;
    case SYS_LISTEN:
        op = EBPF_OP_LISTEN;
        break;
    case SYS_ACCEPT:
    case SYS_ACCEPT4:
        op = EBPF_OP_ACCEPT;
        break;
    case SYS_SENDTO:
    case SYS_SENDMSG:
        op = EBPF_OP_SEND;
        break;
    case SYS_UNLINK:
    case SYS_UNLINKAT:
        op = EBPF_OP_UNLINK;
        break;
    case SYS_RENAME:
    case SYS_RENAMEAT:
    case SYS_RENAMEAT2:
        op = EBPF_OP_RENAME;
        break;
    case SYS_MKDIR:
    case SYS_MKDIRAT:
        op = EBPF_OP_MKDIR;
        break;
    case SYS_CLONE:
    case SYS_CLONE3:
    case SYS_FORK:
    case SYS_VFORK:
        op = EBPF_OP_CLONE;
        break;
    case SYS_EXIT_GROUP:
    case SYS_EXIT:
        op = EBPF_OP_EXIT;
        break;
    default:
        return 0;
    }

    __u32 zero = 0;
    struct ebpf_event *ev = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!ev) {
        return 0;
    }

    bpf_fast_zero(ev);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->cgroup_id = cgid;
    ev->is_discovery = is_disc;
    ev->pid = get_current_pid();
    ev->tgid = (__u32)pid_tgid;
    ev->ppid = get_parent_pid();
    ev->syscall_nr = (__s32)nr;
    ev->op = op;
    ev->ts_ns = bpf_ktime_get_ns();
    ev->target_status = TARGET_STATUS_NONE;

    if (nr == SYS_OPENAT) {
        ev->dfd = (__s32)args[0];
        copy_str(ev->target, (const char *)args[1], TARGET_PATH_MAX, &ev->target_status);
        ev->flags = args[2];
        ev->aux = args[3];
        ev->has_target = 1;
    } else if (nr == SYS_OPENAT2) {
        ev->dfd = (__s32)args[0];
        copy_str(ev->target, (const char *)args[1], TARGET_PATH_MAX, &ev->target_status);
        __u64 how_flags = 0;
        bpf_probe_read_user(&how_flags, sizeof(how_flags), (void *)args[2]);
        ev->flags = how_flags;
        ev->has_target = 1;
    } else if (nr == SYS_OPEN) {
        ev->dfd = AT_FDCWD_VAL;
        copy_str(ev->target, (const char *)args[0], TARGET_PATH_MAX, &ev->target_status);
        ev->flags = args[1];
        ev->aux = args[2];
        ev->has_target = 1;
    } else if (nr == SYS_EXECVE) {
        ev->dfd = AT_FDCWD_VAL;
        copy_str(ev->target, (const char *)args[0], TARGET_PATH_MAX, &ev->target_status);
        ev->has_target = 1;
        if (is_disc) {
            void *argv_user = (void *)args[1];
            if (argv_user) {
                #pragma unroll
                for (int i = 0; i < ARGV_MAX_COUNT; i++) {
                    const char *arg_p = NULL;
                    long r = bpf_probe_read_user(&arg_p, sizeof(arg_p), (char **)argv_user + i);
                    if (r < 0 || !arg_p) {
                        break;
                    }
                    bpf_probe_read_user_str(ev->argv[i], ARGV_ITEM_MAX, arg_p);
                    ev->argv_count++;
                }
            }
        }
    } else if (nr == SYS_EXECVEAT) {
        ev->dfd = (__s32)args[0];
        copy_str(ev->target, (const char *)args[1], TARGET_PATH_MAX, &ev->target_status);
        ev->flags = args[4];
        ev->has_target = 1;
        if (is_disc) {
            void *argv_user = (void *)args[2];
            if (argv_user) {
                #pragma unroll
                for (int i = 0; i < ARGV_MAX_COUNT; i++) {
                    const char *arg_p = NULL;
                    long r = bpf_probe_read_user(&arg_p, sizeof(arg_p), (char **)argv_user + i);
                    if (r < 0 || !arg_p) {
                        break;
                    }
                    bpf_probe_read_user_str(ev->argv[i], ARGV_ITEM_MAX, arg_p);
                    ev->argv_count++;
                }
            }
        }
    } else if (nr == SYS_CONNECT || nr == SYS_BIND) {
        ev->dfd = (__s32)args[0];
        void *sock_ptr = (void *)args[1];
        __u32 sock_len = (__u32)args[2];
        if (sock_len > SOCK_ADDR_MAX) {
            sock_len = SOCK_ADDR_MAX;
        }
        if (sock_ptr && sock_len > 0) {
            bpf_probe_read_user(ev->sock_addr, sock_len, sock_ptr);
            ev->sock_len = sock_len;
            ev->has_sock = 1;
        }
    } else if (nr == SYS_LISTEN) {
        ev->dfd = (__s32)args[0];
        ev->flags = args[1];
    } else if (nr == SYS_ACCEPT || nr == SYS_ACCEPT4) {
        ev->dfd = (__s32)args[0];
        if (nr == SYS_ACCEPT4) {
            ev->flags = args[3];
        }
    } else if (nr == SYS_SENDTO) {
        ev->dfd = (__s32)args[0];
        void *dest_ptr = (void *)args[4];
        __u32 dest_len = (__u32)args[5];
        if (!dest_ptr || dest_len == 0) {
            return 0;
        }
        if (dest_len > SOCK_ADDR_MAX) {
            dest_len = SOCK_ADDR_MAX;
        }
        bpf_probe_read_user(ev->sock_addr, dest_len, dest_ptr);
        ev->sock_len = dest_len;
        ev->has_sock = 1;

        if (is_disc) {
            __u16 dport = 0;
            sa_family_t fam = 0;
            bpf_probe_read_user(&fam, sizeof(fam), dest_ptr);
            if (fam == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), dest_ptr);
                dport = __builtin_bswap16(sin.sin_port);
            } else if (fam == AF_INET6) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), dest_ptr);
                dport = __builtin_bswap16(sin6.sin6_port);
            }

            __u32 target_port = 53;
            __u32 pk = 2;
            __u32 *p_val = bpf_map_lookup_elem(&discovery_cfg, &pk);
            if (p_val && *p_val > 0) {
                target_port = *p_val;
            }

            if (dport != target_port) {
                return 0;
            }

            void *buf_ptr = (void *)args[1];
            size_t buf_len = (size_t)args[2];
            if (buf_ptr && buf_len > 0) {
                __u16 copy_len = buf_len > DNS_PAYLOAD_MAX ? DNS_PAYLOAD_MAX : (__u16)buf_len;
                bpf_probe_read_user(ev->dns_payload, copy_len, buf_ptr);
                ev->dns_payload_len = copy_len;
            }
        }
    } else if (nr == SYS_SENDMSG) {
        ev->dfd = (__s32)args[0];
        void *msg_ptr = (void *)args[1];
        if (!msg_ptr) {
            return 0;
        }
        void *name_ptr = NULL;
        int name_len = 0;
        bpf_probe_read_user(&name_ptr, sizeof(name_ptr), msg_ptr);
        bpf_probe_read_user(&name_len, sizeof(name_len), (char *)msg_ptr + sizeof(void *));
        if (!name_ptr || name_len <= 0) {
            return 0;
        }
        __u32 rlen = (__u32)name_len;
        if (rlen > SOCK_ADDR_MAX) {
            rlen = SOCK_ADDR_MAX;
        }
        bpf_probe_read_user(ev->sock_addr, rlen, name_ptr);
        ev->sock_len = rlen;
        ev->has_sock = 1;

        if (is_disc) {
            __u16 dport = 0;
            sa_family_t fam = 0;
            bpf_probe_read_user(&fam, sizeof(fam), name_ptr);
            if (fam == AF_INET) {
                struct sockaddr_in sin = {};
                bpf_probe_read_user(&sin, sizeof(sin), name_ptr);
                dport = __builtin_bswap16(sin.sin_port);
            } else if (fam == AF_INET6) {
                struct sockaddr_in6 sin6 = {};
                bpf_probe_read_user(&sin6, sizeof(sin6), name_ptr);
                dport = __builtin_bswap16(sin6.sin6_port);
            }

            __u32 target_port = 53;
            __u32 pk = 2;
            __u32 *p_val = bpf_map_lookup_elem(&discovery_cfg, &pk);
            if (p_val && *p_val > 0) {
                target_port = *p_val;
            }

            if (dport != target_port) {
                return 0;
            }

            struct iovec *iov = NULL;
            size_t iovlen = 0;
            bpf_probe_read_user(&iov, sizeof(iov), (char *)msg_ptr + 16);
            bpf_probe_read_user(&iovlen, sizeof(iovlen), (char *)msg_ptr + 16 + sizeof(void *));
            if (iov && iovlen > 0) {
                void *iov_base = NULL;
                size_t iov_len = 0;
                bpf_probe_read_user(&iov_base, sizeof(iov_base), iov);
                bpf_probe_read_user(&iov_len, sizeof(iov_len), (char *)iov + sizeof(void *));
                if (iov_base && iov_len > 0) {
                    __u16 copy_len = iov_len > DNS_PAYLOAD_MAX ? DNS_PAYLOAD_MAX : (__u16)iov_len;
                    bpf_probe_read_user(ev->dns_payload, copy_len, iov_base);
                    ev->dns_payload_len = copy_len;
                }
            }
        }
    } else if (nr == SYS_UNLINKAT) {
        ev->dfd = (__s32)args[0];
        copy_str(ev->target, (const char *)args[1], TARGET_PATH_MAX, &ev->target_status);
        ev->flags = args[2];
        ev->has_target = 1;
    } else if (nr == SYS_UNLINK) {
        ev->dfd = AT_FDCWD_VAL;
        copy_str(ev->target, (const char *)args[0], TARGET_PATH_MAX, &ev->target_status);
        ev->has_target = 1;
    } else if (nr == SYS_RENAMEAT2 || nr == SYS_RENAMEAT) {
        ev->dfd = (__s32)args[0];
        copy_str(ev->target, (const char *)args[1], TARGET_PATH_MAX, &ev->target_status);
        ev->dfd2 = (__s32)args[2];
        __u8 status2 = TARGET_STATUS_NONE;
        copy_str(ev->target2, (const char *)args[3], TARGET_PATH_MAX, &status2);
        if (nr == SYS_RENAMEAT2) {
            ev->flags = args[4];
        }
        ev->has_target = 1;
        ev->has_target2 = 1;
    } else if (nr == SYS_RENAME) {
        ev->dfd = AT_FDCWD_VAL;
        copy_str(ev->target, (const char *)args[0], TARGET_PATH_MAX, &ev->target_status);
        ev->dfd2 = AT_FDCWD_VAL;
        __u8 status2 = TARGET_STATUS_NONE;
        copy_str(ev->target2, (const char *)args[1], TARGET_PATH_MAX, &status2);
        ev->has_target = 1;
        ev->has_target2 = 1;
    } else if (nr == SYS_MKDIRAT) {
        ev->dfd = (__s32)args[0];
        copy_str(ev->target, (const char *)args[1], TARGET_PATH_MAX, &ev->target_status);
        ev->flags = args[2];
        ev->has_target = 1;
    } else if (nr == SYS_MKDIR) {
        ev->dfd = AT_FDCWD_VAL;
        copy_str(ev->target, (const char *)args[0], TARGET_PATH_MAX, &ev->target_status);
        ev->flags = args[1];
        ev->has_target = 1;
    } else if (nr == SYS_CLONE || nr == SYS_CLONE3 || nr == SYS_FORK || nr == SYS_VFORK) {
        ev->flags = args[0];
    } else if (nr == SYS_EXIT_GROUP || nr == SYS_EXIT) {
        ev->ret = args[0];
        struct ebpf_event *out = bpf_ringbuf_reserve(&events_rb, sizeof(*out), 0);
        if (!out) {
            record_drop();
            return 0;
        }
        bpf_fast_copy(out, ev);
        bpf_ringbuf_submit(out, 0);
        return 0;
    }

    bpf_map_update_elem(&active_syscalls, &pid_tgid, ev, BPF_ANY);
    return 0;
}

SEC("raw_tp/sys_exit")
int BPF_PROG(raw_tp_sys_exit, struct pt_regs *regs, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ebpf_event *pending = bpf_map_lookup_elem(&active_syscalls, &pid_tgid);
    if (!pending) {
        return 0;
    }

    struct ebpf_event *out = bpf_ringbuf_reserve(&events_rb, sizeof(*out), 0);
    if (!out) {
        record_drop();
        bpf_map_delete_elem(&active_syscalls, &pid_tgid);
        return 0;
    }

    bpf_fast_copy(out, pending);
    out->ret = ret;
    bpf_ringbuf_submit(out, 0);

    bpf_map_delete_elem(&active_syscalls, &pid_tgid);
    return 0;
}
