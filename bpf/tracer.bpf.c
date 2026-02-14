// SPDX-License-Identifier: GPL-2.0
// Azazel: Linux Runtime Security and Forensics using eBPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 256
#define MAX_COMM_LEN 16
#define RING_BUF_SIZE (1 << 24) // 16MB

// Event type constants — must match Go side
#define EVENT_PROCESS_EXEC   1
#define EVENT_PROCESS_EXIT   2
#define EVENT_FILE_OPEN      3
#define EVENT_FILE_WRITE     4
#define EVENT_FILE_READ      5
#define EVENT_FILE_UNLINK    6
#define EVENT_NET_CONNECT    7
#define EVENT_NET_ACCEPT     8
#define EVENT_NET_BIND       9
#define EVENT_NET_SENDTO     10
#define EVENT_NET_RECVFROM   11
#define EVENT_NET_DNS        12
#define EVENT_SYSCALL_GENERIC 13
#define EVENT_PROCESS_CLONE  14
#define EVENT_FILE_RENAME    15
#define EVENT_NET_LISTEN     16
#define EVENT_MMAP_EXEC      17
#define EVENT_PTRACE         18
#define EVENT_MODULE_LOAD    19

// Config array indices
#define CONFIG_FILTER_ENABLED 0
#define CONFIG_SELF_PID       1

// Common event header — present in every event
struct event_header {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 ppid;
    __u32 event_type;
    __u64 cgroup_id;
    char comm[MAX_COMM_LEN];
};

// Per-event structs
struct process_exec_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
};

struct process_exit_event {
    struct event_header hdr;
    __s32 exit_code;
    __u32 _pad;
};

struct file_open_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
    __s32 flags;
    __u32 _pad;
};

struct file_write_event {
    struct event_header hdr;
    __u32 fd;
    __u64 count;
    __u32 _pad;
};

struct file_read_event {
    struct event_header hdr;
    __u32 fd;
    __u64 count;
    __u32 _pad;
};

struct file_unlink_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
};

struct net_connect_event {
    struct event_header hdr;
    __u16 sa_family;
    __u16 dst_port;
    __u32 dst_addr4;
    __u8 dst_addr6[16];
    __u32 _pad;
};

struct net_accept_event {
    struct event_header hdr;
};

struct net_bind_event {
    struct event_header hdr;
    __u16 sa_family;
    __u16 port;
    __u32 addr4;
    __u8 addr6[16];
    __u32 _pad;
};

struct net_sendto_event {
    struct event_header hdr;
    __u16 sa_family;
    __u16 dst_port;
    __u32 dst_addr4;
    __u8 dst_addr6[16];
    __u32 _pad;
};

struct net_dns_event {
    struct event_header hdr;
    __u32 server_addr4;
    __u16 server_port;
    __u16 _pad;
};

struct process_clone_event {
    struct event_header hdr;
    __u64 clone_flags;
};

struct file_rename_event {
    struct event_header hdr;
    char oldname[MAX_FILENAME_LEN];
};

struct net_listen_event {
    struct event_header hdr;
    __s32 backlog;
    __u32 _pad;
};

struct mmap_exec_event {
    struct event_header hdr;
    __u64 addr;
    __u64 len;
    __u32 prot;
    __u32 flags;
};

struct ptrace_event {
    struct event_header hdr;
    __u32 request;
    __u32 target_pid;
};

struct module_load_event {
    struct event_header hdr;
    __s32 fd;
    __s32 flags;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUF_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} tracer_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} container_filter SEC(".maps");

// Helpers

static __always_inline int should_trace(void) {
    // Filter out events from the tracer itself to prevent feedback loops
    __u32 self_key = CONFIG_SELF_PID;
    __u64 *self_pid = bpf_map_lookup_elem(&tracer_config, &self_key);
    if (self_pid && *self_pid != 0) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        if (tgid == (__u32)*self_pid)
            return 0;
    }

    __u32 key = CONFIG_FILTER_ENABLED;
    __u64 *val = bpf_map_lookup_elem(&tracer_config, &key);
    if (!val || *val == 0)
        return 1; // no filter, trace everything

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *allowed = bpf_map_lookup_elem(&container_filter, &cgroup_id);
    return allowed != NULL;
}

static __always_inline void fill_header(struct event_header *hdr, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->tgid = (__u32)(pid_tgid >> 32);
    hdr->pid = (__u32)pid_tgid;
    hdr->uid = (__u32)uid_gid;
    hdr->gid = (__u32)(uid_gid >> 32);
    hdr->event_type = event_type;
    hdr->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));

    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        BPF_CORE_READ_INTO(&parent, task, real_parent);
        if (parent) {
            BPF_CORE_READ_INTO(&hdr->ppid, parent, tgid);
        }
    }
}

// Tracepoint context helpers for syscall arguments
// sys_enter tracepoints provide args via ctx->args[N]

// ============================================================
// Process events
// ============================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct process_exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_PROCESS_EXEC);

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

    // Read first argument (argv[0])
    const char **argv = (const char **)ctx->args[1];
    if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
        if (arg0) {
            bpf_probe_read_user_str(e->args, sizeof(e->args), arg0);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    if (!should_trace())
        return 0;

    struct process_exit_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_PROCESS_EXIT);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        BPF_CORE_READ_INTO(&e->exit_code, task, exit_code);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct process_clone_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_PROCESS_CLONE);
    e->clone_flags = ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// File events
// ============================================================

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct file_open_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_FILE_OPEN);

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);
    e->flags = (__s32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct file_write_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_FILE_WRITE);
    e->fd = (__u32)ctx->args[0];
    e->count = ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct file_read_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_FILE_READ);
    e->fd = (__u32)ctx->args[0];
    e->count = ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct file_unlink_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_FILE_UNLINK);

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct file_rename_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_FILE_RENAME);

    const char *oldname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->oldname, sizeof(e->oldname), oldname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// Network events
// ============================================================

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr)
        return 0;

    __u16 sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family != 2 /* AF_INET */ && sa_family != 10 /* AF_INET6 */)
        return 0;

    struct net_connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_CONNECT);
    e->sa_family = sa_family;

    if (sa_family == 2) { // AF_INET
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        e->dst_port = __builtin_bswap16(sin.sin_port);
        e->dst_addr4 = sin.sin_addr.s_addr;
    } else if (sa_family == 10) { // AF_INET6
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), addr);
        e->dst_port = __builtin_bswap16(sin6.sin6_port);
        __builtin_memcpy(e->dst_addr6, &sin6.sin6_addr, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct net_accept_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_ACCEPT);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr)
        return 0;

    __u16 sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family != 2 && sa_family != 10)
        return 0;

    struct net_bind_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_BIND);
    e->sa_family = sa_family;

    if (sa_family == 2) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        e->port = __builtin_bswap16(sin.sin_port);
        e->addr4 = sin.sin_addr.s_addr;
    } else if (sa_family == 10) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), addr);
        e->port = __builtin_bswap16(sin6.sin6_port);
        __builtin_memcpy(e->addr6, &sin6.sin6_addr, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct net_listen_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_LISTEN);
    e->backlog = (__s32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct sockaddr *addr = (struct sockaddr *)ctx->args[4];
    if (!addr)
        return 0;

    __u16 sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family != 2 && sa_family != 10)
        return 0;

    struct net_sendto_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_SENDTO);
    e->sa_family = sa_family;

    if (sa_family == 2) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        e->dst_port = __builtin_bswap16(sin.sin_port);
        e->dst_addr4 = sin.sin_addr.s_addr;
    } else if (sa_family == 10) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), addr);
        e->dst_port = __builtin_bswap16(sin6.sin6_port);
        __builtin_memcpy(e->dst_addr6, &sin6.sin6_addr, 16);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// DNS detection via kprobe on udp_sendmsg
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    if (!sk)
        return 0;

    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    if (dport != 53)
        return 0;

    struct net_dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_NET_DNS);
    BPF_CORE_READ_INTO(&e->server_addr4, sk, __sk_common.skc_daddr);
    e->server_port = 53;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// Security events
// ============================================================

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    __u32 prot = (__u32)ctx->args[2];

    // Only capture if PROT_EXEC is set (bit 2)
    // PROT_WRITE = 0x2, PROT_EXEC = 0x4
    if (!(prot & 0x4))
        return 0;

    struct mmap_exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_MMAP_EXEC);
    e->addr = ctx->args[0];
    e->len = ctx->args[1];
    e->prot = prot;
    e->flags = (__u32)ctx->args[3];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct ptrace_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_PTRACE);
    e->request = (__u32)ctx->args[0];
    e->target_pid = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;

    struct module_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_header(&e->hdr, EVENT_MODULE_LOAD);
    e->fd = (__s32)ctx->args[0];
    e->flags = (__s32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
