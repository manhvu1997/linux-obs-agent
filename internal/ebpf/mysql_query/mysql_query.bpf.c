//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// mysql_query.bpf.c – MySQL slow-query latency tracer (server-side).
//
// Design goals (production):
//   - Always-on, bounded memory: LRU map auto-evicts least-recently-used PIDs.
//   - Trace the MySQL SERVER, not the client: attach uprobes to dispatch_command
//     inside the running mysqld binary.
//   - Measure every command; COM_QUERY also feeds the legacy per-PID stats
//     and slow events. Per command: wall time, on-CPU time, run-queue wait and
//     result bytes, emitted once on the cmd_events ring buffer. With
//     emit_all_queries == 0 only COM_QUERY is tracked (legacy behaviour).
//   - Read the SQL query text directly from the COM_DATA argument at function
//     entry — no wire-protocol parsing required, works with TLS connections.
//   - Filter early (in kernel) to reduce overhead: only emit ringbuf events when
//     latency exceeds slow_query_threshold_ns.
//
// Hooks attached (uprobes on mysqld binary):
//   uprobe/dispatch_command   – record start time + query text at entry
//   uretprobe/dispatch_command – compute latency, update LRU stats, emit if slow
//
// Hooks attached (kretprobes, optional):
//   kretprobe/tcp_sendmsg, kretprobe/unix_stream_sendmsg – result bytes sent
//     by a thread while it is inside dispatch_command
//
// MySQL dispatch_command signature (MySQL 5.7+ / 8.0, x86-64 SysV ABI):
//   bool dispatch_command(THD *thd, const COM_DATA *com_data,
//                         enum_server_command command)
//   RDI = thd  |  RSI = com_data  |  RDX = command
//
// COM_DATA union for COM_QUERY (command == 3):
//   struct COM_QUERY_DATA {
//     const char *query_str;  // com_data[0..7]  – pointer to SQL text
//     unsigned int length;    // com_data[8..11] – byte length of SQL text
//                             // (4 bytes; 4 bytes of padding follow, may be
//                             // stack garbage – never read them)
//     ...
//   };
//   Since COM_QUERY_DATA is at the start of the COM_DATA union, offset 0 always
//   gives the query_str pointer regardless of which union member is active.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * x86-64 SysV ABI register save frame used by uprobes.
 *
 * Defined locally to avoid depending on vmlinux.h's struct pt_regs, which
 * is generated from the *running* kernel's BTF.  On ARM64 hosts (e.g. macOS
 * Apple Silicon running Docker), vmlinux.h contains the ARM64 pt_regs layout
 * and has no x86-64 register field names (rdx, rsi, rdi, …).
 *
 * Casting ctx to struct x86_regs * is safe: for uprobe programs the kernel
 * always passes an x86-64 register save area regardless of where bpf2go is
 * run from.  The BPF verifier treats the cast as reading at fixed offsets
 * from the ctx pointer, which is permitted for kprobe/uprobe programs.
 *
 * Layout matches arch/x86/include/asm/ptrace.h (pt_regs, kernel push order):
 *   PUSH r15, r14, r13, r12, rbp, rbx → callee-saved
 *   PUSH r11, r10, r9, r8             → caller-saved (scratch)
 *   PUSH rax, rcx, rdx, rsi, rdi     → arg regs + rax
 * (orig_rax, rip, cs, eflags, rsp, ss follow but are not needed here)
 */
struct x86_regs {
    __u64 r15, r14, r13, r12, rbp, rbx;
    __u64 r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi;
};

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN    16
#define QUERY_MAX       512   /* must equal cmdmap.QueryMax in Go            */
#define MAX_ENTRIES     8192  /* in-flight commands ≤ mysqld worker threads   */
#define MAX_PID_ENTRIES 10240
#define COM_QUERY 3

// ─── Value structs ────────────────────────────────────────────────────────────

/* In-flight command state, keyed by TID. 576 bytes: built in pending_scratch
 * because it does not fit the 512-byte BPF stack. */
struct mysql_pending_t {
    __u64 start_ts;
    __u64 cpu_start;   /* task->se.sum_exec_runtime at entry  */
    __u64 rq_start;    /* task->sched_info.run_delay at entry */
    __u64 bytes_in;    /* COM_QUERY length (u32 in mysqld)    */
    __u64 bytes_out;   /* tcp/unix sendmsg bytes during call   */
    __u32 command;
    __u32 query_len;
    __u8  query[QUERY_MAX];
    __u8  comm[TASK_COMM_LEN];
};
_Static_assert(sizeof(struct mysql_pending_t) == 576, "pending layout");

struct mysql_pid_stats_t {
    __u64 total_queries;
    __u64 slow_queries;
    __u64 total_latency_ns;
    __u64 max_latency_ns;
    __u64 last_seen_ts;
    __u8  comm[TASK_COMM_LEN];
};
struct mysql_pid_stats_t *__mysql_pid_stats_t_unused __attribute__((unused));

struct mysql_slow_event_t {
    __u32 pid;
    __u32 tid;
    __u64 latency_ns;
    __u64 timestamp_ns;
    __u8  comm[TASK_COMM_LEN];
    __u8  query[QUERY_MAX];
};
struct mysql_slow_event_t *__mysql_slow_event_t_unused __attribute__((unused));

/* One record per dispatch_command call. Layout is decoded by hand in
 * loader.go (decodeCmdEvent) — keep offsets in sync: 584 bytes, no padding. */
struct mysql_cmd_event_t {
    __u32 pid;          /*   0 */
    __u32 tid;          /*   4 */
    __u32 command;      /*   8 */
    __u32 query_len;    /*  12 */
    __u64 wall_ns;      /*  16 */
    __u64 cpu_ns;       /*  24 */
    __u64 runq_ns;      /*  32 */
    __u64 bytes_in;     /*  40 */
    __u64 bytes_out;    /*  48 */
    __u8  comm[TASK_COMM_LEN];  /* 56 */
    __u8  query[QUERY_MAX];     /* 72 */
};
_Static_assert(sizeof(struct mysql_cmd_event_t) == 584, "cmd event layout");
/* Force BTF emission for bpf2go -type. */
struct mysql_cmd_event_t *__mysql_cmd_event_t_unused __attribute__((unused));

// ─── Maps ─────────────────────────────────────────────────────────────────────

/* In-flight commands keyed by TID; always deleted in the uretprobe. LRU so
 * entries of threads that never returned (killed thread, crashed mysqld)
 * are reclaimed instead of filling the map. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct mysql_pending_t);
    __uint(max_entries, MAX_ENTRIES);
} mysql_pending SEC(".maps");

/* Per-CPU scratch slot: mysql_pending_t (576 B) exceeds the 512-B stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct mysql_pending_t);
    __uint(max_entries, 1);
} pending_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct mysql_pid_stats_t);
    __uint(max_entries, MAX_PID_ENTRIES);
} mysql_pid_stats SEC(".maps");

/* Slow-query outliers (unchanged consumer). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

/* Every command: < 20k QPS × 584 B ≈ 12 MB/s; 4 MB absorbs ~7k-event bursts. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MB */
} cmd_events SEC(".maps");

/* cmd_events reservations that failed (ring buffer full), per CPU. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} dropped SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

const volatile __u64 slow_query_threshold_ns = 100000000ULL;
/* 1: emit cmd_events for every command. 0: legacy COM_QUERY-only behaviour. */
const volatile __u8 emit_all_queries = 1;

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u64 task_cpu_ns(struct task_struct *t)
{
    return BPF_CORE_READ(t, se.sum_exec_runtime);
}

/* sched_info exists only with CONFIG_SCHED_INFO; report 0 otherwise and let
 * userspace detect "run_delay_unavailable". */
static __always_inline __u64 task_runq_ns(struct task_struct *t)
{
    if (bpf_core_field_exists(t->sched_info.run_delay))
        return BPF_CORE_READ(t, sched_info.run_delay);
    return 0;
}

// ─── Programs ─────────────────────────────────────────────────────────────────

/*
 * Entry: x86-64 SysV ABI, dispatch_command(THD *thd, const COM_DATA *com_data,
 * enum_server_command command): RSI = com_data, RDX = command. See the
 * struct x86_regs comment for why ctx is cast instead of PT_REGS_PARM*.
 */
SEC("uprobe/dispatch_command")
int uprobe_dispatch_command(struct pt_regs *ctx)
{
    struct x86_regs *regs = (struct x86_regs *)ctx;
    __u32 command = (__u32)regs->rdx;
    if (!emit_all_queries && command != COM_QUERY)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct mysql_pending_t *p = bpf_map_lookup_elem(&pending_scratch, &zero);
    if (!p)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    p->start_ts  = bpf_ktime_get_ns();
    p->cpu_start = task_cpu_ns(task);
    p->rq_start  = task_runq_ns(task);
    p->bytes_in  = 0;
    p->bytes_out = 0;
    p->command   = command;
    p->query_len = 0;
    p->query[0]  = 0;
    bpf_get_current_comm(&p->comm, sizeof(p->comm));

    /* COM_DATA for COM_QUERY (MySQL 5.7 st_com_query_data / 8.0 COM_QUERY_DATA):
     * offset 0 = const char *query, offset 8 = unsigned int length (4 bytes;
     * 4 bytes of padding follow and may be stack garbage, so read only 4). */
    void *com_data = (void *)regs->rsi;
    if (command == COM_QUERY && com_data) {
        const char *query_str = NULL;
        __u32 len = 0;
        if (bpf_probe_read_user(&query_str, sizeof(query_str), com_data) == 0 && query_str)
            bpf_probe_read_user_str(p->query, sizeof(p->query), query_str);
        if (bpf_probe_read_user(&len, sizeof(len), (char *)com_data + 8) == 0) {
            p->bytes_in  = len;
            p->query_len = len;
        }
    }
    /* Copies the scratch value (map-value pointer) into the per-TID entry. */
    bpf_map_update_elem(&mysql_pending, &tid, p, BPF_ANY);
    return 0;
}

/* Result bytes: add the int return of the protocol sendmsg while the calling
 * thread is inside dispatch_command. Hooked at tcp/unix level, not
 * sock_sendmsg, because since 6.6 send()/write() reach the protocol through
 * the static, inlinable __sock_sendmsg. */
static __always_inline int add_bytes_out(struct pt_regs *ctx)
{
    int ret = (int)((struct x86_regs *)ctx)->rax;
    if (ret <= 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (p)
        __sync_fetch_and_add(&p->bytes_out, (__u64)ret);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx) { return add_bytes_out(ctx); }

SEC("kretprobe/unix_stream_sendmsg")
int kretprobe_unix_stream_sendmsg(struct pt_regs *ctx) { return add_bytes_out(ctx); }

/*
 * Return: everything is read through the mysql_pending map-value pointer (no
 * 576-byte local); the entry is deleted on every path after a successful lookup.
 */
SEC("uretprobe/dispatch_command")
int uretprobe_dispatch_command(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid  = (__u32)pid_tgid;

    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!p)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - p->start_ts;
    __u64 cpu_now = task_cpu_ns(task), rq_now = task_runq_ns(task);
    __u64 cpu_ns  = cpu_now > p->cpu_start ? cpu_now - p->cpu_start : 0;
    __u64 runq_ns = rq_now > p->rq_start ? rq_now - p->rq_start : 0;
    /* sum_exec_runtime is tick-granular: keep cpu, runq <= wall. */
    if (cpu_ns > latency_ns)
        cpu_ns = latency_ns;
    if (runq_ns > latency_ns)
        runq_ns = latency_ns;

    if (p->command == COM_QUERY) {
        struct mysql_pid_stats_t *stats = bpf_map_lookup_elem(&mysql_pid_stats, &tgid);
        if (stats) {
            __sync_fetch_and_add(&stats->total_queries, 1);
            __sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
            if (latency_ns > stats->max_latency_ns)
                stats->max_latency_ns = latency_ns;
            if (latency_ns >= slow_query_threshold_ns)
                __sync_fetch_and_add(&stats->slow_queries, 1);
            stats->last_seen_ts = now;
            bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
        } else {
            struct mysql_pid_stats_t ns;
            __builtin_memset(&ns, 0, sizeof(ns));
            ns.total_queries    = 1;
            ns.total_latency_ns = latency_ns;
            ns.max_latency_ns   = latency_ns;
            ns.slow_queries     = latency_ns >= slow_query_threshold_ns ? 1 : 0;
            ns.last_seen_ts     = now;
            bpf_get_current_comm(&ns.comm, sizeof(ns.comm));
            bpf_map_update_elem(&mysql_pid_stats, &tgid, &ns, BPF_NOEXIST);
        }
        if (latency_ns >= slow_query_threshold_ns) {
            struct mysql_slow_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
            if (ev) {
                ev->pid = tgid;
                ev->tid = tid;
                ev->latency_ns = latency_ns;
                ev->timestamp_ns = now;
                __builtin_memcpy(ev->comm, p->comm, sizeof(ev->comm));
                __builtin_memcpy(ev->query, p->query, sizeof(ev->query));
                bpf_ringbuf_submit(ev, 0);
            }
        }
    }

    if (emit_all_queries) {
        struct mysql_cmd_event_t *ev = bpf_ringbuf_reserve(&cmd_events, sizeof(*ev), 0);
        if (ev) {
            ev->pid       = tgid;
            ev->tid       = tid;
            ev->command   = p->command;
            ev->query_len = p->query_len;
            ev->wall_ns   = latency_ns;
            ev->cpu_ns    = cpu_ns;
            ev->runq_ns   = runq_ns;
            ev->bytes_in  = p->bytes_in;
            ev->bytes_out = p->bytes_out;
            __builtin_memcpy(ev->comm, p->comm, sizeof(ev->comm));
            __builtin_memcpy(ev->query, p->query, sizeof(ev->query));
            bpf_ringbuf_submit(ev, 0);
        } else {
            __u32 zero = 0;
            __u64 *d = bpf_map_lookup_elem(&dropped, &zero);
            if (d)
                *d += 1; /* per-CPU slot: no atomic needed */
        }
    }

    bpf_map_delete_elem(&mysql_pending, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
