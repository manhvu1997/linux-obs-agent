//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// mysql_query.bpf.c – MySQL slow-query latency tracer (server-side).
//
// Design goals (production):
//   - Always-on, bounded memory: LRU map auto-evicts least-recently-used PIDs.
//   - Trace the MySQL SERVER, not the client: attach uprobes to dispatch_command
//     inside the running mysqld binary.
//   - Only intercept COM_QUERY commands (command type 3) – skip all internal
//     MySQL commands (ping, statistics, quit, etc.) that are not user queries.
//   - Read the SQL query text directly from the COM_DATA argument at function
//     entry — no wire-protocol parsing required, works with TLS connections.
//   - Filter early (in kernel) to reduce overhead: only emit ringbuf events when
//     latency exceeds slow_query_threshold_ns.
//
// Hooks attached (uprobes on mysqld binary):
//   uprobe/dispatch_command   – record start time + query text at entry
//   uretprobe/dispatch_command – compute latency, update LRU stats, emit if slow
//
// MySQL dispatch_command signature (MySQL 5.7+ / 8.0, x86-64 SysV ABI):
//   bool dispatch_command(THD *thd, const COM_DATA *com_data,
//                         enum_server_command command)
//   RDI = thd  |  RSI = com_data  |  RDX = command
//
// COM_DATA union for COM_QUERY (command == 3):
//   struct COM_QUERY_DATA {
//     const char *query_str;  // com_data[0..7]  – pointer to SQL text
//     size_t      length;     // com_data[8..15] – byte length of SQL text
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
#define QUERY_MAX       256   /* max SQL bytes captured (truncated if longer) */
#define MAX_ENTRIES   65536   /* in-flight pending entries                    */
#define MAX_PID_ENTRIES 10240 /* LRU per-PID stats (auto-evicts oldest)       */

/*
 * COM_QUERY = 3: the only command type that carries a user SQL statement.
 * All other commands (COM_PING, COM_QUIT, COM_STATISTICS, etc.) are skipped
 * at the uprobe entry to keep overhead near zero.
 */
#define COM_QUERY 3

// ─── Value structs ────────────────────────────────────────────────────────────

/*
 * mysql_pending_t: in-flight query state recorded at uprobe entry.
 * Keyed by kernel TID (one entry per active dispatch_command call).
 * Deleted in the matching uretprobe so the map stays bounded.
 */
struct mysql_pending_t {
    __u64 start_ts;               /* bpf_ktime_get_ns() at uprobe entry     */
    __u8  query[QUERY_MAX];       /* SQL text (NUL-terminated, may truncate) */
    __u8  comm[TASK_COMM_LEN];    /* mysqld thread comm name                 */
};

/*
 * mysql_pid_stats_t: per-PID aggregated query statistics stored in the LRU map.
 * Monotonically increasing counters updated atomically.
 * Exported via bpf2go -type for map iteration in userspace.
 */
struct mysql_pid_stats_t {
    __u64 total_queries;     /* all COM_QUERY calls observed on this PID       */
    __u64 slow_queries;      /* queries exceeding slow_query_threshold_ns      */
    __u64 total_latency_ns;  /* sum of all query latencies                     */
    __u64 max_latency_ns;    /* worst single-query latency                     */
    __u64 last_seen_ts;      /* bpf_ktime_get_ns() of last update              */
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct mysql_pid_stats_t *__mysql_pid_stats_t_unused __attribute__((unused));

/*
 * mysql_slow_event_t: ringbuf event emitted for each slow query.
 * Contains all information needed for a useful /api/diagnose entry.
 * Exported via bpf2go -type for binary.Read in userspace.
 */
struct mysql_slow_event_t {
    __u32 pid;                 /* userspace PID (thread-group leader)          */
    __u32 tid;                 /* kernel TID of the mysqld worker thread       */
    __u64 latency_ns;          /* query duration in nanoseconds                */
    __u64 timestamp_ns;        /* bpf_ktime_get_ns() at dispatch_command exit  */
    __u8  comm[TASK_COMM_LEN]; /* mysqld thread comm (always "mysqld")         */
    __u8  query[QUERY_MAX];    /* SQL text (NUL-terminated, may be truncated)  */
};

/* Force BTF emission for bpf2go -type. */
struct mysql_slow_event_t *__mysql_slow_event_t_unused __attribute__((unused));

// ─── Maps ─────────────────────────────────────────────────────────────────────

/*
 * mysql_pending: in-flight query state keyed by kernel TID.
 * Entries are created in the uprobe and always deleted in the uretprobe –
 * no stale growth even at high query rates.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);  /* kernel TID */
    __type(value, struct mysql_pending_t);
    __uint(max_entries, MAX_ENTRIES);
} mysql_pending SEC(".maps");

/*
 * mysql_pid_stats: per-PID aggregated stats.
 * LRU_HASH auto-evicts when full so memory is bounded regardless of PID churn.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);  /* tgid (userspace PID) */
    __type(value, struct mysql_pid_stats_t);
    __uint(max_entries, MAX_PID_ENTRIES);
} mysql_pid_stats SEC(".maps");

/*
 * events: ringbuf for slow-query outlier notifications.
 * 256 KB ≈ 1 000 events before consumer must drain.
 * Events are dropped (not blocking) when the buffer is full.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

/*
 * slow_query_threshold_ns: emit a ringbuf event only when a single query takes
 * longer than this duration (nanoseconds).  Default 100 000 000 ns = 100 ms.
 * Override from Go before loading: spec.Variables["slow_query_threshold_ns"].Set(v).
 */
const volatile __u64 slow_query_threshold_ns = 100000000ULL;

// ─── Uprobe programs ──────────────────────────────────────────────────────────

/*
 * uprobe_dispatch_command: fires at the entry of dispatch_command in mysqld.
 *
 * Reads the command type from RDX (third argument).  Only proceeds for
 * COM_QUERY (== 3) to avoid any overhead on internal MySQL commands.
 *
 * For COM_QUERY, reads the SQL text from the COM_DATA union:
 *   - com_data is RSI (second argument), a pointer to COM_DATA in userspace.
 *   - COM_DATA union offset 0 == COM_QUERY_DATA.query_str (a char * pointer).
 *   - bpf_probe_read_user_str copies the SQL into the pending map entry,
 *     NUL-terminates it, and silently truncates at QUERY_MAX bytes.
 *
 * Stack budget: pending(272) + comm/query inline into map = ~80 bytes total.
 */
SEC("uprobe/dispatch_command")
int uprobe_dispatch_command(struct pt_regs *ctx)
{
    /*
     * Cast ctx to struct x86_regs to read x86-64 argument registers.
     *
     * We cannot use PT_REGS_PARM* or PT_REGS_PARM*_CORE: both expand to
     * short aliases ("dx", "si") that only exist in the kernel-internal
     * definition of pt_regs, not in vmlinux.h.  We also cannot access
     * ctx->rdx / ctx->rsi directly when vmlinux.h was generated from an
     * ARM64 kernel (e.g. Docker on macOS Apple Silicon), because that
     * pt_regs has no such fields.
     *
     * struct x86_regs is defined locally (above) with the exact x86-64
     * push order, so the compiler resolves rdx/rsi without any vmlinux.h
     * dependency.
     *
     * x86-64 SysV ABI:   RDI=arg1  RSI=arg2  RDX=arg3
     * dispatch_command:  RDI=thd   RSI=com_data  RDX=command
     */
    struct x86_regs *regs = (struct x86_regs *)ctx;
    __u32 command = (__u32)regs->rdx;
    if (command != COM_QUERY)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid      = (__u32)(pid_tgid & 0xffffffffULL);

    struct mysql_pending_t pending;
    __builtin_memset(&pending, 0, sizeof(pending));
    pending.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&pending.comm, sizeof(pending.comm));

    /*
     * Second argument (RSI): const COM_DATA *com_data (userspace pointer).
     * COM_DATA union layout for COM_QUERY:
     *   offset 0: const char *query_str
     *   offset 8: size_t      length
     * Read the query_str pointer from userspace, then copy the SQL text.
     */
    void *com_data = (void *)regs->rsi;
    if (com_data) {
        const char *query_str = NULL;
        if (bpf_probe_read_user(&query_str, sizeof(query_str), com_data) == 0 &&
            query_str != NULL) {
            /*
             * bpf_probe_read_user_str: copies up to QUERY_MAX bytes from
             * userspace, stops at the first NUL, always NUL-terminates dst.
             * The return value is the number of bytes written (including NUL).
             * This is safe even if the SQL string is longer than QUERY_MAX.
             */
            bpf_probe_read_user_str(pending.query, sizeof(pending.query), query_str);
        }
    }

    bpf_map_update_elem(&mysql_pending, &tid, &pending, BPF_ANY);
    return 0;
}

/*
 * uretprobe_dispatch_command: fires at the return of dispatch_command in mysqld.
 *
 * Looks up the pending entry for this TID, computes latency, updates the
 * per-PID LRU stats, and emits a ringbuf event if latency exceeds the threshold.
 * The pending entry is deleted at the very end so its comm/query fields can be
 * referenced directly into the ringbuf-reserved memory — avoiding any local
 * copies on the BPF stack (which would consume ~272 bytes and overflow the 512B limit).
 *
 * Stack budget (this function):
 *   pid_tgid(8) + tgid(4) + tid(4) + now(8) + latency_ns(8)
 *   + pending ptr(8) + stats ptr(8) + new_stats(56) + ev ptr(8)
 *   ≈ 112 bytes — well under the 512-byte BPF limit.
 */
SEC("uretprobe/dispatch_command")
int uretprobe_dispatch_command(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)(pid_tgid & 0xffffffffULL);

    struct mysql_pending_t *pending = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!pending)
        return 0;

    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - pending->start_ts;

    /*
     * No local comm[]/query[] copies — pending->comm and pending->query are
     * read directly from map memory into the ringbuf-reserved slot below.
     * The delete is deferred to the very end so the pointer stays valid.
     */

    /* ── Update per-PID aggregated stats (LRU map) ─────────────────────────── */
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
        /*
         * new_stats is the only large stack object (56 bytes).
         * It is kept as small as possible — no padding fields.
         */
        struct mysql_pid_stats_t new_stats;
        __builtin_memset(&new_stats, 0, sizeof(new_stats));
        new_stats.total_queries    = 1;
        new_stats.total_latency_ns = latency_ns;
        new_stats.max_latency_ns   = latency_ns;
        new_stats.slow_queries     = (latency_ns >= slow_query_threshold_ns) ? 1 : 0;
        new_stats.last_seen_ts     = now;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        bpf_map_update_elem(&mysql_pid_stats, &tgid, &new_stats, BPF_NOEXIST);
    }

    /* ── Emit ringbuf slow event ────────────────────────────────────────────── */
    if (latency_ns >= slow_query_threshold_ns) {
        struct mysql_slow_event_t *ev =
            bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (ev) {
            ev->pid          = tgid;
            ev->tid          = tid;
            ev->latency_ns   = latency_ns;
            ev->timestamp_ns = now;
            /*
             * Copy comm/query directly from the pending map entry into the
             * ringbuf slot — no intermediate stack buffers needed.
             * pending is still valid here; delete happens below.
             */
            __builtin_memcpy(ev->comm,  pending->comm,  sizeof(ev->comm));
            __builtin_memcpy(ev->query, pending->query, sizeof(ev->query));
            bpf_ringbuf_submit(ev, 0);
        }
    }

    /* Always delete – prevents stale entries at any query rate. */
    bpf_map_delete_elem(&mysql_pending, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
