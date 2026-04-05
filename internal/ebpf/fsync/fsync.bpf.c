//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// fsync.bpf.c – per-PID fsync/fdatasync/sync_file_range latency aggregator.
//
// Design goals (production):
//   - No per-event userspace wakeup: aggregate in-kernel, poll every 5 s.
//   - LRU map bounds memory: entries evicted automatically when full.
//   - Three kprobe/kretprobe pairs share a single per-TID start map and a
//     single per-PID stats LRU map, keeping footprint minimal.
//   - Slow events (> slow_fsync_threshold_us) are emitted to a 256 KB ringbuf
//     for real-time detection of outliers; normal events update only the map.
//
// Hooks:
//   kprobe/__x64_sys_fsync
//   kretprobe/__x64_sys_fsync
//   kprobe/__x64_sys_fdatasync
//   kretprobe/__x64_sys_fdatasync
//   kprobe/__x64_sys_sync_file_range
//   kretprobe/__x64_sys_sync_file_range
//
// Requires kernel >= 4.x (kprobes).  No BTF dependency.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN   16
#define MAX_TID_ENTRIES 65536   /* in-flight syscall start timestamps        */
#define MAX_PID_ENTRIES 10240   /* LRU per-PID stats (auto-evicts oldest)    */

// ─── Structs ──────────────────────────────────────────────────────────────────

/* Per-PID aggregated fsync statistics (value of fsync_stats LRU map). */
struct fsync_pid_val {
    __u64 total_calls;
    __u64 total_latency_ns;
    __u64 max_latency_ns;
    __u64 last_seen_ts;
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct fsync_pid_val *__fsync_pid_val_unused __attribute__((unused));

/*
 * Slow-fsync ringbuf event (emitted only when latency > slow_fsync_threshold_us).
 * Userspace reads this for real-time outlier detection without polling.
 */
struct fsync_event {
    __u32 pid;
    __u32 tgid;
    __u64 latency_us;
    __u64 timestamp_ns;
    __u8  comm[TASK_COMM_LEN];
    __u8  syscall_nr; /* 0=fsync 1=fdatasync 2=sync_file_range */
};

/* Force BTF emission for bpf2go -type. */
struct fsync_event *__fsync_event_unused __attribute__((unused));

// ─── Maps ─────────────────────────────────────────────────────────────────────

/*
 * fsync_start: temporary per-TID entry timestamp.
 * Keyed by kernel TID (bpf_get_current_pid_tgid() & 0xffffffff).
 * Entries are always deleted in the kretprobe so no stale growth occurs.
 * Regular HASH (not LRU) because entries are transient – bounded by
 * MAX_TID_ENTRIES concurrent in-flight fsync syscalls.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);   /* tid */
    __type(value, __u64);   /* entry timestamp (ns) */
    __uint(max_entries, MAX_TID_ENTRIES);
} fsync_start SEC(".maps");

/*
 * fsync_stats: per-PID aggregated statistics.
 * LRU_HASH automatically evicts the least-recently-used entry when full,
 * giving bounded memory while retaining the hottest PIDs.
 * Keyed by TGID (userspace PID).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);               /* tgid / userspace PID */
    __type(value, struct fsync_pid_val);
    __uint(max_entries, MAX_PID_ENTRIES);
} fsync_stats SEC(".maps");

/*
 * events: ringbuf for slow-fsync notifications.
 * 256 KB is sufficient for ~1600 events before consumer must drain.
 * Events are discarded (not blocking) if the buffer is full.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

/* Emit a ringbuf event only when fsync latency exceeds this (microseconds).
 * Default 5 ms – reduces event noise at 10k+ fsync/s workloads.
 * Override from Go before loading: spec.Variables["slow_fsync_threshold_us"].Set(v). */
const volatile __u64 slow_fsync_threshold_us = 5000;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/*
 * record_entry: called on every kprobe (syscall entry).
 * Stores the current monotonic timestamp keyed by TID.
 */
static __always_inline void record_entry(void)
{
    __u32 tid = (__u32)(bpf_get_current_pid_tgid() & 0xffffffffULL);
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&fsync_start, &tid, &ts, BPF_ANY);
}

/*
 * record_exit: called on every kretprobe (syscall return).
 *
 * 1. Looks up and deletes the start timestamp for this TID.
 * 2. Computes latency in nanoseconds.
 * 3. Updates the per-PID LRU stats map (atomic).
 * 4. Emits a ringbuf event if latency exceeds slow_fsync_threshold_us.
 */
static __always_inline void record_exit(__u8 syscall_nr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid      = (__u32)(pid_tgid & 0xffffffffULL);
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    __u64 *start_ts = bpf_map_lookup_elem(&fsync_start, &tid);
    if (!start_ts)
        return;

    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - *start_ts;
    bpf_map_delete_elem(&fsync_start, &tid);

    // ── Update per-PID aggregated stats ──────────────────────────────────
    struct fsync_pid_val *stats = bpf_map_lookup_elem(&fsync_stats, &tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->total_calls, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
        /* max_latency_ns: no atomic max on all kernels, use compare-and-swap
         * approximation. Under extreme concurrency the max may be slightly
         * under-reported but never over-reported. */
        if (latency_ns > stats->max_latency_ns)
            stats->max_latency_ns = latency_ns;
        stats->last_seen_ts = now;
        /* Refresh comm on every update – PID can exec without changing TGID. */
        bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
    } else {
        /* First call for this PID: initialise the entry. */
        struct fsync_pid_val new_val;
        __builtin_memset(&new_val, 0, sizeof(new_val));
        new_val.total_calls      = 1;
        new_val.total_latency_ns = latency_ns;
        new_val.max_latency_ns   = latency_ns;
        new_val.last_seen_ts     = now;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&fsync_stats, &tgid, &new_val, BPF_NOEXIST);
    }

    // ── Emit slow-event to ringbuf (drop-safe) ────────────────────────────
    __u64 latency_us = latency_ns / 1000ULL;
    if (latency_us < slow_fsync_threshold_us)
        return;

    struct fsync_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return; /* ring full – drop rather than block */

    ev->pid           = tid;
    ev->tgid          = tgid;
    ev->latency_us    = latency_us;
    ev->timestamp_ns  = now;
    ev->syscall_nr    = syscall_nr;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
}

// ─── Programs ─────────────────────────────────────────────────────────────────

SEC("kprobe/__x64_sys_fsync")
int kprobe_fsync(struct pt_regs *ctx)
{
    record_entry();
    return 0;
}

SEC("kretprobe/__x64_sys_fsync")
int kretprobe_fsync(struct pt_regs *ctx)
{
    record_exit(0);
    return 0;
}

SEC("kprobe/__x64_sys_fdatasync")
int kprobe_fdatasync(struct pt_regs *ctx)
{
    record_entry();
    return 0;
}

SEC("kretprobe/__x64_sys_fdatasync")
int kretprobe_fdatasync(struct pt_regs *ctx)
{
    record_exit(1);
    return 0;
}

SEC("kprobe/__x64_sys_sync_file_range")
int kprobe_sync_file_range(struct pt_regs *ctx)
{
    record_entry();
    return 0;
}

SEC("kretprobe/__x64_sys_sync_file_range")
int kretprobe_sync_file_range(struct pt_regs *ctx)
{
    record_exit(2);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
