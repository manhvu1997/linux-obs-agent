//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// writeback.bpf.c – per-PID memory writeback and direct-reclaim latency tracer.
//
// Design goals (production):
//   - Always-on, bounded memory: LRU map auto-evicts least-recently-used PIDs.
//   - No per-event userspace wakeup for normal dirty-page or writeback ops.
//   - Direct-reclaim outliers (latency > slow_reclaim_threshold_ns) emitted to
//     a 256 KB ringbuf for real-time alerting.
//   - <2% CPU overhead at typical dirty-page rates (10k–100k pages/s).
//
// Tracepoints attached:
//   tracepoint/writeback/writeback_dirty_page          – per-PID dirty count
//   tracepoint/writeback/writeback_start               – system writeback counter
//   tracepoint/vmscan/mm_vmscan_direct_reclaim_begin   – per-TID reclaim start
//   tracepoint/vmscan/mm_vmscan_direct_reclaim_end     – per-TID reclaim end
//
// Note: writeback_dirty_page and mm_vmscan_direct_reclaim_* fire in the
// context of the process that dirtied/stalled, so bpf_get_current_pid_tgid()
// returns the responsible userspace PID.  writeback_start fires in a kworker
// context and is used only for a system-wide writeback counter.
//
// Requires kernel >= 4.x (tracepoints).  No BTF dependency: tracepoint args
// are not read from ctx – only bpf_get_current_pid_tgid() / bpf_ktime_get_ns()
// are used, avoiding trace_event_raw_* struct relocation issues.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN    16
#define MAX_PID_ENTRIES  16384   /* LRU per-PID stats (auto-evicts oldest)     */
#define MAX_TID_ENTRIES  65536   /* in-flight direct-reclaim start timestamps  */

// ─── Structs ──────────────────────────────────────────────────────────────────

/*
 * Per-PID aggregated writeback / reclaim statistics.
 * Written from multiple tracepoints; monotonically increasing counters.
 */
struct wb_pid_val {
    __u64 dirty_pages;        /* pages dirtied by this PID since agent start  */
    __u64 reclaim_count;      /* number of direct-reclaim episodes             */
    __u64 total_reclaim_ns;   /* total ns spent stalled in direct reclaim      */
    __u64 max_reclaim_ns;     /* worst single direct-reclaim stall             */
    __u64 last_seen_ts;       /* bpf_ktime_get_ns() of last update             */
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct wb_pid_val *__wb_pid_val_unused __attribute__((unused));

/*
 * Slow direct-reclaim ringbuf event.
 * Emitted only when a single episode exceeds slow_reclaim_threshold_ns.
 */
struct wb_slow_event {
    __u32 pid;                /* kernel TID of the reclaiming thread           */
    __u32 tgid;               /* userspace PID (process group leader)          */
    __u64 reclaim_latency_ns; /* duration of this direct-reclaim episode       */
    __u64 timestamp_ns;       /* bpf_ktime_get_ns() at reclaim exit            */
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct wb_slow_event *__wb_slow_event_unused __attribute__((unused));

// ─── Maps ─────────────────────────────────────────────────────────────────────

/*
 * wb_pid_stats: per-PID aggregated dirty-page and reclaim statistics.
 * LRU_HASH auto-evicts the least-recently-used entry when max_entries is hit,
 * so memory is always bounded regardless of PID churn.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);               /* tgid / userspace PID */
    __type(value, struct wb_pid_val);
    __uint(max_entries, MAX_PID_ENTRIES);
} wb_pid_stats SEC(".maps");

/*
 * reclaim_start: transient per-TID start timestamp for direct-reclaim pairing.
 * Regular HASH (not LRU) because entries are always deleted in the "end"
 * tracepoint – no unbounded growth.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);   /* kernel TID */
    __type(value, __u64);   /* bpf_ktime_get_ns() at reclaim entry */
    __uint(max_entries, MAX_TID_ENTRIES);
} reclaim_start SEC(".maps");

/*
 * wb_sys_count: single-entry array holding the total number of writeback
 * operations started system-wide (updated in kworker context from
 * writeback_start tracepoint).
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} wb_sys_count SEC(".maps");

/*
 * events: ringbuf for slow direct-reclaim outlier notifications.
 * 256 KB ≈ 1600 events before consumer must drain.
 * Events are dropped (not blocking) when the buffer is full.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

/*
 * Emit a ringbuf event only when a single direct-reclaim episode exceeds this
 * duration (nanoseconds).  Default 100 ms – reduces noise for short stalls.
 * Override from Go before loading: spec.Variables["slow_reclaim_threshold_ns"].Set(v).
 */
const volatile __u64 slow_reclaim_threshold_ns = 100000000ULL; /* 100 ms */

// ─── Tracepoint programs ──────────────────────────────────────────────────────

/*
 * writeback_dirty_page: fires in the context of the process that dirtied the
 * page (via __set_page_dirty / folio_mark_dirty).  Increments the per-PID
 * dirty_pages counter.
 *
 * High-frequency path (can fire 100k+/s).  The only work done here is a single
 * LRU map lookup + atomic increment, keeping overhead minimal.
 */
SEC("tracepoint/writeback/writeback_dirty_page")
int tp_writeback_dirty_page(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);
    __u64 now      = bpf_ktime_get_ns();

    struct wb_pid_val *stats = bpf_map_lookup_elem(&wb_pid_stats, &tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->dirty_pages, 1);
        stats->last_seen_ts = now;
        bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
    } else {
        struct wb_pid_val new_val;
        __builtin_memset(&new_val, 0, sizeof(new_val));
        new_val.dirty_pages  = 1;
        new_val.last_seen_ts = now;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&wb_pid_stats, &tgid, &new_val, BPF_NOEXIST);
    }
    return 0;
}

/*
 * writeback_start: fires in the kworker (flusher thread) context when the
 * kernel begins flushing dirty pages to disk.  Used only to maintain a
 * system-wide writeback operation counter; PID attribution is not attempted
 * here because the kworker PID != the dirtying process PID.
 */
SEC("tracepoint/writeback/writeback_start")
int tp_writeback_start(void *ctx)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&wb_sys_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    return 0;
}

/*
 * mm_vmscan_direct_reclaim_begin: fires when the current process is about to
 * perform synchronous page reclaim (it ran out of free memory and cannot wait
 * for the background kswapd).  This is the primary latency impact on
 * application threads.  Records the start timestamp keyed by kernel TID.
 */
SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int tp_direct_reclaim_begin(void *ctx)
{
    __u32 tid = (__u32)(bpf_get_current_pid_tgid() & 0xffffffffULL);
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&reclaim_start, &tid, &ts, BPF_ANY);
    return 0;
}

/*
 * mm_vmscan_direct_reclaim_end: fires when direct reclaim for the current
 * thread completes.  Computes the stall duration, updates the per-PID LRU
 * map, and emits a ringbuf outlier event when the stall exceeds the threshold.
 */
SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int tp_direct_reclaim_end(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid      = (__u32)(pid_tgid & 0xffffffffULL);
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    __u64 *start_ts = bpf_map_lookup_elem(&reclaim_start, &tid);
    if (!start_ts)
        return 0;

    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - *start_ts;
    bpf_map_delete_elem(&reclaim_start, &tid);

    /* ── Update per-PID aggregated stats ──────────────────────────────────── */
    struct wb_pid_val *stats = bpf_map_lookup_elem(&wb_pid_stats, &tgid);
    if (stats) {
        __sync_fetch_and_add(&stats->reclaim_count, 1);
        __sync_fetch_and_add(&stats->total_reclaim_ns, latency_ns);
        if (latency_ns > stats->max_reclaim_ns)
            stats->max_reclaim_ns = latency_ns;
        stats->last_seen_ts = now;
        bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
    } else {
        struct wb_pid_val new_val;
        __builtin_memset(&new_val, 0, sizeof(new_val));
        new_val.reclaim_count    = 1;
        new_val.total_reclaim_ns = latency_ns;
        new_val.max_reclaim_ns   = latency_ns;
        new_val.last_seen_ts     = now;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&wb_pid_stats, &tgid, &new_val, BPF_NOEXIST);
    }

    /* ── Emit slow-event to ringbuf (drop-safe) ────────────────────────────── */
    if (latency_ns < slow_reclaim_threshold_ns)
        return 0;

    struct wb_slow_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0; /* ring full – drop rather than block */

    ev->pid                = tid;
    ev->tgid               = tgid;
    ev->reclaim_latency_ns = latency_ns;
    ev->timestamp_ns       = now;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
