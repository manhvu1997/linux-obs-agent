//go:build ignore
// Compiled by bpf2go.

// runqlat: measure task run-queue wait latency.
// Attach to sched_wakeup/sched_wakeup_new to record when a task becomes
// runnable, and to sched_switch to measure how long it had to wait.
//
// Two data paths, both aggregated in-kernel so userspace never wakes per event:
//   1. hist       – global log2(us) histogram over EVERY switch.
//   2. runq_stats – per-process (TGID) LRU aggregate, used to answer "which
//                   process is stalling on the run queue?".  Only waits at or
//                   above runq_track_min_us are aggregated here: sched_switch
//                   fires 100k-500k/s and the overwhelming majority of waits
//                   are sub-100us noise, so this gate removes >90% of the map
//                   writes without losing any signal (the histogram above
//                   still counts every switch).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN    16
#define MAX_ENTRIES      65536
#define MAX_PID_ENTRIES  8192   /* LRU per-process stats (auto-evicts oldest) */

// ─── Structs ─────────────────────────────────────────────────────────────────

struct runq_event {
    __u32 pid;
    __u32 tgid;
    __u64 latency_us;
    char  comm[TASK_COMM_LEN];
};

// Force BTF emission so bpf2go -type can export this struct.
struct runq_event *__runq_event_unused __attribute__((unused));

/*
 * Per-process aggregated run-queue statistics (value of the runq_stats map).
 *
 * tracked_switches counts only waits >= runq_track_min_us, so
 * total_latency_ns / tracked_switches is the mean over TRACKED waits — not
 * over all context switches. Userspace labels it accordingly.
 */
struct runq_pid_stat {
    __u64 tracked_switches;
    __u64 total_latency_ns;
    __u64 max_latency_ns;
    __u64 slow_events;    /* waits >= runqlat_threshold_us (level-2 breaches) */
    __u64 last_seen_ts;
    __u32 tgid;
    __u8  comm[TASK_COMM_LEN];
};

// Force BTF emission so bpf2go -type can export this struct.
struct runq_pid_stat *__runq_pid_stat_unused __attribute__((unused));

// ─── Maps ────────────────────────────────────────────────────────────────────

// Record wakeup timestamp per PID.
// LRU (not plain HASH): a task that is woken and then exits before ever being
// scheduled never reaches sched_switch, so its entry is never deleted. With a
// plain HASH those leak until the map is full and further inserts fail
// silently; LRU evicts the coldest entry instead.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32); // pid
    __type(value, __u64); // wakeup time ns
    __uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

// Ring buffer for high-latency run-queue events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

// Histogram: key = log2(us), value = sample count.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} hist SEC(".maps");

// Per-process aggregate. LRU bounds memory at ~8192 * 64 B ≈ 512 KB.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);                  /* tgid / userspace PID */
    __type(value, struct runq_pid_stat);
    __uint(max_entries, MAX_PID_ENTRIES);
} runq_stats SEC(".maps");

// ─── Config ──────────────────────────────────────────────────────────────────

// Only emit events when runq wait > this threshold (microseconds).
// Overridden from Go: spec.Variables["runqlat_threshold_us"].Set(v).
const volatile __u64 runqlat_threshold_us = 5000; // 5ms

// Aggregation floor: waits below this are counted in the histogram but do not
// touch the per-process map. Overridden from Go the same way.
const volatile __u64 runq_track_min_us = 100;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static __always_inline __u32 log2u(__u64 v) {
    __u32 r = 0;
    if (v > 0xffffffff) { v >>= 32; r += 32; }
    if (v > 0x0000ffff) { v >>= 16; r += 16; }
    if (v > 0x000000ff) { v >>= 8;  r += 8; }
    if (v > 0x0000000f) { v >>= 4;  r += 4; }
    if (v > 0x00000003) { v >>= 2;  r += 2; }
    r += (v >> 1);
    return r;
}

// Record the time a task enters the run queue.
static __always_inline void record_start(__u32 pid) {
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
}

/*
 * Fold one run-queue wait into the per-process aggregate.
 * Called only for waits >= runq_track_min_us (see handle_switch).
 */
static __always_inline void record_pid_stat(struct task_struct *next, __u32 tgid,
                                            __u64 latency_ns, __u64 now, __u8 is_slow)
{
    struct runq_pid_stat *st = bpf_map_lookup_elem(&runq_stats, &tgid);
    if (st) {
        __sync_fetch_and_add(&st->tracked_switches, 1);
        __sync_fetch_and_add(&st->total_latency_ns, latency_ns);
        if (is_slow)
            __sync_fetch_and_add(&st->slow_events, 1);
        /* No atomic max helper on all kernels. Under extreme concurrency the
         * max may be slightly under-reported, never over-reported. */
        if (latency_ns > st->max_latency_ns)
            st->max_latency_ns = latency_ns;
        st->last_seen_ts = now;
        /* Refresh comm: a process can exec without changing its TGID. */
        BPF_CORE_READ_STR_INTO(&st->comm, next, comm);
        return;
    }

    struct runq_pid_stat new_val;
    __builtin_memset(&new_val, 0, sizeof(new_val));
    new_val.tracked_switches = 1;
    new_val.total_latency_ns = latency_ns;
    new_val.max_latency_ns   = latency_ns;
    new_val.slow_events      = is_slow ? 1 : 0;
    new_val.last_seen_ts     = now;
    new_val.tgid             = tgid;
    BPF_CORE_READ_STR_INTO(&new_val.comm, next, comm);
    bpf_map_update_elem(&runq_stats, &tgid, &new_val, BPF_NOEXIST);
}

// ─── Programs ────────────────────────────────────────────────────────────────

// sched_wakeup: a task that was sleeping becomes runnable.
SEC("tp_btf/sched_wakeup")
int handle_wakeup(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[0];
    __u32 pid = BPF_CORE_READ(p, pid);
    record_start(pid);
    return 0;
}

// sched_wakeup_new: a newly forked task becomes runnable for the first time.
SEC("tp_btf/sched_wakeup_new")
int handle_wakeup_new(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[0];
    __u32 pid = BPF_CORE_READ(p, pid);
    record_start(pid);
    return 0;
}

// sched_switch: the scheduler is picking a new task to run.
// prev = task losing the CPU, next = task gaining the CPU.
SEC("tp_btf/sched_switch")
int handle_switch(u64 *ctx)
{
    // ctx layout (from kernel sched_switch tracepoint):
    //   ctx[0] = preempt (bool)
    //   ctx[1] = prev task_struct*
    //   ctx[2] = next task_struct*
    struct task_struct *next = (struct task_struct *)ctx[2];

    __u32 pid  = BPF_CORE_READ(next, pid);
    __u32 tgid = BPF_CORE_READ(next, tgid);

    __u64 *tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) return 0;

    __u64 now   = bpf_ktime_get_ns();
    __u64 delta = now - *tsp;
    bpf_map_delete_elem(&start, &pid);

    __u64 lat_us = delta / 1000ULL;

    // Update histogram (every switch, unconditionally).
    __u32 bucket = log2u(lat_us + 1);
    if (bucket >= 64) bucket = 63;
    __u64 *hv = bpf_map_lookup_elem(&hist, &bucket);
    if (hv) __sync_fetch_and_add(hv, 1);

    __u8 is_slow = lat_us >= runqlat_threshold_us;

    // Per-process aggregate: skip sub-threshold noise to keep the hot path cheap.
    if (lat_us >= runq_track_min_us)
        record_pid_stat(next, tgid, delta, now, is_slow);

    // Emit event only when above threshold.
    if (!is_slow) return 0;

    struct runq_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid        = pid;
    ev->tgid       = tgid;
    ev->latency_us = lat_us;
    BPF_CORE_READ_STR_INTO(&ev->comm, next, comm);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
