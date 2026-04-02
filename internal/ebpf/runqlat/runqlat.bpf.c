//go:build ignore
// Compiled by bpf2go.

// runqlat: measure task run-queue wait latency.
// Attach to sched_wakeup/sched_wakeup_new to record when a task becomes
// runnable, and to sched_switch to measure how long it had to wait.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_ENTRIES   65536

// ─── Structs ─────────────────────────────────────────────────────────────────

struct runq_event {
    __u32 pid;
    __u32 tgid;
    __u64 latency_us;
    char  comm[TASK_COMM_LEN];
};

// Force BTF emission so bpf2go -type can export this struct.
struct runq_event *__runq_event_unused __attribute__((unused));

// ─── Maps ────────────────────────────────────────────────────────────────────

// Record wakeup timestamp per PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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

// ─── Config ──────────────────────────────────────────────────────────────────

// Only emit events when runq wait > this threshold (microseconds).
const volatile __u64 runqlat_threshold_us = 5000; // 5ms

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

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &pid);

    __u64 lat_us = delta / 1000ULL;

    // Update histogram.
    __u32 bucket = log2u(lat_us + 1);
    if (bucket >= 64) bucket = 63;
    __u64 *hv = bpf_map_lookup_elem(&hist, &bucket);
    if (hv) __sync_fetch_and_add(hv, 1);

    // Emit event only when above threshold.
    if (lat_us < runqlat_threshold_us) return 0;

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
