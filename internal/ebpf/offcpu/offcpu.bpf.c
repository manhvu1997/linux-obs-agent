//go:build ignore
// Compiled by bpf2go.

// offcpu.bpf.c – off-CPU (blocked-time) profiler.
//
// Answers the question an on-CPU profiler structurally cannot: "what is this
// process BLOCKED on, and for how long?".  A perf_event sampler only fires on
// a CPU that is running a task, so a task sleeping in D state is never
// sampled — which is exactly the state that produces iowait.
//
// Mechanism (the classic offcputime technique), one tracepoint, two halves:
//
//   sched_switch(prev, next)
//     ├── prev is leaving the CPU
//     │     if prev is BLOCKING (not merely preempted):
//     │         blocked[prev->pid] = { now, kstack, ustack, comm }
//     │     ^ the stack is captured here, at the moment of blocking, which is
//     │       what makes the result attributable.  `current` is still prev at
//     │       this tracepoint, so bpf_get_stackid walks the right task.
//     │
//     └── next is entering the CPU
//           info = blocked[next->pid]
//           delta = now - info.ts          ← time spent off-CPU
//           counts[{tgid, pid, kstack, ustack, comm}] += delta
//
// Overhead: the dominant cost is bpf_get_stackid, and it only runs when prev
// is actually blocking.  Involuntary preemption leaves prev in TASK_RUNNING
// and is skipped before any stack walk — on a busy host that is the large
// majority of context switches.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ───────────────────────────────────────────────────────────────

#define TASK_COMM_LEN     16
#define MAX_STACK_DEPTH   64
#define MAX_ENTRIES       10240
#define MAX_BLOCKED       65536

/* Linux task state bits (include/linux/sched.h). */
#define TASK_INTERRUPTIBLE    0x0001  /* S – sleeping, wakeable (epoll, futex) */
#define TASK_UNINTERRUPTIBLE  0x0002  /* D – sleeping in the kernel, counts to iowait */

/* track_state bitmask values, mirrored in the Go loader. */
#define TRACK_INTERRUPTIBLE   0x01
#define TRACK_UNINTERRUPTIBLE 0x02

// ─── Structs ─────────────────────────────────────────────────────────────────

/* Aggregation key: one unique blocking site for one thread. */
struct offcpu_key {
    __u32 tgid;
    __u32 pid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
    __u8  comm[TASK_COMM_LEN];
};

/* Accumulated blocked time for one key. */
struct offcpu_val {
    __u64 total_ns;
    __u64 events;
    __u64 max_ns;
};

/* Force BTF emission so bpf2go -type can export these. */
struct offcpu_key *__offcpu_key_unused __attribute__((unused));
struct offcpu_val *__offcpu_val_unused __attribute__((unused));

/* In-flight record: written when a task blocks, consumed when it wakes. */
struct blocked_info {
    __u64 ts;
    __s32 kern_stack_id;
    __s32 user_stack_id;
    __u32 tgid;
    __u8  comm[TASK_COMM_LEN];
};

// ─── CO-RE task state accessor ───────────────────────────────────────────────
//
// Kernel 5.14 renamed task_struct.state → task_struct.__state and narrowed it
// from `long` to `unsigned int`.  Both shapes are declared as standalone
// relocatable structs so this file compiles against either vmlinux.h, and CO-RE
// picks the right one at load time.

struct task_struct___new {
    unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___old {
    long int state;
} __attribute__((preserve_access_index));

static __always_inline __u32 get_task_state(struct task_struct *t)
{
    struct task_struct___new *n = (void *)t;
    if (bpf_core_field_exists(n->__state))
        return (__u32)BPF_CORE_READ(n, __state);

    struct task_struct___old *o = (void *)t;
    return (__u32)BPF_CORE_READ(o, state);
}

// ─── Maps ────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

/*
 * blocked: in-flight blocking intervals, keyed by TID.
 * LRU because a task can block and then exit without ever being scheduled
 * again, which would leak the entry in a plain HASH.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);                 /* tid */
    __type(value, struct blocked_info);
    __uint(max_entries, MAX_BLOCKED);
} blocked SEC(".maps");

/* counts: accumulated blocked time per (thread, blocking stack). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   struct offcpu_key);
    __type(value, struct offcpu_val);
    __uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

// ─── Config (rewritten from Go before load) ──────────────────────────────────

/* Restrict to one process (0 = system-wide). */
const volatile __u32 target_tgid = 0;

/* Ignore blocking intervals shorter than this (microseconds). Filters out the
 * constant churn of short sleeps that carry no diagnostic signal. */
const volatile __u64 min_block_us = 1000;

/* Sanity cap: ignore intervals longer than this (microseconds). Guards against
 * a stale `blocked` entry being matched to an unrelated later wake-up. */
const volatile __u64 max_block_us = 60000000; /* 60 s */

/* Which sleep states to attribute. Default: uninterruptible only — that is the
 * state behind iowait. Adding TRACK_INTERRUPTIBLE also captures ordinary idle
 * waiting (epoll, futex, sleep), which is usually overwhelming noise. */
const volatile __u8 track_state = TRACK_UNINTERRUPTIBLE;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/* record_block: prev is leaving the CPU. Capture the blocking stack. */
static __always_inline void record_block(void *ctx, struct task_struct *prev, __u64 now)
{
    __u32 state = get_task_state(prev);

    /* Build the same bitmask shape as track_state. A task left in
     * TASK_RUNNING was preempted, not blocked — nothing to attribute. */
    __u8 want = 0;
    if (state & TASK_UNINTERRUPTIBLE)
        want |= TRACK_UNINTERRUPTIBLE;
    if (state & TASK_INTERRUPTIBLE)
        want |= TRACK_INTERRUPTIBLE;
    if (!(want & track_state))
        return;

    __u32 tgid = BPF_CORE_READ(prev, tgid);
    if (tgid == 0)
        return; /* idle / kernel-idle task */
    if (target_tgid && tgid != target_tgid)
        return;

    __u32 pid = BPF_CORE_READ(prev, pid);

    struct blocked_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.ts            = now;
    info.tgid          = tgid;
    info.kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    info.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    BPF_CORE_READ_STR_INTO(&info.comm, prev, comm);

    bpf_map_update_elem(&blocked, &pid, &info, BPF_ANY);
}

/* record_wake: next is entering the CPU. Close out its blocked interval. */
static __always_inline void record_wake(struct task_struct *next, __u64 now)
{
    __u32 pid = BPF_CORE_READ(next, pid);

    struct blocked_info *ip = bpf_map_lookup_elem(&blocked, &pid);
    if (!ip)
        return;

    /* Copy out BEFORE deleting — the map may free the value afterwards. */
    struct blocked_info info = *ip;
    bpf_map_delete_elem(&blocked, &pid);

    if (now <= info.ts)
        return;
    __u64 delta    = now - info.ts;
    __u64 delta_us = delta / 1000ULL;

    if (delta_us < min_block_us)
        return;
    if (max_block_us && delta_us > max_block_us)
        return;

    struct offcpu_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.tgid          = info.tgid;
    key.pid           = pid;
    key.kern_stack_id = info.kern_stack_id;
    key.user_stack_id = info.user_stack_id;
    __builtin_memcpy(&key.comm, &info.comm, TASK_COMM_LEN);

    struct offcpu_val *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(&val->total_ns, delta);
        __sync_fetch_and_add(&val->events, 1);
        if (delta > val->max_ns)
            val->max_ns = delta;
        return;
    }

    struct offcpu_val nv;
    __builtin_memset(&nv, 0, sizeof(nv));
    nv.total_ns = delta;
    nv.events   = 1;
    nv.max_ns   = delta;
    bpf_map_update_elem(&counts, &key, &nv, BPF_NOEXIST);
}

// ─── Program ─────────────────────────────────────────────────────────────────

SEC("tp_btf/sched_switch")
int handle_switch(u64 *ctx)
{
    /* ctx layout: [0] = preempt, [1] = prev task_struct*, [2] = next task_struct* */
    struct task_struct *prev = (struct task_struct *)ctx[1];
    struct task_struct *next = (struct task_struct *)ctx[2];

    __u64 now = bpf_ktime_get_ns();

    record_block(ctx, prev, now);
    record_wake(next, now);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
