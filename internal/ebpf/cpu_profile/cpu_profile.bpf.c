//go:build ignore
// This file is compiled by bpf2go (not the Go toolchain).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ───────────────────────────────────────────────────────────────

#define MAX_STACK_DEPTH  64
#define TASK_COMM_LEN    16
#define MAX_ENTRIES      10240

// ─── Maps ────────────────────────────────────────────────────────────────────

// Stack-trace storage: key = stack_id (u32), value = array of instruction ptrs
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

// Per-PID sample count map for aggregated flamegraph output
struct cpu_count_key {
    __u32 pid;
    __u32 tgid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct cpu_count_key);
    __type(value, __u64);
    __uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

// Ring buffer for raw per-sample events (used when detailed events are needed)
struct cpu_sample_event {
    __u32 pid;
    __u32 tgid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
    __u64 ts_ns;
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256 KB
} events SEC(".maps");

// ─── Config (set via global variables from Go) ───────────────────────────────

// Sampling filter: only emit for a specific PID (0 = all)
const volatile __u32 target_pid = 0;

// ─── Program ─────────────────────────────────────────────────────────────────

// Attached to perf_event (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK)
// by the Go loader via link.AttachPerfEvent for each online CPU.
SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx)
{
    __u64 id   = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 pid  = id & 0xffffffffULL;

    // Skip idle thread and kernel-only threads.
    if (tgid == 0) return 0;

    // Optionally filter to a single pid.
    if (target_pid && pid != target_pid) return 0;

    struct cpu_count_key key = {};
    key.pid  = pid;
    key.tgid = tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    // Increment aggregated count (flamegraph-ready folded format).
    __u64 *cnt = bpf_map_lookup_elem(&counts, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }

    // Emit raw sample event into ring buffer so the user-space consumer
    // can react in near-real-time (e.g., detect a hot PID).
    struct cpu_sample_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid          = pid;
    ev->tgid         = tgid;
    ev->ts_ns        = bpf_ktime_get_ns();
    ev->kern_stack_id = key.kern_stack_id;
    ev->user_stack_id = key.user_stack_id;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
