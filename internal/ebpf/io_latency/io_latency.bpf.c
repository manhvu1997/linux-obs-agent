//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ───────────────────────────────────────────────────────────────

#define TASK_COMM_LEN 16
#define MAX_ENTRIES   65536

// ─── Structs ─────────────────────────────────────────────────────────────────

struct io_key {
    __u64 dev;      // major:minor encoded as u64
    __u64 sector;
};

struct io_start_val {
    __u64 ts_ns;
    __u32 pid;
    char  comm[TASK_COMM_LEN];
};

struct io_event {
    __u32 pid;
    __u32 dev;
    __u64 sector;
    __u64 latency_us;
    __u32 bytes;        // nr_sector * 512
    __u8  op;           // 0 = read, 1 = write
    char  comm[TASK_COMM_LEN];
};

// ─── Maps ────────────────────────────────────────────────────────────────────

// Track IO start time and submitting PID per request.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct io_key);
    __type(value, struct io_start_val);
    __uint(max_entries, MAX_ENTRIES);
} io_start SEC(".maps");

// Ring buffer for slow-IO events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256 KB
} events SEC(".maps");

// Latency histogram: key = log2(us), value = count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} latency_hist SEC(".maps");

// ─── Config (set from Go via global vars) ────────────────────────────────────

// Only emit events for IO requests slower than this (microseconds).
const volatile __u64 slow_threshold_us = 1000; // default 1ms

// ─── Helpers ─────────────────────────────────────────────────────────────────

static __always_inline __u32 log2(__u64 v)
{
    __u32 r = 0;
    if (v > 0xffffffff) { v >>= 32; r += 32; }
    if (v > 0x0000ffff) { v >>= 16; r += 16; }
    if (v > 0x000000ff) { v >>= 8;  r += 8; }
    if (v > 0x0000000f) { v >>= 4;  r += 4; }
    if (v > 0x00000003) { v >>= 2;  r += 2; }
    r += (v >> 1);
    return r;
}

// ─── Programs ────────────────────────────────────────────────────────────────

// block_rq_issue fires when a block request is submitted to the driver.
// (Preferred over block_rq_insert which fires even before the plug queue drains.)
SEC("tracepoint/block/block_rq_issue")
int trace_rq_issue(struct trace_event_raw_block_rq *ctx)
{
    struct io_key key = {
        .dev    = ctx->dev,
        .sector = ctx->sector,
    };

    struct io_start_val val = {
        .ts_ns = bpf_ktime_get_ns(),
        .pid   = bpf_get_current_pid_tgid() & 0xffffffff,
    };
    bpf_get_current_comm(&val.comm, sizeof(val.comm));

    bpf_map_update_elem(&io_start, &key, &val, BPF_ANY);
    return 0;
}

// block_rq_complete fires when the driver signals completion.
SEC("tracepoint/block/block_rq_complete")
int trace_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
{
    struct io_key key = {
        .dev    = ctx->dev,
        .sector = ctx->sector,
    };

    struct io_start_val *start = bpf_map_lookup_elem(&io_start, &key);
    if (!start) return 0;

    __u64 latency_us = (bpf_ktime_get_ns() - start->ts_ns) / 1000ULL;
    __u32 pid = start->pid;
    char  comm[TASK_COMM_LEN];
    __builtin_memcpy(comm, start->comm, TASK_COMM_LEN);

    bpf_map_delete_elem(&io_start, &key);

    // Update histogram.
    __u32 bucket = log2(latency_us + 1);
    if (bucket >= 64) bucket = 63;
    __u64 *hval = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (hval)
        __sync_fetch_and_add(hval, 1);

    // Only emit events that exceed the slow threshold.
    if (latency_us < slow_threshold_us) return 0;

    struct io_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid        = pid;
    ev->dev        = (__u32)ctx->dev;
    ev->sector     = ctx->sector;
    ev->latency_us = latency_us;
    ev->bytes      = ctx->nr_sector * 512;
    // rwbs[0]: 'R'=read, 'W'=write, 'D'=discard, etc.
    ev->op = (ctx->rwbs[0] == 'R') ? 0 : 1;
    __builtin_memcpy(ev->comm, comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
