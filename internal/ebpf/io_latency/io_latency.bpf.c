//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// io_latency: block IO latency tracking via fentry hooks.
//
// Uses fentry/blk_mq_start_request and fentry/blk_mq_end_request instead of
// the raw tracepoints block:block_rq_issue / block:block_rq_complete.
//
// Reason: the classic tracepoint approach requires struct trace_event_raw_block_rq_completion
// to be present in the running kernel's BTF.  This struct was renamed between
// kernel versions (5.14 introduced the "completion" class), causing CO-RE
// relocation failures ("invalid func unknown#...") when vmlinux.h was compiled
// from a different kernel than the running one.
//
// fentry programs hook the actual kernel functions via BTF, avoiding the raw
// event struct entirely.  Requires kernel >= 5.5 with CONFIG_DEBUG_INFO_BTF=y.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ───────────────────────────────────────────────────────────────

#define TASK_COMM_LEN 16
#define MAX_ENTRIES   65536

/* req_op: low 8 bits of cmd_flags; 0=READ, 1=WRITE. */
#define REQ_OP_MASK 0xffu
#define REQ_OP_READ  0u
#define REQ_OP_WRITE 1u

// ─── Structs ─────────────────────────────────────────────────────────────────

struct io_lat_event {
    __u32 pid;
    __u32 dev;
    __u64 sector;
    __u64 latency_us;
    __u32 bytes;        /* request data length */
    __u8  op;           /* 0 = read, 1 = write */
    char  comm[TASK_COMM_LEN];
};

/* Force BTF emission so bpf2go -type can export this struct. */
struct io_lat_event *__io_lat_event_unused __attribute__((unused));

/* Per-request start info keyed by request pointer. */
struct io_start_val {
    __u64 ts_ns;
    __u32 pid;
    char  comm[TASK_COMM_LEN];
};

// ─── Maps ────────────────────────────────────────────────────────────────────

/* Track IO start time per in-flight request (keyed by struct request *). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u64);              /* request pointer cast to u64 */
    __type(value, struct io_start_val);
    __uint(max_entries, MAX_ENTRIES);
} io_start SEC(".maps");

/* Ring buffer for slow-IO events. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

/* Latency histogram: key = log2(us), value = count. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} latency_hist SEC(".maps");

// ─── Config (set from Go via global vars) ────────────────────────────────────

/* Only emit events for IO requests slower than this (microseconds). */
const volatile __u64 slow_threshold_us = 1000; /* default 1ms */

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

/*
 * get_request_devt: read the device number from struct request.
 *
 * rq->part (struct block_device *) was introduced in kernel 5.12, replacing
 * the older rq->rq_disk (struct gendisk *).  Since vmlinux.h is generated
 * from a kernel >= 5.12, rq_disk no longer exists in the compiled headers
 * and we use rq->part->bd_dev directly.
 */
static __always_inline __u32 get_request_devt(struct request *rq)
{
    struct block_device *part = BPF_CORE_READ(rq, part);
    return (__u32)BPF_CORE_READ(part, bd_dev);
}

// ─── Programs ────────────────────────────────────────────────────────────────

/*
 * blk_mq_start_request fires when a request is handed to the hardware queue.
 * Record the start timestamp and submitting PID, keyed by request pointer.
 */
SEC("fentry/blk_mq_start_request")
int BPF_PROG(trace_rq_issue, struct request *rq)
{
    __u64 key = (__u64)(unsigned long)rq;

    struct io_start_val val = {
        .ts_ns = bpf_ktime_get_ns(),
        .pid   = bpf_get_current_pid_tgid() & 0xffffffff,
    };
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    bpf_map_update_elem(&io_start, &key, &val, BPF_ANY);
    return 0;
}

/*
 * blk_mq_end_request fires on IO completion from the hardware queue.
 * Compute latency, update histogram, and emit slow-IO events.
 */
SEC("fentry/blk_mq_end_request")
int BPF_PROG(trace_rq_complete, struct request *rq, blk_status_t error)
{
    __u64 key = (__u64)(unsigned long)rq;

    struct io_start_val *start = bpf_map_lookup_elem(&io_start, &key);
    if (!start)
        return 0;

    __u64 latency_us = (bpf_ktime_get_ns() - start->ts_ns) / 1000ULL;
    __u32 pid = start->pid;
    char  comm[TASK_COMM_LEN];
    __builtin_memcpy(comm, start->comm, TASK_COMM_LEN);
    bpf_map_delete_elem(&io_start, &key);

    /* Update histogram. */
    __u32 bucket = log2(latency_us + 1);
    if (bucket >= 64) bucket = 63;
    __u64 *hval = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (hval)
        __sync_fetch_and_add(hval, 1);

    if (latency_us < slow_threshold_us)
        return 0;

    struct io_lat_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid        = pid;
    ev->sector     = BPF_CORE_READ(rq, __sector);
    ev->latency_us = latency_us;
    ev->bytes      = (__u32)BPF_CORE_READ(rq, __data_len);
    ev->dev        = get_request_devt(rq);

    /* Low 8 bits of cmd_flags = req_op; 0 = READ, anything else = WRITE. */
    __u32 cmd_flags = BPF_CORE_READ(rq, cmd_flags);
    ev->op = ((cmd_flags & REQ_OP_MASK) == REQ_OP_READ) ? 0 : 1;

    __builtin_memcpy(ev->comm, comm, TASK_COMM_LEN);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
