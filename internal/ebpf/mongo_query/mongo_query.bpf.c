//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// mongo_query.bpf.c – MongoDB slow query latency tracer.
//
// Design goals (production):
//   - Always-on, bounded memory: LRU map auto-evicts least-recently-used PIDs.
//   - Track query latency on the CLIENT side: hook the process that calls
//     connect()/write()/read() to a MongoDB server.
//   - Use PID+FD as the unique correlation key per active connection.
//   - Parse the MongoDB wire protocol (OP_MSG, opCode 2013) to extract the
//     operation type (find/insert/update/delete/aggregate) and collection name.
//   - For TLS-encrypted connections the header check will fail (ciphertext ≠
//     OP_MSG magic), so op_type/collection are left empty – latency is still
//     tracked correctly via the connect/write/read timing.
//
// Hooks attached:
//   tracepoint/syscalls/sys_enter_connect  – mark fd as a MongoDB connection
//   tracepoint/syscalls/sys_enter_write    – start query timer, parse OP_MSG
//   tracepoint/syscalls/sys_exit_read      – stop timer, emit slow event
//   tracepoint/syscalls/sys_enter_close    – clean up per-fd tracking state
//
// MongoDB wire protocol (OP_MSG, opCode 2013, MongoDB 5.1+):
//   Offset  0: int32  messageLength
//   Offset  4: int32  requestID
//   Offset  8: int32  responseTo
//   Offset 12: int32  opCode       (2013 = OP_MSG)
//   Offset 16: uint32 flagBits
//   Offset 20: uint8  sectionKind  (0 = Body)
//   Offset 21: BSON document
//     BSON doc: int32 docSize, then elements:
//       element: uint8 type, CString key, value
//     First element key = command name ("find","insert","update","delete","aggregate")
//     First element value (for string type 0x02): int32 len, UTF-8 bytes, NUL

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN    16
#define MAX_FD_ENTRIES   65536   /* in-flight connect + pending query tracking   */
#define MAX_PID_ENTRIES  10240   /* LRU per-PID stats (auto-evicts oldest)       */

#define OP_MSG           2013    /* MongoDB OP_MSG opCode                         */
#define MSG_HEADER_SIZE  16      /* 4×int32: msgLen, reqId, respTo, opCode        */

// Maximum length to copy for op_type and collection name.
// Must satisfy BPF verifier: constant bounds on all reads.
#define OP_TYPE_MAX      31
#define COLL_MAX         63

// ─── Key struct ───────────────────────────────────────────────────────────────

/*
 * mongo_fd_key_t: identifies a specific file descriptor within a process.
 * Used as the map key for both tracked_fds and pending_queries.
 */
struct mongo_fd_key_t {
    __u32 tgid;  /* process ID (thread-group leader) */
    __u32 fd;    /* file descriptor                   */
};

// ─── Value structs ────────────────────────────────────────────────────────────

/*
 * mongo_conn_val_t: metadata recorded at connect() time.
 * Keeps the MongoDB server address so slow events include dest_addr.
 */
struct mongo_conn_val_t {
    __u32 dest_ip;    /* IPv4 address in network byte order */
    __u16 dest_port;  /* port in host byte order            */
    __u8  _pad[2];
};

/*
 * mongo_pending_val_t: in-flight query state recorded at write() time.
 * Deleted at the matching read() so the map stays bounded.
 */
struct mongo_pending_val_t {
    __u64 start_ts;               /* bpf_ktime_get_ns() at write entry        */
    __u32 request_id;             /* OP_MSG requestID from wire header        */
    __u8  op_type[OP_TYPE_MAX+1]; /* command name: "find", "insert", ...      */
    __u8  collection[COLL_MAX+1]; /* collection name (empty for TLS traffic)  */
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct mongo_pending_val_t *__mongo_pending_val_t_unused __attribute__((unused));

/*
 * mongo_pid_stats_t: per-PID aggregated query statistics stored in the LRU map.
 * Monotonically increasing counters updated atomically.
 */
struct mongo_pid_stats_t {
    __u64 total_queries;      /* all queries observed on this PID              */
    __u64 slow_queries;       /* queries exceeding slow_query_threshold_ns     */
    __u64 total_latency_ns;   /* sum of all query latencies                    */
    __u64 max_latency_ns;     /* worst single query latency                    */
    __u64 last_seen_ts;       /* bpf_ktime_get_ns() of last update             */
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct mongo_pid_stats_t *__mongo_pid_stats_t_unused __attribute__((unused));

/*
 * mongo_slow_event_t: ringbuf event emitted for each slow query.
 * Contains all information needed for a useful /api/diagnose entry.
 */
struct mongo_slow_event_t {
    __u32 pid;                    /* kernel TID of the querying thread         */
    __u32 tgid;                   /* userspace PID (process group leader)      */
    __u32 fd;                     /* file descriptor of the MongoDB connection */
    __u32 request_id;             /* OP_MSG requestID                          */
    __u64 latency_ns;             /* query duration in nanoseconds             */
    __u32 dest_ip;                /* MongoDB server IPv4 (network byte order)  */
    __u16 dest_port;              /* MongoDB server port                       */
    __u8  op_type[OP_TYPE_MAX+1]; /* "find", "insert", etc. (empty if TLS)    */
    __u8  collection[COLL_MAX+1]; /* collection name (empty if TLS)           */
    __u8  comm[TASK_COMM_LEN];
};

/* Force BTF emission for bpf2go -type. */
struct mongo_slow_event_t *__mongo_slow_event_t_unused __attribute__((unused));

// ─── Maps ─────────────────────────────────────────────────────────────────────

/*
 * tracked_fds: file descriptors that we have identified as MongoDB connections
 * (i.e. connected to mongo_port at connect() time).
 * Regular HASH – entries are deleted in close(), so no unbounded growth.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct mongo_fd_key_t);
    __type(value, struct mongo_conn_val_t);
    __uint(max_entries, MAX_FD_ENTRIES);
} tracked_fds SEC(".maps");

/*
 * pending_queries: in-flight query state keyed by {tgid, fd}.
 * Entries are always deleted in the matching sys_exit_read – bounded size.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   struct mongo_fd_key_t);
    __type(value, struct mongo_pending_val_t);
    __uint(max_entries, MAX_FD_ENTRIES);
} pending_queries SEC(".maps");

/*
 * mongo_pid_stats: per-PID aggregated stats.
 * LRU_HASH auto-evicts when full, so memory is bounded regardless of PID churn.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);  /* tgid */
    __type(value, struct mongo_pid_stats_t);
    __uint(max_entries, MAX_PID_ENTRIES);
} mongo_pid_stats SEC(".maps");

/*
 * events: ringbuf for slow-query outlier notifications.
 * 256 KB ≈ 1600 events before consumer must drain.
 * Events are dropped (not blocking) when the buffer is full.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

/*
 * slow_query_threshold_ns: emit a ringbuf event only when a single query takes
 * longer than this duration (nanoseconds).  Default 2 000 000 000 ns = 2 s.
 * Override from Go before loading: spec.Variables["slow_query_threshold_ns"].Set(v).
 */
const volatile __u64 slow_query_threshold_ns = 2000000000ULL;

/*
 * mongo_port: the destination port used to identify MongoDB connections.
 * Default 27017.  Override via spec.Variables["mongo_port"].Set(v).
 */
const volatile __u32 mongo_port = 27017;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/*
 * copy_cstring_bounded: copy at most `max` bytes of a user-space CString into
 * `dst`, stopping at the first NUL byte.  Returns the number of bytes copied
 * (not including the NUL terminator, which is always written to dst[max]).
 *
 * Uses bpf_probe_read_user byte-by-byte so the verifier can track bounds.
 * max must be a compile-time constant ≤ 63 for the verifier to accept the loop.
 */
static __always_inline int copy_cstring_bounded(
    __u8 *dst, const char *src, int max)
{
    int i;
    __u8 c = 0;
    #pragma unroll
    for (i = 0; i < max; i++) {
        if (bpf_probe_read_user(&c, 1, src + i) != 0)
            break;
        if (c == 0)
            break;
        dst[i] = c;
    }
    dst[i] = 0; /* always NUL-terminate */
    return i;
}

/*
 * parse_op_msg: reads the MongoDB OP_MSG wire-format buffer from user space.
 * Extracts:
 *   - requestID  (wire header offset 4)
 *   - command name (first BSON element key in the Body section)
 *   - collection name (value of the command element, if type == string 0x02)
 *
 * Returns 1 if the buffer looks like a valid OP_MSG, 0 otherwise.
 * On a TLS connection the buffer will contain ciphertext – the opCode check
 * will fail, so we return 0 and the caller leaves op_type/collection empty.
 */
static __always_inline int parse_op_msg(
    const char *buf, __u64 buf_len,
    __u32 *out_req_id,
    __u8  *out_op_type,    /* pre-allocated OP_TYPE_MAX+1 bytes */
    __u8  *out_collection  /* pre-allocated COLL_MAX+1 bytes    */
) {
    if (buf_len < MSG_HEADER_SIZE + 4 + 1 + 4) /* header + flags + sectionKind + docLen */
        return 0;

    /* Read the 16-byte message header. */
    __s32 msg_len  = 0;
    __s32 req_id   = 0;
    __s32 op_code  = 0;

    if (bpf_probe_read_user(&msg_len, 4, buf + 0) != 0) return 0;
    if (bpf_probe_read_user(&req_id,  4, buf + 4) != 0) return 0;
    if (bpf_probe_read_user(&op_code, 4, buf + 12) != 0) return 0;

    if (op_code != OP_MSG)
        return 0; /* not an OP_MSG (or TLS ciphertext) */

    *out_req_id = (__u32)req_id;

    /*
     * Skip: flagBits (4B) + sectionKind (1B) + BSON doc length (4B) = 9 bytes.
     * First BSON element starts at offset 16 + 9 = 25.
     * BSON element: [1B type][CString key][value]
     */
    __u8 elem_type = 0;
    if (bpf_probe_read_user(&elem_type, 1, buf + 25) != 0) return 0;

    /* Command name is the CString key starting at offset 26. */
    const char *key_ptr = buf + 26;

    /* Copy command name into op_type (max OP_TYPE_MAX chars). */
    int key_len = copy_cstring_bounded(out_op_type, key_ptr, OP_TYPE_MAX);
    if (key_len == 0) return 1; /* valid OP_MSG but no key – unusual, skip collection */

    /* Value pointer: key_ptr + key_len + 1 (skip NUL terminator). */
    const char *val_ptr = key_ptr + key_len + 1;

    /*
     * If elem_type == 0x02 (UTF8 string), the value is:
     *   [4B string_len][UTF-8 bytes][NUL]
     * string_len includes the trailing NUL.
     */
    if (elem_type == 0x02) {
        __s32 str_len = 0;
        if (bpf_probe_read_user(&str_len, 4, val_ptr) != 0) return 1;
        if (str_len > 1 && str_len <= COLL_MAX + 1) {
            /* Collection name bytes start at val_ptr+4. */
            copy_cstring_bounded(out_collection, val_ptr + 4, COLL_MAX);
        }
    }

    return 1;
}

// ─── Tracepoint programs ──────────────────────────────────────────────────────

/*
 * sys_enter_connect: fires when any process calls connect(2).
 * We inspect the sockaddr argument: if it is AF_INET and the destination port
 * matches mongo_port, we record the fd in tracked_fds so that subsequent
 * write/read calls can be correlated with MongoDB traffic.
 *
 * args layout (syscalls/sys_enter_connect):
 *   args[0] = int fd
 *   args[1] = struct sockaddr __user *uservaddr
 *   args[2] = int addrlen
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_mongo_connect(struct trace_event_raw_sys_enter *ctx)
{
    int fd          = (int)ctx->args[0];
    void *uservaddr = (void *)ctx->args[1];
    int addrlen     = (int)ctx->args[2];

    if (fd < 0 || addrlen < 8 || !uservaddr)
        return 0;

    /* Read sa_family (first 2 bytes of sockaddr). */
    __u16 sa_family = 0;
    if (bpf_probe_read_user(&sa_family, 2, uservaddr) != 0)
        return 0;
    if (sa_family != 2) /* AF_INET only */
        return 0;

    /* Read sin_port (bytes 2-3, network byte order) and sin_addr (bytes 4-7). */
    __u16 sin_port = 0;
    __u32 sin_addr = 0;
    if (bpf_probe_read_user(&sin_port, 2, uservaddr + 2) != 0) return 0;
    if (bpf_probe_read_user(&sin_addr, 4, uservaddr + 4) != 0) return 0;

    /* sin_port is big-endian; convert to host byte order for comparison. */
    __u16 host_port = ((sin_port & 0xFF) << 8) | ((sin_port >> 8) & 0xFF);
    if (host_port != (__u16)mongo_port)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    struct mongo_fd_key_t key = { .tgid = tgid, .fd = (__u32)fd };
    struct mongo_conn_val_t val;
    __builtin_memset(&val, 0, sizeof(val));
    val.dest_ip   = sin_addr;
    val.dest_port = host_port;

    bpf_map_update_elem(&tracked_fds, &key, &val, BPF_ANY);
    return 0;
}

/*
 * sys_enter_write: fires when any process calls write(2) or send(2).
 * If the fd is in tracked_fds (i.e. a known MongoDB connection), we:
 *   1. Attempt to parse the buffer as an OP_MSG to extract op_type/collection.
 *   2. Record a pending_queries entry with the start timestamp.
 *
 * args layout (syscalls/sys_enter_write):
 *   args[0] = int fd
 *   args[1] = const void __user *buf
 *   args[2] = size_t count
 */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_mongo_write(struct trace_event_raw_sys_enter *ctx)
{
    int         fd  = (int)ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    __u64       cnt = (__u64)ctx->args[2];

    if (fd < 0 || cnt < MSG_HEADER_SIZE || !buf)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    struct mongo_fd_key_t key = { .tgid = tgid, .fd = (__u32)fd };
    if (!bpf_map_lookup_elem(&tracked_fds, &key))
        return 0; /* not a tracked MongoDB connection */

    struct mongo_pending_val_t pending;
    __builtin_memset(&pending, 0, sizeof(pending));
    pending.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&pending.comm, sizeof(pending.comm));

    /* Try to parse OP_MSG; if TLS, op_type/collection stay empty – that's OK. */
    parse_op_msg(buf, cnt, &pending.request_id,
                 pending.op_type, pending.collection);

    bpf_map_update_elem(&pending_queries, &key, &pending, BPF_ANY);
    return 0;
}

/*
 * sys_exit_read: fires when read(2) returns in any process.
 * If the fd is a tracked MongoDB connection and we have a pending query entry,
 * we compute the latency, update the per-PID LRU stats, and emit a ringbuf
 * event if the latency exceeds slow_query_threshold_ns.
 *
 * We use sys_exit_read (rather than sys_enter_read) so that:
 *   - The return value (ret) is available for validation (ret > 0 = data received).
 *   - We don't need to stash the fd ourselves; it is preserved in pending_queries.
 *
 * NOTE: On sys_exit we only have (ret) in args[1]; we need to iterate pending
 * queries for this tgid to find all fds that might have received data.
 * Since we key by {tgid, fd}, we use the fact that the fd is in the map –
 * we look up all tracked fds for this tgid.  In practice, with one connection
 * per MongoDB session, the pending_queries map entry for {tgid, fd} is the one
 * we want.  However, we cannot iterate by partial key in eBPF.
 *
 * Practical solution: also hook sys_enter_read to record the fd, then use it
 * in sys_exit_read via a per-TID stash map.  We store the fd at enter and
 * consume it at exit.
 *
 * Implementation uses a per-TID read_fd_stash map (regular HASH, bounded).
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);   /* kernel TID */
    __type(value, __u32);   /* fd being read */
    __uint(max_entries, MAX_FD_ENTRIES);
} read_fd_stash SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int tp_mongo_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    if (fd < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)(pid_tgid & 0xffffffffULL);

    /* Only stash if this fd is a tracked MongoDB connection. */
    struct mongo_fd_key_t key = { .tgid = tgid, .fd = (__u32)fd };
    if (!bpf_map_lookup_elem(&tracked_fds, &key))
        return 0;

    __u32 fd_u = (__u32)fd;
    bpf_map_update_elem(&read_fd_stash, &tid, &fd_u, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_mongo_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    long ret = ctx->ret;
    if (ret <= 0)
        return 0; /* read returned error or EOF – nothing to correlate */

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)(pid_tgid & 0xffffffffULL);

    /* Retrieve the fd we stashed in sys_enter_read. */
    __u32 *fd_p = bpf_map_lookup_elem(&read_fd_stash, &tid);
    if (!fd_p)
        return 0;
    __u32 fd = *fd_p;
    bpf_map_delete_elem(&read_fd_stash, &tid);

    struct mongo_fd_key_t key = { .tgid = tgid, .fd = fd };

    /* Look up the pending query for this {tgid, fd}. */
    struct mongo_pending_val_t *pending = bpf_map_lookup_elem(&pending_queries, &key);
    if (!pending)
        return 0;

    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - pending->start_ts;

    /* Save fields before deleting the pending entry. */
    __u32 request_id = pending->request_id;
    __u8  op_type[OP_TYPE_MAX+1];
    __u8  collection[COLL_MAX+1];
    __u8  comm[TASK_COMM_LEN];
    __builtin_memcpy(op_type,    pending->op_type,    sizeof(op_type));
    __builtin_memcpy(collection, pending->collection, sizeof(collection));
    __builtin_memcpy(comm,       pending->comm,       sizeof(comm));

    bpf_map_delete_elem(&pending_queries, &key);

    /* ── Update per-PID aggregated stats (LRU map) ─────────────────────────── */
    struct mongo_pid_stats_t *stats = bpf_map_lookup_elem(&mongo_pid_stats, &tgid);
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
        struct mongo_pid_stats_t new_stats;
        __builtin_memset(&new_stats, 0, sizeof(new_stats));
        new_stats.total_queries   = 1;
        new_stats.total_latency_ns = latency_ns;
        new_stats.max_latency_ns   = latency_ns;
        new_stats.slow_queries     = (latency_ns >= slow_query_threshold_ns) ? 1 : 0;
        new_stats.last_seen_ts     = now;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        bpf_map_update_elem(&mongo_pid_stats, &tgid, &new_stats, BPF_NOEXIST);
    }

    /* ── Emit ringbuf slow event ────────────────────────────────────────────── */
    if (latency_ns < slow_query_threshold_ns)
        return 0;

    /* Look up the connection metadata for dest_ip/dest_port. */
    struct mongo_conn_val_t *conn = bpf_map_lookup_elem(&tracked_fds, &key);
    __u32 dest_ip   = conn ? conn->dest_ip   : 0;
    __u16 dest_port = conn ? conn->dest_port : 0;

    struct mongo_slow_event_t *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0; /* ring full – drop rather than block */

    ev->pid        = tid;
    ev->tgid       = tgid;
    ev->fd         = fd;
    ev->request_id = request_id;
    ev->latency_ns = latency_ns;
    ev->dest_ip    = dest_ip;
    ev->dest_port  = dest_port;
    __builtin_memcpy(ev->op_type,    op_type,    sizeof(ev->op_type));
    __builtin_memcpy(ev->collection, collection, sizeof(ev->collection));
    __builtin_memcpy(ev->comm,       comm,       sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * sys_enter_close: fires when any process calls close(2).
 * Clean up tracked_fds so we do not track stale file descriptors after the
 * MongoDB connection is closed.  Also clean up any dangling pending_queries
 * entry (e.g. when a connection is closed mid-query).
 *
 * args layout (syscalls/sys_enter_close):
 *   args[0] = int fd
 */
SEC("tracepoint/syscalls/sys_enter_close")
int tp_mongo_close(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    if (fd < 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    struct mongo_fd_key_t key = { .tgid = tgid, .fd = (__u32)fd };

    /* Only clean up if this was a tracked MongoDB fd (avoids spurious work). */
    if (!bpf_map_lookup_elem(&tracked_fds, &key))
        return 0;

    bpf_map_delete_elem(&tracked_fds,    &key);
    bpf_map_delete_elem(&pending_queries, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
