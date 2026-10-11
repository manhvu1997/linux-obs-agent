//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// pg_query.bpf.c – PostgreSQL statement attribution (server-side uprobes).
//
// Every backend's time is cut into intervals at pgstat_report_activity: a
// RUNNING report (simple Query, Parse, Bind, Execute, parallel worker start)
// opens an interval tagged with the hash of its SQL text; any report closes
// the open one, whose deltas are summed into agg_<agg_active> keyed by
// {postmaster, kind, hash}. Idle and idle-in-transaction time is never
// attributed. Text crosses to userspace once per hash (text_events).
//
// Hooks (uprobes on the postgres binary; all exported in PGDG 16–19):
//   uprobe   pgstat_report_activity(BackendState state, const char *cmd_str)
//   uprobe   PortalRun(Portal, long, bool isTopLevel, …)      calls++ when top level
//   uprobe   pgstat_report_query_id(uint64 id, bool force)      optional (enrichment)
//   u/uret   XLogFlush                                          WAL-flush wait
//   u/uret   SyncRepWaitForLSN                                  optional (sync replication)
//   u/uret   ParallelQueryMain                                  parallel workers
//
// The postmaster of a backend or parallel worker is task->real_parent->tgid
// (both are forked by the postmaster). Its BackendState constants come from
// the clusters map, written by userspace per postmaster, so one object serves
// PostgreSQL 16 (RUNNING = 2) and 18 (RUNNING = 3) side by side.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* x86-64 pt_regs layout (see mysql_query.bpf.c for why ctx is cast). */
struct x86_regs {
    __u64 r15, r14, r13, r12, rbp, rbx;
    __u64 r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi;
};

#define TEXT_MAX            512   /* pghash.MaxText + 1 */
#define SESSION_ENTRIES     16384
#define AGG_ENTRIES         16384
#define TEXT_SEEN_ENTRIES   32768
#define UNSAFE_ENTRIES      1024
#define UNSAFE_TEXT_ENTRIES 1024
#define QID_ENTRIES         32768
#define CLUSTER_ENTRIES     64
#define PARALLEL_ENTRIES    4096
#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x100000001b3ULL

enum { KIND_CLIENT = 1, KIND_PARALLEL = 2, KIND_FASTPATH = 3 };
enum { FRAME_NONE = 0, FRAME_WAL = 1, FRAME_SYNCREP = 2 };
enum { TEXT_VERIFY = 1, TEXT_TRUNCATED = 2 };
enum { CNT_DROPPED = 0, CNT_AGG_OVERFLOW = 1, CNT_MAX = 2 };

struct cluster_cfg_t {
    __u32 state_running;
    __u32 state_fastpath;
};

/* One backend's open interval: baselines at open, sums of closed wait frames. */
struct pg_session_t {
    __u64 ts, cpu, runq, rd, wr, blkio;
    __u64 hash;
    __u64 calls;
    __u64 wal, syncrep;
    __u64 fr_ts, fr_cpu, fr_runq, fr_blkio;  /* open XLogFlush / SyncRep frame */
    __u32 postmaster;
    __u8  kind;
    __u8  open;
    __u8  frame;        /* FRAME_* */
    __u8  unsafe_text;  /* unsafe_text[tid] holds this interval's text */
};
_Static_assert(sizeof(struct pg_session_t) == 120, "session layout");

struct agg_key_t {
    __u32 postmaster;
    __u32 kind;
    __u64 hash;         /* 0: no text (fastpath, unreadable text) */
};
struct agg_val_t {
    __u64 calls, wall_ns, wall_max_ns, cpu_ns, runq_ns;
    __u64 disk_read_bytes, disk_write_bytes, io_wait_ns, wal_wait_ns, syncrep_wait_ns;
};
_Static_assert(sizeof(struct agg_key_t) == 16, "agg key layout");
_Static_assert(sizeof(struct agg_val_t) == 80, "agg value layout");

struct text_buf_t {
    __u8 text[TEXT_MAX];
};
struct unsafe_text_t {
    __u32 len;
    __u32 _pad;
    __u8  text[TEXT_MAX];
};
_Static_assert(__builtin_offsetof(struct unsafe_text_t, text) % 8 == 0, "unsafe text alignment");

/* Decoded by hand in events.go: keep offsets in sync. */
struct pg_text_event_t {        /* 528 bytes */
    __u64 hash;                 /*   0 */
    __u32 len;                  /*   8 */
    __u32 flags;                /*  12 TEXT_VERIFY | TEXT_TRUNCATED */
    __u8  text[TEXT_MAX];       /*  16 */
};
struct pg_cmd_event_t {         /* 608 bytes */
    __u32 postmaster, pid, kind, len;           /*  0 .. 15 */
    __u64 hash;                                 /* 16 */
    __u64 calls, wall_ns, cpu_ns, runq_ns;      /* 24 .. 55 */
    __u64 disk_read_bytes, disk_write_bytes;    /* 56 .. 71 */
    __u64 io_wait_ns, wal_wait_ns, syncrep_wait_ns; /* 72 .. 95 */
    __u8  text[TEXT_MAX];                       /* 96 */
};
struct pg_slow_event_t {        /* 64 bytes */
    __u32 postmaster, pid;      /*  0,  4 */
    __u64 hash;                 /*  8 */
    __u64 wall_ns, cpu_ns, runq_ns, io_wait_ns, wal_wait_ns; /* 16 .. 55 */
    __u64 ts_ns;                /* 56 */
};
_Static_assert(sizeof(struct pg_text_event_t) == 528, "text event layout");
_Static_assert(sizeof(struct pg_cmd_event_t) == 608, "cmd event layout");
_Static_assert(sizeof(struct pg_slow_event_t) == 64, "slow event layout");
/* Force BTF emission for bpf2go -type. */
struct agg_key_t *__agg_key_t_unused __attribute__((unused));
struct agg_val_t *__agg_val_t_unused __attribute__((unused));
struct pg_session_t *__pg_session_t_unused __attribute__((unused));
struct cluster_cfg_t *__cluster_cfg_t_unused __attribute__((unused));

struct pg_delta {
    __u64 calls, wall, cpu, runq, rd, wr, iow, wal, syncrep;
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __type(key, __u32); __type(value, struct pg_session_t);
         __uint(max_entries, SESSION_ENTRIES); } pg_session SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __type(key, __u32); __type(value, __u8);
         __uint(max_entries, PARALLEL_ENTRIES); } in_parallel SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct cluster_cfg_t);
         __uint(max_entries, CLUSTER_ENTRIES); } clusters SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, struct text_buf_t);
         __uint(max_entries, 1); } text_scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, struct unsafe_text_t);
         __uint(max_entries, 1); } unsafe_scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __type(key, __u32); __type(value, struct unsafe_text_t);
         __uint(max_entries, UNSAFE_TEXT_ENTRIES); } unsafe_text SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct agg_key_t); __type(value, struct agg_val_t);
         __uint(max_entries, AGG_ENTRIES); } agg_0 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, struct agg_key_t); __type(value, struct agg_val_t);
         __uint(max_entries, AGG_ENTRIES); } agg_1 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __type(key, __u64); __type(value, __u8);
         __uint(max_entries, TEXT_SEEN_ENTRIES); } text_seen SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __type(key, __u64); __type(value, __u8);
         __uint(max_entries, UNSAFE_ENTRIES); } unsafe_hash SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __type(key, __u64); __type(value, __u64);
         __uint(max_entries, QID_ENTRIES); } qid SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } text_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 21); } cmd_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 18); } slow_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, __u64);
         __uint(max_entries, CNT_MAX); } counters SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

const volatile __u64 slow_threshold_ns = 100000000ULL;
/* 1: literal-skipping hash (pghash.KernelHash). 0: plain FNV-1a (verifier fallback). */
const volatile __u8 literal_skip = 1;
/* Written by userspace at every drain (0 or 1). */
volatile __u32 agg_active = 0;

// ─── Task fields (same CO-RE flavors as mysql_query.bpf.c) ───────────────────

struct task_io_accounting___obs {
    __u64 read_bytes;
    __u64 write_bytes;
} __attribute__((preserve_access_index));
struct task_delay_info___obs {
    __u64 blkio_delay;
} __attribute__((preserve_access_index));
struct task_struct___obs {
    struct task_io_accounting___obs ioac;
    struct task_delay_info___obs *delays;
} __attribute__((preserve_access_index));

static __always_inline __u64 task_cpu_ns(struct task_struct *t) { return BPF_CORE_READ(t, se.sum_exec_runtime); }
static __always_inline __u64 task_runq_ns(struct task_struct *t)
{
    if (bpf_core_field_exists(t->sched_info.run_delay))
        return BPF_CORE_READ(t, sched_info.run_delay);
    return 0;
}
static __always_inline void task_io_bytes(struct task_struct *task, __u64 *rd, __u64 *wr)
{
    struct task_struct___obs *t = (void *)task;
    *rd = 0;
    *wr = 0;
    if (bpf_core_field_exists(t->ioac.read_bytes)) {
        *rd = BPF_CORE_READ(t, ioac.read_bytes);
        *wr = BPF_CORE_READ(t, ioac.write_bytes);
    }
}
static __always_inline __u64 task_blkio_ns(struct task_struct *task)
{
    struct task_struct___obs *t = (void *)task;
    if (!bpf_core_field_exists(t->delays))
        return 0;
    struct task_delay_info___obs *d = BPF_CORE_READ(t, delays);
    if (!d)
        return 0;
    return BPF_CORE_READ(d, blkio_delay);
}
static __always_inline __u64 sub0(__u64 now, __u64 start) { return now > start ? now - start : 0; }
static __always_inline __u64 min64(__u64 a, __u64 b) { return a < b ? a : b; }

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        *v += 1; /* per-CPU slot */
}

// ─── Text hash (mirrors internal/postgres/pghash walk; change both together) ──

static __always_inline __u64 fnv1a(__u64 h, __u8 c) { return (h ^ c) * FNV_PRIME; }
static __always_inline int is_digit(__u8 c) { return c >= '0' && c <= '9'; }
static __always_inline int is_ident(__u8 c)
{
    __u8 l = c | 0x20;
    return (l >= 'a' && l <= 'z') || is_digit(c) || c == '_' || c == '$' || c >= 0x80;
}
static __always_inline int dollar_tag_start(__u8 c)
{
    __u8 l = c | 0x20;
    return (l >= 'a' && l <= 'z') || c == '_' || c == '$' || c >= 0x80;
}

enum { ST_CODE, ST_STR, ST_IDENT, ST_BLOCK, ST_LINE, ST_DIGITS, ST_EXACT };

/* text: a NUL-terminated TEXT_MAX-byte map value. Go's prev byte is reduced to
 * the four tests applied to it (prev_ident, prev_star, prev_slash, prev_e);
 * blk = min(i - blockAt, 3). See pghash.walk for the rules. */
static __always_inline __u64 pg_text_hash(const __u8 *text)
{
    __u64 h = FNV_OFFSET, keep = 0, skip = 0;
    __u32 st = ST_CODE;
    __u8 esc = 0, blk = 0, prev_ident = 0, prev_star = 0, prev_slash = 0, prev_e = 0;

    if (!literal_skip) {
        for (__u32 i = 0; i < TEXT_MAX - 1; i++) {
            __u8 c = text[i];
            if (!c)
                break;
            h = fnv1a(h, c);
        }
        return h ? h : 1;
    }
    for (__u32 i = 0; i < TEXT_MAX - 1; i++) {
        __u8 c = text[i];
        if (!c)
            break;
        if (st == ST_EXACT) {
            h = fnv1a(h, c);
            continue;
        }
        __u8 c1 = text[i + 1];  /* i + 1 <= TEXT_MAX - 1: the next byte or the terminator */
        if (st == ST_DIGITS) {
            if (is_digit(c)) {
                keep = fnv1a(keep, c);
                prev_ident = 1;
                prev_star = 0;
                prev_slash = 0;
                prev_e = 0;
                continue;
            }
            h = is_ident(c) ? keep : skip;
            st = ST_CODE;
        }
        if (st == ST_CODE) {
            if (c == '\\') {
                h = fnv1a(h, c);
                st = ST_EXACT;
            } else if (c == '\'' && prev_e) {
                h = fnv1a(h, c);
                st = ST_EXACT;
            } else if (c == '$' && dollar_tag_start(c1)) {
                h = fnv1a(h, c);
                st = ST_EXACT;
            } else if (c == '\'') {
                h = fnv1a(h, c);
                st = ST_STR;
                esc = 0;
            } else if (c == '"') {
                h = fnv1a(h, c);
                st = ST_IDENT;
            } else if (c == '/' && c1 == '*') {
                h = fnv1a(h, c);
                st = ST_BLOCK;
                blk = 0;
            } else if (c == '-' && c1 == '-') {
                h = fnv1a(h, c);
                st = ST_LINE;
            } else if (is_digit(c) && !prev_ident) {
                keep = fnv1a(h, c);
                skip = fnv1a(h, 0);
                st = ST_DIGITS;
            } else {
                h = fnv1a(h, c);
            }
        } else if (st == ST_STR) {
            if (esc) {
                esc = 0;
            } else if (c == '\\') {
                h = fnv1a(h, c);
                st = ST_EXACT;
            } else if (c == '\'' && c1 == '\'') {
                esc = 1;
            } else if (c == '\'') {
                st = ST_CODE;
            }
        } else if (st == ST_IDENT) {
            h = fnv1a(h, c);
            if (c == '"')
                st = ST_CODE;
        } else if (st == ST_BLOCK) {
            h = fnv1a(h, c);
            if (blk < 3)
                blk++;
            if (c == '*' && prev_slash && blk >= 3)
                st = ST_EXACT;
            else if (c == '/' && prev_star && blk >= 3)
                st = ST_CODE;
        } else { /* ST_LINE */
            h = fnv1a(h, c);
            if (c == '\n')
                st = ST_CODE;
        }
        prev_ident = is_ident(c);
        prev_star = c == '*';
        prev_slash = c == '/';
        prev_e = c == 'E' || c == 'e';
    }
    if (st == ST_DIGITS)
        h = skip;
    return h ? h : 1;
}

// ─── Aggregation and events ───────────────────────────────────────────────────

static __always_inline int agg_add_to(void *map, struct agg_key_t *k, const struct pg_delta *d)
{
    struct agg_val_t *v = bpf_map_lookup_elem(map, k);
    if (!v) {
        struct agg_val_t zero = {};
        bpf_map_update_elem(map, k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(map, k);
        if (!v)
            return -1;
    }
    __sync_fetch_and_add(&v->calls, d->calls);
    __sync_fetch_and_add(&v->wall_ns, d->wall);
    __sync_fetch_and_add(&v->cpu_ns, d->cpu);
    __sync_fetch_and_add(&v->runq_ns, d->runq);
    __sync_fetch_and_add(&v->disk_read_bytes, d->rd);
    __sync_fetch_and_add(&v->disk_write_bytes, d->wr);
    __sync_fetch_and_add(&v->io_wait_ns, d->iow);
    __sync_fetch_and_add(&v->wal_wait_ns, d->wal);
    __sync_fetch_and_add(&v->syncrep_wait_ns, d->syncrep);
    if (d->wall > v->wall_max_ns)
        v->wall_max_ns = d->wall; /* best effort: no CAS before 5.12 */
    return 0;
}

static __always_inline int agg_add(struct agg_key_t *k, const struct pg_delta *d)
{
    if (agg_active)
        return agg_add_to(&agg_1, k, d);
    return agg_add_to(&agg_0, k, d);
}

static __always_inline void emit_text(__u64 hash, __u32 len, __u32 flags, const __u8 *text)
{
    struct pg_text_event_t *ev = bpf_ringbuf_reserve(&text_events, sizeof(*ev), 0);
    if (!ev)
        return; /* not marked seen: retried on the next statement */
    ev->hash = hash;
    ev->len = len;
    ev->flags = flags;
    __builtin_memcpy(ev->text, __builtin_assume_aligned(text, 8), sizeof(ev->text));
    bpf_ringbuf_submit(ev, 0);
    if (!(flags & TEXT_VERIFY)) {
        __u8 one = 1;
        bpf_map_update_elem(&text_seen, &hash, &one, BPF_ANY);
    }
}

/* Keeps a copy of an unsafe hash's text for its interval's full event. */
static __always_inline __u8 keep_unsafe_text(__u32 tid, const struct text_buf_t *buf, __u32 len)
{
    __u32 zero = 0;
    struct unsafe_text_t *u = bpf_map_lookup_elem(&unsafe_scratch, &zero);
    if (!u)
        return 0;
    u->len = len;
    u->_pad = 0;
    __builtin_memcpy(u->text, __builtin_assume_aligned(buf->text, 8), sizeof(u->text));
    return bpf_map_update_elem(&unsafe_text, &tid, u, BPF_ANY) == 0;
}

static __always_inline void emit_cmd(struct pg_session_t *s, const struct pg_delta *d, __u32 tid)
{
    struct pg_cmd_event_t *ev = bpf_ringbuf_reserve(&cmd_events, sizeof(*ev), 0);
    if (!ev) {
        bump(CNT_DROPPED);
        if (s->unsafe_text)
            bpf_map_delete_elem(&unsafe_text, &tid);
        return;
    }
    ev->postmaster = s->postmaster;
    ev->pid = tid;
    ev->kind = s->kind;
    ev->len = 0;
    ev->hash = s->hash;
    ev->calls = d->calls;
    ev->wall_ns = d->wall;
    ev->cpu_ns = d->cpu;
    ev->runq_ns = d->runq;
    ev->disk_read_bytes = d->rd;
    ev->disk_write_bytes = d->wr;
    ev->io_wait_ns = d->iow;
    ev->wal_wait_ns = d->wal;
    ev->syncrep_wait_ns = d->syncrep;
    ev->text[0] = 0;
    if (s->unsafe_text) {
        struct unsafe_text_t *u = bpf_map_lookup_elem(&unsafe_text, &tid);
        if (u) {
            ev->len = u->len;
            __builtin_memcpy(ev->text, __builtin_assume_aligned(u->text, 8), sizeof(ev->text));
        }
        bpf_map_delete_elem(&unsafe_text, &tid);
    }
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline void emit_slow(struct pg_session_t *s, const struct pg_delta *d, __u32 tid, __u64 now)
{
    struct pg_slow_event_t *ev = bpf_ringbuf_reserve(&slow_events, sizeof(*ev), 0);
    if (!ev)
        return;
    ev->postmaster = s->postmaster;
    ev->pid = tid;
    ev->hash = s->hash;
    ev->wall_ns = d->wall;
    ev->cpu_ns = d->cpu;
    ev->runq_ns = d->runq;
    ev->io_wait_ns = d->iow;
    ev->wal_wait_ns = d->wal;
    ev->ts_ns = now;
    bpf_ringbuf_submit(ev, 0);
}

/* Closes s: deltas since open, clamped to wall (tick-granular counters). */
static __always_inline void close_session(struct pg_session_t *s, struct task_struct *task, __u32 tid)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 rd, wr;
    struct pg_delta d = {};
    d.calls = s->calls;
    d.wall = sub0(now, s->ts);
    d.cpu = min64(sub0(task_cpu_ns(task), s->cpu), d.wall);
    d.runq = min64(sub0(task_runq_ns(task), s->runq), d.wall);
    task_io_bytes(task, &rd, &wr);
    d.rd = sub0(rd, s->rd);
    d.wr = sub0(wr, s->wr);
    d.iow = min64(sub0(task_blkio_ns(task), s->blkio), d.wall);
    d.wal = min64(s->wal, d.wall);
    d.syncrep = min64(s->syncrep, d.wall);
    s->open = 0;

    struct agg_key_t k = { .postmaster = s->postmaster, .kind = s->kind, .hash = s->hash };
    int full = s->unsafe_text;
    if (!full && agg_add(&k, &d) != 0) {
        full = 1;
        bump(CNT_AGG_OVERFLOW);
    }
    if (full)
        emit_cmd(s, &d, tid);
    if (s->kind == KIND_CLIENT && d.wall >= slow_threshold_ns)
        emit_slow(s, &d, tid, now);
}

// ─── Programs ─────────────────────────────────────────────────────────────────

SEC("uprobe/pgstat_report_activity")
int uprobe_report_activity(struct pt_regs *ctx)
{
    struct x86_regs *regs = (struct x86_regs *)ctx;
    __u32 state = (__u32)regs->rdi;
    const char *cmd = (const char *)regs->rsi;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct pg_session_t *s = bpf_map_lookup_elem(&pg_session, &tid);
    if (s && s->open)
        close_session(s, task, tid);

    __u32 postmaster = BPF_CORE_READ(task, real_parent, tgid);
    struct cluster_cfg_t *cfg = bpf_map_lookup_elem(&clusters, &postmaster);
    if (!cfg)
        return 0; /* not a traced cluster (yet) */
    __u8 kind;
    if (state == cfg->state_running && cmd) {
        kind = bpf_map_lookup_elem(&in_parallel, &tid) ? KIND_PARALLEL : KIND_CLIENT;
    } else if (state == cfg->state_fastpath) {
        kind = KIND_FASTPATH;
        cmd = NULL;
    } else {
        return 0;
    }
    if (!s) {
        struct pg_session_t zero = {};
        bpf_map_update_elem(&pg_session, &tid, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&pg_session, &tid);
        if (!s)
            return 0;
    }

    __u64 hash = 0;
    __u8 unsafe = 0;
    if (cmd) {
        __u32 zero = 0;
        struct text_buf_t *buf = bpf_map_lookup_elem(&text_scratch, &zero);
        if (buf) {
            long n = bpf_probe_read_user_str(buf->text, sizeof(buf->text), cmd);
            if (n > 1) {
                __u32 len = (__u32)n - 1;
                __u32 flags = n >= TEXT_MAX ? TEXT_TRUNCATED : 0;
                hash = pg_text_hash(buf->text);
                if (bpf_map_lookup_elem(&unsafe_hash, &hash)) {
                    keep_unsafe_text(tid, buf, len);
                    unsafe = 1;
                } else if (!bpf_map_lookup_elem(&text_seen, &hash)) {
                    emit_text(hash, len, flags, buf->text);
                } else if ((bpf_get_prandom_u32() & 1023) == 0) {
                    emit_text(hash, len, flags | TEXT_VERIFY, buf->text);
                }
            }
        }
    }
    s->ts = bpf_ktime_get_ns();
    s->cpu = task_cpu_ns(task);
    s->runq = task_runq_ns(task);
    task_io_bytes(task, &s->rd, &s->wr);
    s->blkio = task_blkio_ns(task);
    s->hash = hash;
    s->calls = 0;
    s->wal = 0;
    s->syncrep = 0;
    s->frame = FRAME_NONE;
    s->postmaster = postmaster;
    s->kind = kind;
    s->unsafe_text = unsafe;
    s->open = 1;
    return 0;
}

SEC("uprobe/PortalRun")
int uprobe_portal_run(struct pt_regs *ctx)
{
    if (!(((struct x86_regs *)ctx)->rdx & 0xff)) /* bool isTopLevel */
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pg_session_t *s = bpf_map_lookup_elem(&pg_session, &tid);
    if (s && s->open)
        s->calls++;
    return 0;
}

SEC("uprobe/pgstat_report_query_id")
int uprobe_query_id(struct pt_regs *ctx)
{
    __u64 id = ((struct x86_regs *)ctx)->rdi;
    if (!id)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pg_session_t *s = bpf_map_lookup_elem(&pg_session, &tid);
    if (!s || !s->open || !s->hash)
        return 0;
    __u64 key = s->hash;
    __u64 *old = bpf_map_lookup_elem(&qid, &key);
    if (!old || *old != id)
        bpf_map_update_elem(&qid, &key, &id, BPF_ANY);
    return 0;
}

static __always_inline int frame_enter(__u8 kind)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pg_session_t *s = bpf_map_lookup_elem(&pg_session, &tid);
    if (!s || !s->open || s->frame)
        return 0; /* outermost frame inside an open interval only */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    s->fr_cpu = task_cpu_ns(task);
    s->fr_runq = task_runq_ns(task);
    s->fr_blkio = task_blkio_ns(task);
    s->fr_ts = bpf_ktime_get_ns();
    s->frame = kind;
    return 0;
}

static __always_inline int frame_exit(__u8 kind)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pg_session_t *s = bpf_map_lookup_elem(&pg_session, &tid);
    if (!s || s->frame != kind)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 wall = sub0(bpf_ktime_get_ns(), s->fr_ts);
    __u64 busy = sub0(task_cpu_ns(task), s->fr_cpu) + sub0(task_runq_ns(task), s->fr_runq) +
                 sub0(task_blkio_ns(task), s->fr_blkio);
    if (wall > busy) {
        if (kind == FRAME_WAL)
            s->wal += wall - busy;
        else
            s->syncrep += wall - busy;
    }
    s->frame = FRAME_NONE;
    return 0;
}

SEC("uprobe/XLogFlush")
int uprobe_xlog_flush(struct pt_regs *ctx) { return frame_enter(FRAME_WAL); }
SEC("uretprobe/XLogFlush")
int uretprobe_xlog_flush(struct pt_regs *ctx) { return frame_exit(FRAME_WAL); }
SEC("uprobe/SyncRepWaitForLSN")
int uprobe_sync_rep(struct pt_regs *ctx) { return frame_enter(FRAME_SYNCREP); }
SEC("uretprobe/SyncRepWaitForLSN")
int uretprobe_sync_rep(struct pt_regs *ctx) { return frame_exit(FRAME_SYNCREP); }

SEC("uprobe/ParallelQueryMain")
int uprobe_parallel_main(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u8 one = 1;
    bpf_map_update_elem(&in_parallel, &tid, &one, BPF_ANY);
    return 0;
}

SEC("uretprobe/ParallelQueryMain")
int uretprobe_parallel_main(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct pg_session_t *s = bpf_map_lookup_elem(&pg_session, &tid);
    if (s && s->open)
        close_session(s, (struct task_struct *)bpf_get_current_task(), tid);
    bpf_map_delete_elem(&in_parallel, &tid);
    bpf_map_delete_elem(&pg_session, &tid); /* the worker exits next */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
