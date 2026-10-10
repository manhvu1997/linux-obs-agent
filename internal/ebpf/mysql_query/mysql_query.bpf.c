//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// mysql_query.bpf.c – MySQL slow-query latency tracer (server-side).
//
// Design goals (production):
//   - Always-on, bounded memory: every map has a fixed size (LRU where entries can leak).
//   - Trace the MySQL SERVER, not the client: attach uprobes to dispatch_command
//     inside the running mysqld binary.
//   - Measure every command; COM_QUERY and COM_STMT_EXECUTE also feed slow
//     events. Per command: wall time, on-CPU time, run-queue wait, result
//     bytes, disk bytes read/written, block-I/O wait and redo (commit) wait,
//     summed in the kernel into agg_<agg_active> keyed by {tgid, command,
//     text hash}. The hash (text_hash, mirroring sqlhash.KernelHash) skips
//     numeric and string literals, so a statement's executions share one
//     entry; its text is sent once on text_events (first sight of a
//     (command, hash), plus a 1/1024 verification resend). Userspace flips
//     agg_active and drains the idle buffer. cmd_events carries a full per-command record only as the
//     fallback (agg_* full, or a hash userspace marked unsafe).
//     With emit_all_queries == 0 only COM_QUERY and COM_STMT_EXECUTE are
//     tracked (legacy behaviour, no aggregation).
//   - Read the SQL query text directly from the COM_DATA argument at function
//     entry — no wire-protocol parsing required, works with TLS connections.
//   - Filter early (in kernel) to reduce overhead: only emit ringbuf events when
//     latency exceeds slow_query_threshold_ns.
//
// Hooks attached (uprobes on mysqld binary):
//   uprobe/dispatch_command   – record start time + query text at entry
//   uretprobe/dispatch_command – compute latency, aggregate, emit if slow
//
// Hooks attached (uprobes, optional — prepared-statement text recovery):
//   uprobe/Prepared_statement::prepare      – remember the SQL text per
//     Prepared_statement* (ps_text)
//   uprobe/Prepared_statement::execute_loop – inside a COM_STMT_EXECUTE,
//     remember which Prepared_statement* this thread executes (ps_exec)
//   The dispatch_command uretprobe then reports COM_STMT_EXECUTE with the
//   recovered text instead of an anonymous placeholder.
//
// Hooks attached (uprobes, optional — commit wait):
//   uprobe/uretprobe InnoDB log_write_up_to – inside a dispatch_command, time
//     the thread spends waiting for the redo log beyond its own CPU, run-queue
//     and block-I/O time (a thread's own fsync is already block-I/O wait).
//
// Hooks attached (kretprobes, optional):
//   kretprobe/tcp_sendmsg, kretprobe/unix_stream_sendmsg – result bytes sent
//     by a thread while it is inside dispatch_command
//
// MySQL dispatch_command signature (MySQL 5.7+ / 8.0, x86-64 SysV ABI):
//   bool dispatch_command(THD *thd, const COM_DATA *com_data,
//                         enum_server_command command)
//   RDI = thd  |  RSI = com_data  |  RDX = command
//
// COM_DATA union for COM_QUERY (command == 3):
//   struct COM_QUERY_DATA {
//     const char *query_str;  // com_data[0..7]  – pointer to SQL text
//     unsigned int length;    // com_data[8..11] – byte length of SQL text
//                             // (4 bytes; 4 bytes of padding follow, may be
//                             // stack garbage – never read them)
//     ...
//   };
//   Since COM_QUERY_DATA is at the start of the COM_DATA union, offset 0 always
//   gives the query_str pointer regardless of which union member is active.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * x86-64 SysV ABI register save frame used by uprobes.
 *
 * Defined locally to avoid depending on vmlinux.h's struct pt_regs, which
 * is generated from the *running* kernel's BTF.  On ARM64 hosts (e.g. macOS
 * Apple Silicon running Docker), vmlinux.h contains the ARM64 pt_regs layout
 * and has no x86-64 register field names (rdx, rsi, rdi, …).
 *
 * Casting ctx to struct x86_regs * is safe: for uprobe programs the kernel
 * always passes an x86-64 register save area regardless of where bpf2go is
 * run from.  The BPF verifier treats the cast as reading at fixed offsets
 * from the ctx pointer, which is permitted for kprobe/uprobe programs.
 *
 * Layout matches arch/x86/include/asm/ptrace.h (pt_regs, kernel push order):
 *   PUSH r15, r14, r13, r12, rbp, rbx → callee-saved
 *   PUSH r11, r10, r9, r8             → caller-saved (scratch)
 *   PUSH rax, rcx, rdx, rsi, rdi     → arg regs + rax
 * (orig_rax, rip, cs, eflags, rsp, ss follow but are not needed here)
 */
struct x86_regs {
    __u64 r15, r14, r13, r12, rbp, rbx;
    __u64 r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi;
};

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN    16
#define QUERY_MAX       512   /* must equal cmdmap.QueryMax in Go            */
#define MAX_ENTRIES     8192  /* in-flight commands ≤ mysqld worker threads   */
#define COM_QUERY 3
#define COM_STMT_PREPARE 22
#define COM_STMT_EXECUTE 23
#define PS_TEXT_ENTRIES 16384 /* live prepared statements across all sessions */
#define AGG_ENTRIES       16384
#define TEXT_SEEN_ENTRIES 32768
#define UNSAFE_ENTRIES    1024
#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x100000001b3ULL

// ─── Value structs ────────────────────────────────────────────────────────────

/* In-flight command state, keyed by TID. 640 bytes: built in pending_scratch
 * because it does not fit the 512-byte BPF stack. */
struct mysql_pending_t {
    __u64 start_ts;
    __u64 cpu_start;    /* task->se.sum_exec_runtime at entry  */
    __u64 rq_start;     /* task->sched_info.run_delay at entry */
    __u64 bytes_out;    /* tcp/unix sendmsg bytes during call  */
    __u64 hash;         /* text_hash(query) for COM_QUERY / COM_STMT_PREPARE */
    __u64 rd_start;     /* task->ioac.read_bytes at entry      */
    __u64 wr_start;     /* task->ioac.write_bytes at entry     */
    __u64 blkio_start;  /* task->delays->blkio_delay at entry  */
    __u64 redo_ts;      /* open log_write_up_to frame: entry ts, 0 = none */
    __u64 redo_cpu;
    __u64 redo_rq;
    __u64 redo_blkio;
    __u64 redo_wait;    /* Σ commit wait over closed frames    */
    __u32 command;
    __u32 query_len;
    __u8  query[QUERY_MAX];
    __u8  comm[TASK_COMM_LEN];
};
_Static_assert(sizeof(struct mysql_pending_t) == 640, "pending layout");
_Static_assert(__builtin_offsetof(struct mysql_pending_t, query) % 8 == 0, "query alignment");

struct mysql_slow_event_t {
    __u32 pid;
    __u32 tid;
    __u64 latency_ns;
    __u64 timestamp_ns;
    __u8  comm[TASK_COMM_LEN];
    __u8  query[QUERY_MAX];
    __u32 command;      /* COM_QUERY or COM_STMT_EXECUTE: lets userspace
                         * label an execute whose text was not recovered */
    __u32 _pad;
};
_Static_assert(sizeof(struct mysql_slow_event_t) == 560, "slow event layout");
struct mysql_slow_event_t *__mysql_slow_event_t_unused __attribute__((unused));

/* One record per dispatch_command call. Layout is decoded by hand in
 * loader.go (decodeCmdEvent) — keep offsets in sync: 608 bytes, no padding. */
struct mysql_cmd_event_t {
    __u32 pid;              /*   0 */
    __u32 tid;              /*   4 */
    __u32 command;          /*   8 */
    __u32 query_len;        /*  12 */
    __u64 wall_ns;          /*  16 */
    __u64 cpu_ns;           /*  24 */
    __u64 runq_ns;          /*  32 */
    __u64 bytes_out;        /*  40 */
    __u64 disk_read_bytes;  /*  48 */
    __u64 disk_write_bytes; /*  56 */
    __u64 io_wait_ns;       /*  64 */
    __u64 redo_wait_ns;     /*  72 */
    __u8  comm[TASK_COMM_LEN];  /* 80 */
    __u8  query[QUERY_MAX];     /* 96 */
};
_Static_assert(sizeof(struct mysql_cmd_event_t) == 608, "cmd event layout");
/* Force BTF emission for bpf2go -type. */
struct mysql_cmd_event_t *__mysql_cmd_event_t_unused __attribute__((unused));

/* SQL text of one prepared statement, keyed by its Prepared_statement*.
 * len = original length (clamped to u32); text is NUL-terminated and holds
 * at most QUERY_MAX-1 bytes; hash = text_hash(text), computed once at
 * prepare time so an execute needs no text pass. 528 bytes: built in
 * ps_scratch, never on the stack. */
struct ps_text_t {
    __u32 len;
    __u32 _pad;
    __u64 hash;
    __u8  text[QUERY_MAX];
};
_Static_assert(sizeof(struct ps_text_t) == 16 + QUERY_MAX, "ps_text layout");
_Static_assert(__builtin_offsetof(struct ps_text_t, text) % 8 == 0, "text alignment");

/* In-kernel aggregation (see internal/mysql/sqlhash/sqlhash.go for the hash rule). */
struct agg_key_t {
    __u32 tgid;
    __u32 command;
    __u64 hash;     /* 0: no text (other commands, execute without text) */
};
struct agg_val_t {
    __u64 calls;
    __u64 wall_ns;
    __u64 wall_max_ns;  /* best effort: concurrent updates may lose a max */
    __u64 cpu_ns;
    __u64 runq_ns;
    __u64 bytes_out;
    __u64 disk_read_bytes;
    __u64 disk_write_bytes;
    __u64 io_wait_ns;
    __u64 redo_wait_ns;
};
struct text_key_t {
    __u64 hash;
    __u32 command;
    __u32 _pad;
};
/* First sight of a (command, hash), or a 1/1024 verification resend. */
struct text_event_t {
    __u64 hash;
    __u32 command;
    __u32 query_len;
    __u32 verify;
    __u32 _pad;
    __u8  query[QUERY_MAX];
};
_Static_assert(sizeof(struct agg_key_t) == 16, "agg key layout");
_Static_assert(sizeof(struct agg_val_t) == 80, "agg value layout");
_Static_assert(sizeof(struct text_key_t) == 16, "text key layout");
_Static_assert(sizeof(struct text_event_t) == 24 + QUERY_MAX, "text event layout");
_Static_assert(__builtin_offsetof(struct text_event_t, query) % 8 == 0, "text event query alignment");
/* Force BTF emission for bpf2go -type. */
struct agg_key_t *__agg_key_t_unused __attribute__((unused));
struct agg_val_t *__agg_val_t_unused __attribute__((unused));
struct text_key_t *__text_key_t_unused __attribute__((unused));
struct text_event_t *__text_event_t_unused __attribute__((unused));

/* One command's measurements (stack, 64 bytes). */
struct cmd_delta {
    __u64 wall, cpu, runq, out, rd, wr, iow, redo;
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

/* In-flight commands keyed by TID; always deleted in the uretprobe. LRU so
 * entries of threads that never returned (killed thread, crashed mysqld)
 * are reclaimed instead of filling the map. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct mysql_pending_t);
    __uint(max_entries, MAX_ENTRIES);
} mysql_pending SEC(".maps");

/* Per-CPU scratch slot: mysql_pending_t (640 B) exceeds the 512-B stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct mysql_pending_t);
    __uint(max_entries, 1);
} pending_scratch SEC(".maps");

/* Prepared_statement* → SQL text. LRU: statements closed by COM_STMT_CLOSE
 * (or freed with their connection) are never explicitly deleted; a reused
 * address is overwritten by its next prepare.
 * Known race: the uretprobe reads text and hash through a map-value pointer;
 * if the entry is evicted and its element reused by a concurrent prepare in
 * that window, an execute can send (or verify-resend) a text that does not
 * match its hash. Userspace then detects the mismatch (verify sample or the
 * first-sight kernel-hash check) and marks the hash unsafe: the cost is that
 * this statement is pinned to the exact (full cmd_events) path. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct ps_text_t);
    __uint(max_entries, PS_TEXT_ENTRIES);
} ps_text SEC(".maps");

/* Per-CPU scratch slot for ps_text_t (528 B > 512-B stack). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ps_text_t);
    __uint(max_entries, 1);
} ps_scratch SEC(".maps");

/* TID → Prepared_statement* executed by the COM_STMT_EXECUTE in flight on
 * that thread. Deleted in the dispatch_command uretprobe for every command. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_ENTRIES);
} ps_exec SEC(".maps");

/* Slow-query outliers (unchanged consumer). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

/* Fallback only: commands that could not be aggregated (agg_* full, or an unsafe hash). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MB */
} cmd_events SEC(".maps");

/* cmd_events reservations that failed (ring buffer full), per CPU. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} dropped SEC(".maps");

/* Two aggregation buffers: programs write agg_<agg_active>; userspace flips
 * agg_active, waits a grace period and drains the other one with no
 * concurrent writer (exact sums, no lookup-and-delete race). Two separate
 * definitions (not one shared anonymous struct type) so each map has its own
 * BTF type, the conservative form for libbpf/cilium-ebpf map parsing. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct agg_key_t);
    __type(value, struct agg_val_t);
    __uint(max_entries, AGG_ENTRIES);
} agg_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct agg_key_t);
    __type(value, struct agg_val_t);
    __uint(max_entries, AGG_ENTRIES);
} agg_1 SEC(".maps");

/* (command, hash) whose text userspace has. LRU: userspace deletes a key
 * when it evicts or never received the text, so the kernel resends it. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct text_key_t);
    __type(value, __u8);
    __uint(max_entries, TEXT_SEEN_ENTRIES);
} text_seen SEC(".maps");

/* Hashes userspace found inconsistent with its digest (verification
 * sample): always processed as full per-command events. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct text_key_t);
    __type(value, __u8);
    __uint(max_entries, UNSAFE_ENTRIES);
} unsafe_hash SEC(".maps");

/* Statement text, once per (command, hash) plus verification resends. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MB */
} text_events SEC(".maps");

/* Commands that fell back to cmd_events because agg_* was full, per CPU. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} agg_overflow SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

const volatile __u64 slow_query_threshold_ns = 100000000ULL;
/* 1: emit cmd_events for every command. 0: legacy behaviour (COM_QUERY and
 * COM_STMT_EXECUTE slow events only). */
const volatile __u8 emit_all_queries = 1;
/* Prepared_statement::prepare argument layout, set from the mangled symbol:
 * 1 = MySQL 8.4 prepare(this, THD*, const char *query, size_t length, ...)
 *     → query = RDX, length = RCX
 * 0 = MySQL 8.0 prepare(this, const char *query, size_t length)
 *     → query = RSI, length = RDX */
const volatile __u8 ps_prepare_has_thd = 1;
/* 1: literal-skipping hash (sqlhash.KernelHash). 0: plain FNV-1a of the text
 * — the fallback if a kernel's verifier rejects the skipping loop. */
const volatile __u8 literal_skip = 1;
/* Written by userspace at every drain (0 or 1). */
volatile __u32 agg_active = 0;

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u64 task_cpu_ns(struct task_struct *t)
{
    return BPF_CORE_READ(t, se.sum_exec_runtime);
}

/* sched_info exists only with CONFIG_SCHED_INFO; report 0 otherwise and let
 * userspace detect "run_delay_unavailable". */
static __always_inline __u64 task_runq_ns(struct task_struct *t)
{
    if (bpf_core_field_exists(t->sched_info.run_delay))
        return BPF_CORE_READ(t, sched_info.run_delay);
    return 0;
}

/* Optional task fields through local CO-RE flavors: the object builds against
 * any vmlinux.h and loads on kernels without CONFIG_TASK_IO_ACCOUNTING or
 * CONFIG_TASK_DELAY_ACCT (fields absent → 0; userspace checks kernel BTF and
 * reports those signals as unavailable instead of 0). */
struct task_io_accounting___obs {
    __u64 read_bytes;   /* bytes this task caused to be read from storage */
    __u64 write_bytes;  /* bytes it caused to be written (dirtied / O_DIRECT) */
} __attribute__((preserve_access_index));
struct task_delay_info___obs {
    __u64 blkio_delay;  /* ns waited for synchronous block I/O */
} __attribute__((preserve_access_index));
struct task_struct___obs {
    struct task_io_accounting___obs ioac;
    struct task_delay_info___obs *delays;
} __attribute__((preserve_access_index));

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

/* 0 when delay accounting is compiled out, or delays was never allocated. */
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

static __always_inline __u64 fnv1a(__u64 h, __u8 c) { return (h ^ c) * FNV_PRIME; }
static __always_inline int is_digit(__u8 c) { return c >= '0' && c <= '9'; }
/* sqldigest's identifier bytes (start or part). */
static __always_inline int is_ident(__u8 c)
{
    __u8 l = c | 0x20;
    return (l >= 'a' && l <= 'z') || is_digit(c) || c == '_' || c == '$' || c == '@' || c >= 0x80;
}
static __always_inline int is_space(__u8 c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

enum { ST_CODE, ST_STR, ST_TICK, ST_BLOCK, ST_LINE, ST_DIGITS };

/* text: a NUL-terminated QUERY_MAX-byte map value (pending.query or
 * ps_text_t.text). Mirrors sqlhash.KernelHash statement for statement
 * (internal/mysql/sqlhash/sqlhash.go is the source of truth; change both
 * together): FNV-1a 64 over at most QUERY_MAX-1 bytes, stopping at NUL,
 * except that a quoted string ('…' / "…") hashes as its opening quote byte
 * only and a digit run at a token boundary hashes as one NUL byte.
 *
 * Reading text[i + 1] / text[i + 2] where Go uses at(b, i+1/2): the text is
 * NUL-terminated within QUERY_MAX bytes, c1 is only read past c != 0 (so it
 * is the next byte or the terminator), and c2 is only consulted when
 * c1 == '-' (so i + 2 is at most the terminator); index QUERY_MAX itself
 * reads as 0. Bytes after the terminator (stale scratch data) are never used.
 *
 * Verifier state budget: i must be exact (it indexes memory), so every other
 * loop-carried value that a branch compares against a known constant becomes
 * precise and splits states. Each one is therefore kept to a few values:
 *   st         ST_CODE..ST_DIGITS (6)
 *   q          0, '\'' or '"'; written on entering ST_STR, read only there
 *   esc        0/1; reset on entering ST_STR, read only there
 *   blk        0..3, saturating: bytes since the comment's '/', i.e. Go's
 *              min(i - blockAt, 3); written on entering ST_BLOCK, read only there
 *   prev_ident 0/1 = is_ident(prev)  } Go's prev byte, reduced to the two
 *   prev_star  0/1 = (prev == '*')   } tests Go applies to it
 * h, keep and skip are unknown scalars (no state split). Same semantics as
 * Go: blk >= 3 <=> i >= blockAt + 3; the flags are updated wherever Go
 * assigns prev (the ST_DIGITS continue and the end of the iteration). */
static __always_inline __u64 text_hash(const __u8 *text)
{
    __u64 h = FNV_OFFSET, keep = 0, skip = 0;
    __u32 st = ST_CODE;
    __u8 q = 0, esc = 0, blk = 0, prev_ident = 0, prev_star = 0;

    if (!literal_skip) {
        for (__u32 i = 0; i < QUERY_MAX - 1; i++) {
            __u8 c = text[i];
            if (!c)
                break;
            h = fnv1a(h, c);
        }
        return h;
    }
    for (__u32 i = 0; i < QUERY_MAX - 1; i++) {
        __u8 c = text[i];
        if (!c)
            break;
        __u8 c1 = text[i + 1];                       /* i + 1 <= QUERY_MAX - 1 */
        __u8 c2 = i + 2 < QUERY_MAX ? text[(i + 2) & (QUERY_MAX - 1)] : 0;
        if (st == ST_DIGITS) {
            if (is_digit(c)) {
                keep = fnv1a(keep, c);
                prev_ident = 1;         /* prev = c: a digit is an ident byte, not '*' */
                prev_star = 0;
                continue;
            }
            h = is_ident(c) ? keep : skip;
            st = ST_CODE;
        }
        if (st == ST_CODE) {
            if (c == '\'' || c == '"') {
                h = fnv1a(h, c);        /* opening quote byte: ' and " must not alias */
                st = ST_STR;
                q = c;
                esc = 0;                /* already 0 here (a string closes only unescaped) */
            } else if (c == '`') {
                h = fnv1a(h, c);
                st = ST_TICK;
            } else if (c == '/' && c1 == '*') {
                h = fnv1a(h, c);
                st = ST_BLOCK;
                blk = 0;                /* Go: blockAt = i */
            } else if (c == '#' || (c == '-' && c1 == '-' && (c2 == 0 || is_space(c2)))) {
                h = fnv1a(h, c);
                st = ST_LINE;
            } else if (is_digit(c) && !prev_ident) {
                keep = fnv1a(h, c);
                skip = fnv1a(h, 0);     /* NUL cannot occur in the clipped text */
                st = ST_DIGITS;
            } else {
                h = fnv1a(h, c);
            }
        } else if (st == ST_STR) {
            if (esc)
                esc = 0;
            else if (c == '\\')
                esc = 1;
            else if (c == q && c1 == q)
                esc = 1;                /* doubled quote: the next byte is part of the string */
            else if (c == q)
                st = ST_CODE;
        } else if (st == ST_TICK) {
            h = fnv1a(h, c);
            if (c == '`')
                st = ST_CODE;
        } else if (st == ST_BLOCK) {
            h = fnv1a(h, c);
            if (blk < 3)
                blk++;                  /* blk = min(i - blockAt, 3) */
            if (c == '/' && prev_star && blk >= 3)
                st = ST_CODE;
        } else { /* ST_LINE */
            h = fnv1a(h, c);
            if (c == '\n')
                st = ST_CODE;
        }
        prev_ident = is_ident(c);       /* prev = c */
        prev_star = c == '*';
    }
    if (st == ST_DIGITS)
        h = skip;
    return h;
}

/* Adds one command to an aggregation map. Returns 0, or -1 when the map is
 * full (the caller falls back to a full cmd_events record). */
static __always_inline int agg_add_to(void *map, struct agg_key_t *k, const struct cmd_delta *d)
{
    struct agg_val_t *v = bpf_map_lookup_elem(map, k);
    if (!v) {
        struct agg_val_t zero = {};
        /* EEXIST: another CPU inserted it first — fine, look it up again. */
        bpf_map_update_elem(map, k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(map, k);
        if (!v)
            return -1;
    }
    __sync_fetch_and_add(&v->calls, 1);
    __sync_fetch_and_add(&v->wall_ns, d->wall);
    __sync_fetch_and_add(&v->cpu_ns, d->cpu);
    __sync_fetch_and_add(&v->runq_ns, d->runq);
    __sync_fetch_and_add(&v->bytes_out, d->out);
    __sync_fetch_and_add(&v->disk_read_bytes, d->rd);
    __sync_fetch_and_add(&v->disk_write_bytes, d->wr);
    __sync_fetch_and_add(&v->io_wait_ns, d->iow);
    __sync_fetch_and_add(&v->redo_wait_ns, d->redo);
    if (d->wall > v->wall_max_ns)
        v->wall_max_ns = d->wall;
    return 0;
}

/* Adds one command to agg_<agg_active>. */
static __always_inline int agg_add(struct agg_key_t *k, const struct cmd_delta *d)
{
    if (agg_active)
        return agg_add_to(&agg_1, k, d);
    return agg_add_to(&agg_0, k, d);
}

/* text: a QUERY_MAX-byte map value at an 8-byte aligned offset. verify = 0
 * marks (command, hash) seen once the event is submitted; verify = 1 is a
 * resend for userspace's hash-vs-digest check and leaves text_seen alone. */
static __always_inline void emit_text(__u64 hash, __u32 command, __u32 len, const __u8 *text, __u32 verify)
{
    struct text_event_t *ev = bpf_ringbuf_reserve(&text_events, sizeof(*ev), 0);
    if (!ev)
        return; /* not marked seen: retried on the next call */
    ev->hash = hash;
    ev->command = command;
    ev->query_len = len;
    ev->verify = verify;
    ev->_pad = 0;
    __builtin_memcpy(ev->query, __builtin_assume_aligned(text, 8), sizeof(ev->query));
    bpf_ringbuf_submit(ev, 0);
    if (!verify) {
        struct text_key_t tk = { .hash = hash, .command = command };
        __u8 one = 1;
        bpf_map_update_elem(&text_seen, &tk, &one, BPF_ANY);
    }
}

// ─── Programs ─────────────────────────────────────────────────────────────────

/*
 * Entry: x86-64 SysV ABI, dispatch_command(THD *thd, const COM_DATA *com_data,
 * enum_server_command command): RSI = com_data, RDX = command. See the
 * struct x86_regs comment for why ctx is cast instead of PT_REGS_PARM*.
 */
SEC("uprobe/dispatch_command")
int uprobe_dispatch_command(struct pt_regs *ctx)
{
    struct x86_regs *regs = (struct x86_regs *)ctx;
    __u32 command = (__u32)regs->rdx;
    /* Legacy mode tracks only the commands that feed slow events. */
    if (!emit_all_queries && command != COM_QUERY && command != COM_STMT_EXECUTE)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct mysql_pending_t *p = bpf_map_lookup_elem(&pending_scratch, &zero);
    if (!p)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    p->start_ts  = bpf_ktime_get_ns();
    p->cpu_start = task_cpu_ns(task);
    p->rq_start  = task_runq_ns(task);
    p->bytes_out = 0;
    task_io_bytes(task, &p->rd_start, &p->wr_start);
    p->blkio_start = task_blkio_ns(task);
    p->redo_ts   = 0;
    p->redo_wait = 0;
    p->command   = command;
    p->query_len = 0;
    p->hash      = 0;
    p->query[0]  = 0;
    bpf_get_current_comm(&p->comm, sizeof(p->comm));

    /* COM_DATA for COM_QUERY (MySQL 5.7 st_com_query_data / 8.0 COM_QUERY_DATA)
     * and COM_STMT_PREPARE (COM_STMT_PREPARE_DATA, same layout):
     * offset 0 = const char *query, offset 8 = unsigned int length (4 bytes;
     * 4 bytes of padding follow and may be stack garbage, so read only 4). */
    void *com_data = (void *)regs->rsi;
    if ((command == COM_QUERY || command == COM_STMT_PREPARE) && com_data) {
        const char *query_str = NULL;
        __u32 len = 0;
        if (bpf_probe_read_user(&query_str, sizeof(query_str), com_data) == 0 && query_str)
            bpf_probe_read_user_str(p->query, sizeof(p->query), query_str);
        if (bpf_probe_read_user(&len, sizeof(len), (char *)com_data + 8) == 0)
            p->query_len = len;
    }
    /* Legacy mode never aggregates: keep the hashing loop out of it. */
    if (emit_all_queries && p->query[0])
        p->hash = text_hash(p->query);
    /* A new command starts: no Prepared_statement from an earlier one may
     * linger and block (BPF_NOEXIST) this command's execute_loop. */
    bpf_map_delete_elem(&ps_exec, &tid);
    /* Copies the scratch value (map-value pointer) into the per-TID entry. */
    bpf_map_update_elem(&mysql_pending, &tid, p, BPF_ANY);
    return 0;
}

/*
 * Prepared_statement::prepare(...): remember the statement text per
 * Prepared_statement* (this = RDI). Runs for COM_STMT_PREPARE, for the
 * re-prepare after a metadata change, and for SQL-level PREPARE; only the
 * COM_STMT_EXECUTE path below ever reads the result.
 */
SEC("uprobe/ps_prepare")
int uprobe_ps_prepare(struct pt_regs *ctx)
{
    struct x86_regs *regs = (struct x86_regs *)ctx;
    __u64 self = regs->rdi;
    /* Load every candidate register at its fixed ctx offset, then select.
     * Without the barriers clang turns "flag ? regs->rdx : regs->rsi" into a
     * load from ctx + variable offset, which the verifier rejects
     * ("dereference of modified ctx ptr"). */
    __u64 rsi = regs->rsi, rdx = regs->rdx, rcx = regs->rcx;
    asm volatile("" : "+r"(rsi), "+r"(rdx), "+r"(rcx));
    const char *query;
    __u64 len;
    if (ps_prepare_has_thd) {
        query = (const char *)rdx;
        len   = rcx;
    } else {
        query = (const char *)rsi;
        len   = rdx;
    }
    if (!self || !query || len == 0)
        return 0;

    __u32 zero = 0;
    struct ps_text_t *t = bpf_map_lookup_elem(&ps_scratch, &zero);
    if (!t)
        return 0;

    __u64 n = len < QUERY_MAX - 1 ? len : QUERY_MAX - 1;
    /* Opaque to clang so the mask below is not folded away as redundant:
     * it is the explicit bound the verifier sees, n ∈ [0, QUERY_MAX-1]. */
    asm volatile("" : "+r"(n));
    n &= QUERY_MAX - 1;
    if (bpf_probe_read_user(t->text, n, query) != 0)
        return 0;
    t->text[n] = 0;
    t->len  = len > 0xffffffffULL ? 0xffffffffU : (__u32)len;
    t->_pad = 0;
    /* Only the aggregation path (emit_all_queries) reads the hash. */
    t->hash = emit_all_queries ? text_hash(t->text) : 0;
    bpf_map_update_elem(&ps_text, &self, t, BPF_ANY);
    return 0;
}

/*
 * Prepared_statement::execute_loop(...): only this (RDI) is used, so any
 * signature works. Recorded only when the thread is inside a COM_STMT_EXECUTE
 * dispatch_command (SQL-level EXECUTE runs under COM_QUERY and keeps the
 * text of the EXECUTE statement itself).
 */
SEC("uprobe/ps_execute_loop")
int uprobe_ps_execute_loop(struct pt_regs *ctx)
{
    __u64 self = ((struct x86_regs *)ctx)->rdi;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!p || p->command != COM_STMT_EXECUTE || !self)
        return 0;
    /* Outermost wins: a prepared CALL whose procedure runs EXECUTE re-enters
     * execute_loop in the same dispatch; the whole command belongs to the
     * statement the client executed. */
    bpf_map_update_elem(&ps_exec, &tid, &self, BPF_NOEXIST);
    return 0;
}

/*
 * InnoDB log_write_up_to(...): only timing is used, so any signature works.
 * Measured only inside a dispatch_command (a mysql_pending entry exists for
 * the thread) and only for the outermost frame. Commit wait is the frame's
 * wall time not spent on a CPU, in the run queue or in block I/O, so it never
 * overlaps those parts: a thread that fsyncs the log itself shows that time
 * as io_wait_ns; one that waits for the log writer thread shows commit wait.
 */
SEC("uprobe/log_write_up_to")
int uprobe_log_write_up_to(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!p || p->redo_ts)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    p->redo_cpu   = task_cpu_ns(task);
    p->redo_rq    = task_runq_ns(task);
    p->redo_blkio = task_blkio_ns(task);
    p->redo_ts    = bpf_ktime_get_ns(); /* last: non-zero opens the frame */
    return 0;
}

SEC("uretprobe/log_write_up_to")
int uretprobe_log_write_up_to(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!p || !p->redo_ts)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 wall = sub0(bpf_ktime_get_ns(), p->redo_ts);
    __u64 busy = sub0(task_cpu_ns(task), p->redo_cpu) + sub0(task_runq_ns(task), p->redo_rq) +
                 sub0(task_blkio_ns(task), p->redo_blkio);
    if (wall > busy)
        p->redo_wait += wall - busy;
    p->redo_ts = 0;
    return 0;
}

/* Result bytes: add the int return of the protocol sendmsg while the calling
 * thread is inside dispatch_command. Hooked at tcp/unix level, not
 * sock_sendmsg, because since 6.6 send()/write() reach the protocol through
 * the static, inlinable __sock_sendmsg. */
static __always_inline int add_bytes_out(struct pt_regs *ctx)
{
    int ret = (int)((struct x86_regs *)ctx)->rax;
    if (ret <= 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (p)
        __sync_fetch_and_add(&p->bytes_out, (__u64)ret);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx) { return add_bytes_out(ctx); }

SEC("kretprobe/unix_stream_sendmsg")
int kretprobe_unix_stream_sendmsg(struct pt_regs *ctx) { return add_bytes_out(ctx); }

/*
 * Return: everything is read through the mysql_pending map-value pointer (no
 * 640-byte local); the entry is deleted on every path after a successful lookup.
 */
SEC("uretprobe/dispatch_command")
int uretprobe_dispatch_command(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid  = (__u32)pid_tgid;

    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!p)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - p->start_ts;
    __u64 cpu_now = task_cpu_ns(task), rq_now = task_runq_ns(task);
    __u64 cpu_ns  = cpu_now > p->cpu_start ? cpu_now - p->cpu_start : 0;
    __u64 runq_ns = rq_now > p->rq_start ? rq_now - p->rq_start : 0;
    /* sum_exec_runtime is tick-granular: keep cpu, runq <= wall. */
    if (cpu_ns > latency_ns)
        cpu_ns = latency_ns;
    if (runq_ns > latency_ns)
        runq_ns = latency_ns;
    __u64 rd_now, wr_now;
    task_io_bytes(task, &rd_now, &wr_now);
    struct cmd_delta d = {
        .wall = latency_ns, .cpu = cpu_ns, .runq = runq_ns, .out = p->bytes_out,
        .rd = sub0(rd_now, p->rd_start), .wr = sub0(wr_now, p->wr_start),
        .iow = sub0(task_blkio_ns(task), p->blkio_start), .redo = p->redo_wait,
    };
    if (d.iow > latency_ns)
        d.iow = latency_ns;
    if (d.redo > latency_ns)
        d.redo = latency_ns;

    /* Statement text: the captured COM_QUERY/COM_STMT_PREPARE text, or for
     * COM_STMT_EXECUTE the text recovered from its Prepared_statement*. Both
     * sources are QUERY_MAX-byte, NUL-terminated map values at 8-byte
     * aligned offsets (pending.query @112, ps_text_t.text @16); the alignment
     * hint at the copies keeps them 8-byte wide instead of byte-by-byte. */
    const __u8 *text = p->query;
    __u32 text_len   = p->query_len;
    /* An execute without recovered text aggregates under hash 0. */
    __u64 hash       = p->command == COM_STMT_EXECUTE ? 0 : p->hash;
    if (p->command == COM_STMT_EXECUTE) {
        __u64 *ps = bpf_map_lookup_elem(&ps_exec, &tid);
        if (ps) {
            __u64 key = *ps;
            struct ps_text_t *t = bpf_map_lookup_elem(&ps_text, &key);
            if (t) {
                text     = t->text;
                text_len = t->len;
                hash     = t->hash;
            }
        }
    }

    if (p->command == COM_QUERY || p->command == COM_STMT_EXECUTE) {
        if (latency_ns >= slow_query_threshold_ns) {
            struct mysql_slow_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
            if (ev) {
                ev->pid = tgid;
                ev->tid = tid;
                ev->latency_ns = latency_ns;
                ev->timestamp_ns = now;
                ev->command = p->command;
                ev->_pad = 0;
                __builtin_memcpy(ev->comm, p->comm, sizeof(ev->comm));
                __builtin_memcpy(ev->query, __builtin_assume_aligned(text, 8), sizeof(ev->query));
                bpf_ringbuf_submit(ev, 0);
            }
        }
    }

    if (emit_all_queries) {
        int full = 1;
        struct text_key_t tk = { .hash = hash, .command = p->command };
        if (!(hash && bpf_map_lookup_elem(&unsafe_hash, &tk))) {
            struct agg_key_t ak = { .tgid = tgid, .command = p->command, .hash = hash };
            if (agg_add(&ak, &d) == 0) {
                full = 0;
                if (hash) {
                    if (!bpf_map_lookup_elem(&text_seen, &tk))
                        emit_text(hash, p->command, text_len, text, 0);
                    else if ((bpf_get_prandom_u32() & 1023) == 0)
                        emit_text(hash, p->command, text_len, text, 1);
                }
            } else {
                __u32 zero = 0;
                __u64 *o = bpf_map_lookup_elem(&agg_overflow, &zero);
                if (o)
                    *o += 1; /* per-CPU slot */
            }
        }
        if (full) {
            struct mysql_cmd_event_t *ev = bpf_ringbuf_reserve(&cmd_events, sizeof(*ev), 0);
            if (ev) {
                ev->pid       = tgid;
                ev->tid       = tid;
                ev->command   = p->command;
                ev->query_len = text_len;
                ev->wall_ns   = latency_ns;
                ev->cpu_ns    = cpu_ns;
                ev->runq_ns   = runq_ns;
                ev->bytes_out        = d.out;
                ev->disk_read_bytes  = d.rd;
                ev->disk_write_bytes = d.wr;
                ev->io_wait_ns       = d.iow;
                ev->redo_wait_ns     = d.redo;
                __builtin_memcpy(ev->comm, p->comm, sizeof(ev->comm));
                __builtin_memcpy(ev->query, __builtin_assume_aligned(text, 8), sizeof(ev->query));
                bpf_ringbuf_submit(ev, 0);
            } else {
                __u32 zero = 0;
                __u64 *d = bpf_map_lookup_elem(&dropped, &zero);
                if (d)
                    *d += 1; /* per-CPU slot: no atomic needed */
            }
        }
    }

    bpf_map_delete_elem(&ps_exec, &tid);
    bpf_map_delete_elem(&mysql_pending, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
