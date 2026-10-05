//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// netflow.bpf.c – always-on per-process TCP flow accounting.
//
// Aggregates bytes and connection counts per
//   {tgid, direction, family, peer IP, service port}
// in an LRU map that userspace reads every few seconds. No ring buffer.
//
// Attribution: several TCP state changes run in softirq where `current` is
// unrelated to the socket. The OWNER is therefore recorded only in
// process-context hooks (connect → SYN_SENT, accept return) and stored per
// socket in sock_meta; bytes are charged to the CURRENT tgid in
// tcp_sendmsg / tcp_cleanup_rbuf, which always run in the reading/writing
// process — so a socket handed from a parent to a forked worker is charged
// to the worker.
//
// service port = local listening port for inbound, remote port for outbound;
// the client's ephemeral port is never a key.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Same x86-64 register frame as mysql_query.bpf.c (see the comment there). */
struct x86_regs {
    __u64 r15, r14, r13, r12, rbp, rbx;
    __u64 r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi;
};

#define AF_INET         2
#define AF_INET6        10
#define PROTO_TCP       6
#define ST_ESTABLISHED  1
#define ST_SYN_SENT     2
#define ST_CLOSE        7
#define DIR_IN          1   /* must equal netflow.Inbound  */
#define DIR_OUT         2   /* must equal netflow.Outbound */

struct flow_key {
    __u32 tgid;
    __u8  dir;
    __u8  family;
    __u16 svc_port;   /* host byte order */
    __u8  peer[16];   /* IPv4 stored v4-mapped (::ffff:a.b.c.d) */
};

struct flow_val {
    __u64 bytes_tx;
    __u64 bytes_rx;
    __u64 opened;
    __u64 closed;
    __u64 last_seen_ns;
};

struct sock_meta {
    struct flow_key k;  /* k.tgid = owner recorded at connect/accept */
    __u8 established;
    __u8 ignored;       /* loopback while include_loopback == 0 */
    __u8 _pad[6];
};

struct flow_key *__flow_key_unused __attribute__((unused));
struct flow_val *__flow_val_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);               /* struct sock * */
    __type(value, struct sock_meta);
    __uint(max_entries, 65536);
} sock_meta SEC(".maps");

/* LRU, not HASH: a kretprobe can be missed (maxactive exhausted) or a thread
 * can exit inside tcp_sendmsg, and a plain HASH would then keep the stale
 * entry forever and eventually reject new ones. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);               /* tid */
    __type(value, __u64);             /* struct sock * passed to tcp_sendmsg */
    __uint(max_entries, 16384);
} send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 16384);
} flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);               /* local listening port, host order */
    __type(value, __u8);
    __uint(max_entries, 4096);
} listen_ports SEC(".maps");

const volatile __u8 include_loopback = 1;

static __always_inline int is_loopback(const __u8 *p)
{
    int zero10 = 1;
#pragma unroll
    for (int i = 0; i < 10; i++)
        if (p[i])
            zero10 = 0;
    if (!zero10)
        return 0;
    if (p[10] == 0xff && p[11] == 0xff && p[12] == 127)
        return 1;                                         /* 127.0.0.0/8 */
    return p[10] == 0 && p[11] == 0 && p[12] == 0 && p[13] == 0 &&
           p[14] == 0 && p[15] == 1;                       /* ::1 */
}

static __always_inline void set_v4(__u8 *peer, const void *addr4)
{
    __builtin_memset(peer, 0, 16);
    peer[10] = 0xff;
    peer[11] = 0xff;
    __builtin_memcpy(&peer[12], addr4, 4);
}

static __always_inline int fill_from_sk(struct sock *sk, struct flow_key *k, __u8 dir)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        __be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        set_v4(k->peer, &d);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&k->peer, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    } else {
        return -1;
    }
    k->family = (__u8)family;
    k->dir = dir;
    if (dir == DIR_IN)
        k->svc_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    else
        k->svc_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    return 0;
}

static __always_inline void bump(const struct flow_key *k, __u64 tx, __u64 rx, __u64 op, __u64 cl)
{
    struct flow_val *v = bpf_map_lookup_elem(&flow_stats, k);
    if (!v) {
        struct flow_val zero = {};
        bpf_map_update_elem(&flow_stats, k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&flow_stats, k);
        if (!v)
            return;
    }
    if (tx)
        __sync_fetch_and_add(&v->bytes_tx, tx);
    if (rx)
        __sync_fetch_and_add(&v->bytes_rx, rx);
    if (op)
        __sync_fetch_and_add(&v->opened, op);
    if (cl)
        __sync_fetch_and_add(&v->closed, cl);
    v->last_seen_ns = bpf_ktime_get_ns();
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != PROTO_TCP)
        return 0;
    __u64 skp = (__u64)ctx->skaddr;
    int os = ctx->oldstate, ns = ctx->newstate;

    if (os == ST_CLOSE && ns == ST_SYN_SENT) {     /* connect(): process context */
        struct sock_meta m = {};
        m.k.tgid = bpf_get_current_pid_tgid() >> 32;
        m.k.dir = DIR_OUT;
        m.k.family = (__u8)ctx->family;
        m.k.svc_port = ctx->dport;   /* already host order: TP does ntohs(inet_dport) */
        /* Copy the address arrays with bpf_probe_read_kernel (as libbpf-tools
         * tcpstates does) instead of direct ctx loads: the verifier requires
         * size-aligned tracepoint ctx accesses, and a multi-byte memcpy from a
         * CO-RE-relocated __u8[] gives no alignment guarantee. */
        if (ctx->family == AF_INET) {
            m.k.peer[10] = 0xff;
            m.k.peer[11] = 0xff;
            bpf_probe_read_kernel(&m.k.peer[12], 4, ctx->daddr);
        } else {
            bpf_probe_read_kernel(m.k.peer, 16, ctx->daddr_v6);
        }
        m.ignored = !include_loopback && is_loopback(m.k.peer);
        bpf_map_update_elem(&sock_meta, &skp, &m, BPF_ANY);
        return 0;
    }

    struct sock_meta *m = bpf_map_lookup_elem(&sock_meta, &skp);
    if (!m)
        return 0;
    if (os == ST_SYN_SENT && ns == ST_ESTABLISHED) {
        m->established = 1;
        if (!m->ignored)
            bump(&m->k, 0, 0, 1, 0);
    } else if (ns == ST_CLOSE) {
        if (m->established && !m->ignored)
            bump(&m->k, 0, 0, 0, 1);
        bpf_map_delete_elem(&sock_meta, &skp);
    }
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)((struct x86_regs *)ctx)->rax;
    if (!sk)
        return 0;
    struct sock_meta m = {};
    if (fill_from_sk(sk, &m.k, DIR_IN) < 0)
        return 0;
    m.k.tgid = bpf_get_current_pid_tgid() >> 32;
    m.established = 1;
    m.ignored = !include_loopback && is_loopback(m.k.peer);
    __u64 skp = (__u64)sk;
    bpf_map_update_elem(&sock_meta, &skp, &m, BPF_ANY);
    if (!m.ignored)
        bump(&m.k, 0, 0, 1, 0);
    return 0;
}

/* account charges bytes to the current tgid. Sockets with no sock_meta
 * (open before the agent started, or accept hook unavailable) are adopted
 * lazily: direction comes from listen_ports, filled by userspace.
 *
 * A socket already in TCP_CLOSE is never adopted: its sock_meta was deleted
 * at the ->CLOSE transition (e.g. FIN_WAIT2 -> tcp_time_wait -> tcp_done, or
 * an RST) while the application may still be reading queued data. Adopting
 * it would count an `opened` with no matching `closed`, and leave an entry no
 * later CLOSE deletes - which a new socket reusing the same `sk` address
 * would then inherit. Those trailing bytes are charged without adoption. */
static __always_inline void account(struct sock *sk, __u64 tx, __u64 rx)
{
    __u64 skp = (__u64)sk;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct sock_meta *m = bpf_map_lookup_elem(&sock_meta, &skp);
    if (!m) {
        __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        __u8 dir = bpf_map_lookup_elem(&listen_ports, &lport) ? DIR_IN : DIR_OUT;
        struct sock_meta nm = {};
        if (fill_from_sk(sk, &nm.k, dir) < 0)
            return;
        nm.k.tgid = tgid;
        nm.established = 1;
        nm.ignored = !include_loopback && is_loopback(nm.k.peer);

        __u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
        if (state == ST_CLOSE) {
            if (!nm.ignored)
                bump(&nm.k, tx, rx, 0, 0);
            return;
        }

        /* Only the CPU whose insert wins counts the adoption as opened; a
         * concurrent adopter loses BPF_NOEXIST and just uses the entry. */
        int won = bpf_map_update_elem(&sock_meta, &skp, &nm, BPF_NOEXIST) == 0;
        m = bpf_map_lookup_elem(&sock_meta, &skp);
        if (!m)
            return;
        if (won && !m->ignored)
            bump(&m->k, 0, 0, 1, 0);   /* adopted counts as opened */
    }
    if (m->ignored)
        return;
    struct flow_key k = m->k;
    k.tgid = tgid;
    bump(&k, tx, rx, 0, 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 sk = ((struct x86_regs *)ctx)->rdi;
    bpf_map_update_elem(&send_args, &tid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *skp = bpf_map_lookup_elem(&send_args, &tid);
    if (!skp)
        return 0;
    struct sock *sk = (struct sock *)*skp;
    bpf_map_delete_elem(&send_args, &tid);
    int ret = (int)((struct x86_regs *)ctx)->rax;   /* int return: never read as long */
    if (ret > 0)
        account(sk, (__u64)ret, 0);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
    struct x86_regs *r = (struct x86_regs *)ctx;
    int copied = (int)r->rsi;
    if (copied <= 0)
        return 0;
    account((struct sock *)r->rdi, 0, (__u64)copied);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
