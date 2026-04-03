//go:build ignore
// Compiled by bpf2go.

// tcp_retransmit: enriched TCP observability.
//
// Programs:
//   tp_btf/tcp_retransmit_skb  – per-retransmit event with RTT, cwnd, queues,
//                                 flow duration and cumulative retransmit count.
//   tp_btf/tcp_set_state       – tracks connection start time (ESTABLISHED)
//                                 and cleans up on close, so duration_ms is accurate.
//   tp_btf/kfree_skb           – packet drop events with src/dst IP and
//                                 drop location (kernel address).
//
// Requires kernel >= 5.4 with BTF enabled (CONFIG_DEBUG_INFO_BTF=y).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define AF_INET       2
#define AF_INET6      10

/* TCP state constants (mirrors include/net/tcp_states.h). */
#define TCP_ESTABLISHED  1
#define TCP_FIN_WAIT1    4
#define TCP_CLOSE        7

/* ETH_P_IP / ETH_P_IPV6 in network byte order. */
#define ETH_P_IP_NBO   bpf_htons(0x0800)
#define ETH_P_IPV6_NBO bpf_htons(0x86DD)

/* ─── Flow tracking key/value ─────────────────────────────────────────────── */

/* Key identifying a TCP flow (bidirectional). */
struct flow_key {
    __u8  saddr[16];   /* IPv4: first 4 bytes used */
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u16 af;
    __u8  _pad[2];
};

/* Per-flow state stored in the kernel-side BPF map. */
struct flow_state {
    __u64 start_ns;     /* ktime_get_ns() when ESTABLISHED; 0 = unknown */
    __u32 retransmits;  /* cumulative retransmit count for this flow */
    __u8  _pad[4];
};

/* ─── Event structs ───────────────────────────────────────────────────────── */

/*
 * retransmit_event – emitted for every TCP retransmit.
 * Enriched with RTT, congestion window, byte counters,
 * socket queue sizes, and per-flow duration.
 */
struct retransmit_event {
    /* Connection identity */
    __u32 pid;
    __u16 af;
    __u16 sport;
    __u16 dport;
    __u8  tcp_state;   /* TCP_ESTABLISHED, TCP_CLOSE_WAIT, … */
    __u8  _pad1[1];
    __u8  saddr[16];
    __u8  daddr[16];

    /* RTT from tcp_sock (kernel stores srtt_us << 3, mdev_us << 2). */
    __u32 rtt_us;
    __u32 rtt_var_us;

    /* Congestion control */
    __u32 snd_cwnd;
    __u32 snd_ssthresh;

    /* Byte counters from tcp_sock */
    __u64 bytes_sent;
    __u64 bytes_recv;

    /* Socket queue depths */
    __u32 send_queue_bytes;  /* sk_wmem_queued  – bytes in send buffer */
    __u32 recv_queue_bytes;  /* sk_rmem_alloc   – bytes in recv buffer */
    __u32 sk_backlog;        /* sk_backlog.len  – backlog queue depth  */
    __u32 _pad2;

    /* Flow context */
    __u32 retransmit_count;  /* cumulative retransmits on this flow */
    __u32 _pad3;
    __u64 duration_ms;       /* ms since ESTABLISHED (0 if unknown)   */

    char  comm[TASK_COMM_LEN];
};

/* Force BTF emission so bpf2go -type can export this struct. */
struct retransmit_event *__retransmit_event_unused __attribute__((unused));

/*
 * drop_event – emitted by kfree_skb for dropped TCP/IP packets.
 * drop_reason is 0 (unknown) on kernels < 5.17.
 * location is the raw kernel address of the drop site.
 */
struct drop_event {
    __u32 pid;
    __u32 drop_reason;  /* enum skb_drop_reason; 0 = unknown / not available */
    __u64 location;     /* kaddr of the call site – symbolise in userspace    */
    __u16 af;
    __u16 sport;
    __u16 dport;
    __u8  _pad[2];
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[TASK_COMM_LEN];
};

struct drop_event *__drop_event_unused __attribute__((unused));

/* ─── Maps ────────────────────────────────────────────────────────────────── */

/* Ring buffer for retransmit events → consumed by loader.go:consume(). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17); /* 128 KB */
} events SEC(".maps");

/* Ring buffer for drop events → consumed by loader.go:consumeDrops(). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); /* 64 KB */
} drop_events SEC(".maps");

/* Per-flow tracking (LRU evicts oldest entries under memory pressure). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   struct flow_key);
    __type(value, struct flow_state);
    __uint(max_entries, 8192);
} flows SEC(".maps");

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void
fill_flow_key(struct flow_key *k, const struct sock *sk)
{
    k->af    = BPF_CORE_READ(sk, __sk_common.skc_family);
    k->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    k->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (k->af == AF_INET) {
        BPF_CORE_READ_INTO(&k->saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&k->daddr, sk, __sk_common.skc_daddr);
    } else if (k->af == AF_INET6) {
        BPF_CORE_READ_INTO(k->saddr, sk,
            __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(k->daddr, sk,
            __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
}

/* ─── Program 1: enriched retransmit ─────────────────────────────────────── */

SEC("tp_btf/tcp_retransmit_skb")
int handle_tcp_retransmit(u64 *ctx)
{
    struct sock     *sk = (struct sock *)ctx[0];
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    /* Build flow key and look up per-flow state. */
    struct flow_key fk = {};
    fill_flow_key(&fk, sk);

    __u64 duration_ms    = 0;
    __u32 retransmit_cnt = 0;

    struct flow_state *fs = bpf_map_lookup_elem(&flows, &fk);
    if (fs) {
        __u64 now = bpf_ktime_get_ns();
        if (fs->start_ns > 0)
            duration_ms = (now - fs->start_ns) / 1000000ULL;
        __sync_fetch_and_add(&fs->retransmits, 1);
        retransmit_cnt = fs->retransmits;
    } else {
        /* Missed tcp_set_state ESTABLISHED – create entry now. */
        struct flow_state nfs = { .start_ns = 0, .retransmits = 1 };
        bpf_map_update_elem(&flows, &fk, &nfs, BPF_NOEXIST);
        retransmit_cnt = 1;
    }

    struct retransmit_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid       = bpf_get_current_pid_tgid() & 0xffffffff;
    ev->af        = fk.af;
    ev->sport     = fk.sport;
    ev->dport     = fk.dport;
    ev->tcp_state = BPF_CORE_READ(sk, __sk_common.skc_state);
    __builtin_memcpy(ev->saddr, fk.saddr, 16);
    __builtin_memcpy(ev->daddr, fk.daddr, 16);

    /* RTT: kernel keeps srtt_us shifted left 3, mdev_us shifted left 2. */
    ev->rtt_us      = BPF_CORE_READ(tp, srtt_us) >> 3;
    ev->rtt_var_us  = BPF_CORE_READ(tp, mdev_us) >> 2;
    ev->snd_cwnd    = BPF_CORE_READ(tp, snd_cwnd);
    ev->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    ev->bytes_sent  = BPF_CORE_READ(tp, bytes_sent);
    ev->bytes_recv  = BPF_CORE_READ(tp, bytes_received);

    /* Queue depths from struct sock. */
    ev->send_queue_bytes = (__u32)BPF_CORE_READ(sk, sk_wmem_queued);
    /* In kernel 6.x sk_rmem_alloc was moved inside sk_backlog.rmem_alloc. */
    ev->recv_queue_bytes = (__u32)BPF_CORE_READ(sk, sk_backlog.rmem_alloc.counter);
    ev->sk_backlog       = (__u32)BPF_CORE_READ(sk, sk_backlog.len);

    ev->retransmit_count = retransmit_cnt;
    ev->duration_ms      = duration_ms;

    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ─── Program 2: connection state tracking ───────────────────────────────── */

/*
 * tcp_set_state is a kernel function, not a raw tracepoint, so we use
 * fentry (kernel >= 5.5, BTF required) instead of tp_btf.
 * BPF_PROG gives us typed args directly without the u64 *ctx dance.
 */
SEC("fentry/tcp_set_state")
int BPF_PROG(handle_tcp_set_state, struct sock *sk, int newstate)
{
    struct flow_key fk = {};
    fill_flow_key(&fk, sk);

    if (newstate == TCP_ESTABLISHED) {
        /* Record connection start time for duration calculation. */
        struct flow_state fs = {
            .start_ns    = bpf_ktime_get_ns(),
            .retransmits = 0,
        };
        bpf_map_update_elem(&flows, &fk, &fs, BPF_ANY);
    } else if (newstate >= TCP_FIN_WAIT1) {
        /* Connection is closing – free the map entry. */
        bpf_map_delete_elem(&flows, &fk);
    }
    return 0;
}

/* ─── Program 3: packet drop events ─────────────────────────────────────── */

/*
 * Use BPF_PROG with typed arguments so the verifier uses BTF-typed access
 * to enum skb_drop_reason (ctx[2]).  The raw u64 *ctx approach can miss the
 * enum value on some verifier versions.  Pre-5.17 kernels lack the third
 * argument entirely; the loader detects the load failure and disables drop
 * event collection gracefully.
 */
SEC("tp_btf/kfree_skb")
int BPF_PROG(handle_kfree_skb, struct sk_buff *skb, void *location,
             enum skb_drop_reason reason)
{
    __u32 drop_reason = (__u32)reason;
    __u64 loc         = (__u64)(unsigned long)location;

    /* Filter: only track IP (TCP/UDP) drops. */
    __u16 protocol = BPF_CORE_READ(skb, protocol);
    if (protocol != ETH_P_IP_NBO && protocol != ETH_P_IPV6_NBO)
        return 0;

    struct drop_event *ev =
        bpf_ringbuf_reserve(&drop_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid         = bpf_get_current_pid_tgid() & 0xffffffff;
    ev->drop_reason = drop_reason;
    ev->location    = loc;
    ev->sport       = 0;
    ev->dport       = 0;
    __builtin_memset(ev->saddr, 0, 16);
    __builtin_memset(ev->daddr, 0, 16);

    /*
     * Strategy 1: read addresses from the socket attached to the skb.
     * skb->sk is set for locally-originated and locally-destined packets and
     * gives canonical connection endpoints regardless of network-header state.
     */
    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (sk) {
        __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        ev->af    = family;
        /* skc_num = local port (host byte order); skc_dport = remote (network). */
        ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (family == AF_INET) {
            __u32 saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            __u32 daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            __builtin_memcpy(ev->saddr, &saddr4, 4);
            __builtin_memcpy(ev->daddr, &daddr4, 4);
        } else if (family == AF_INET6) {
            BPF_CORE_READ_INTO(ev->saddr, sk,
                __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            BPF_CORE_READ_INTO(ev->daddr, sk,
                __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        }
        bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
        bpf_ringbuf_submit(ev, 0);
        return 0;
    }

    /*
     * Strategy 2: parse network header from packet buffer.
     * Used for forwarded / pre-socket drops where skb->sk is NULL.
     * Guard against network_header == 0 (not yet populated at drop point).
     */
    __u16 nh_off = BPF_CORE_READ(skb, network_header);
    if (nh_off == 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    void *head = BPF_CORE_READ(skb, head);

    if (protocol == ETH_P_IP_NBO) {
        ev->af = AF_INET;
        struct iphdr iph;
        if (bpf_probe_read_kernel(&iph, sizeof(iph), head + nh_off) < 0) {
            bpf_ringbuf_discard(ev, 0);
            return 0;
        }
        __builtin_memcpy(ev->saddr, &iph.saddr, 4);
        __builtin_memcpy(ev->daddr, &iph.daddr, 4);

        /* Best-effort TCP/UDP port extraction. */
        if (iph.protocol == 6 || iph.protocol == 17) {
            __u32 th_off = nh_off + ((__u32)iph.ihl * 4);
            struct tcphdr th;
            bpf_probe_read_kernel(&th, 4, head + th_off); /* first 4 B only */
            ev->sport = bpf_ntohs(th.source);
            ev->dport = bpf_ntohs(th.dest);
        }
    } else {
        ev->af = AF_INET6;
        struct ipv6hdr ip6h;
        if (bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + nh_off) < 0) {
            bpf_ringbuf_discard(ev, 0);
            return 0;
        }
        __builtin_memcpy(ev->saddr, &ip6h.saddr, 16);
        __builtin_memcpy(ev->daddr, &ip6h.daddr, 16);

        if (ip6h.nexthdr == 6 || ip6h.nexthdr == 17) {
            __u32 th_off = nh_off + sizeof(struct ipv6hdr);
            struct tcphdr th;
            bpf_probe_read_kernel(&th, 4, head + th_off);
            ev->sport = bpf_ntohs(th.source);
            ev->dport = bpf_ntohs(th.dest);
        }
    }

    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
