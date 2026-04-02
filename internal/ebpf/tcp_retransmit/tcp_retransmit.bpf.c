//go:build ignore
// Compiled by bpf2go.

// tcp_retransmit: trace TCP retransmits using the tcp_retransmit_skb tracepoint.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10

// ─── Structs ─────────────────────────────────────────────────────────────────

struct retransmit_event {
    __u32 pid;
    __u16 af;           // AF_INET or AF_INET6
    __u8  saddr[16];    // IPv4 uses first 4 bytes
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u8  state;        // TCP state
    char  comm[TASK_COMM_LEN];
};

// ─── Maps ────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17); // 128 KB
} events SEC(".maps");

// Rate-limiting: count retransmits per (src,dst,sport,dport) to detect floods.
struct retransmit_key {
    __u8  saddr[16];
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   struct retransmit_key);
    __type(value, __u64);
    __uint(max_entries, 4096);
} retransmit_count SEC(".maps");

// ─── Program ─────────────────────────────────────────────────────────────────

// tp_btf/tcp_retransmit_skb is available on kernels >= 5.4 with BTF.
SEC("tp_btf/tcp_retransmit_skb")
int handle_tcp_retransmit(u64 *ctx)
{
    // Arguments: sock *sk, struct sk_buff *skb
    struct sock *sk = (struct sock *)ctx[0];

    __u16 af     = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 dport  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __u16 sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u8  state  = BPF_CORE_READ(sk, __sk_common.skc_state);

    struct retransmit_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid   = bpf_get_current_pid_tgid() & 0xffffffff;
    ev->af    = af;
    ev->sport = sport;
    ev->dport = dport;
    ev->state = state;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    if (af == AF_INET) {
        BPF_CORE_READ_INTO(&ev->saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&ev->daddr, sk, __sk_common.skc_daddr);
    } else if (af == AF_INET6) {
        BPF_CORE_READ_INTO(ev->saddr,
            sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(ev->daddr,
            sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    // Update per-flow retransmit count.
    struct retransmit_key rkey = {};
    __builtin_memcpy(rkey.saddr, ev->saddr, 16);
    __builtin_memcpy(rkey.daddr, ev->daddr, 16);
    rkey.sport = sport;
    rkey.dport = dport;

    __u64 *cnt = bpf_map_lookup_elem(&retransmit_count, &rkey);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&retransmit_count, &rkey, &one, BPF_NOEXIST);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char __license[] SEC("license") = "GPL";
