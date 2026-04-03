// Package tcp_retransmit provides on-demand TCP retransmit tracing.
//
// Three eBPF programs are loaded:
//   - tp_btf/tcp_retransmit_skb  – enriched per-retransmit event
//   - fentry/tcp_set_state       – per-flow ESTABLISHED timestamp tracking
//   - tp_btf/kfree_skb           – packet drop events (requires kernel >= 5.17
//                                  for drop_reason; older kernels get reason=0)
package tcp_retransmit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// tcpStateNames maps the kernel TCP state byte to a human-readable string.
var tcpStateNames = map[uint8]string{
	1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
	4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
	7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
	10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
}

// skbDropReasons is a partial mapping of kernel enum skb_drop_reason values.
// Covers the most common cases (kernel 6.x).  Unknown values are reported as
// "UNKNOWN(<n>)".
var skbDropReasons = map[uint32]string{
	0:   "NOT_SPECIFIED",
	1:   "NO_SOCKET",
	2:   "PKT_TOO_SMALL",
	3:   "TCP_CSUM",
	4:   "SOCKET_FILTER",
	5:   "UDP_CSUM",
	6:   "NETFILTER_DROP",
	7:   "OTHERHOST",
	8:   "IP_CSUM",
	9:   "IP_INHDR",
	10:  "IP_RPFILTER",
	11:  "UNICAST_IN_L2_MULTICAST",
	12:  "XFRM_POLICY",
	13:  "IP_NOPROTO",
	14:  "SOCKET_RCVBUFF",
	15:  "PROTO_MEM",
	16:  "TCP_MD5NOTFOUND",
	17:  "TCP_MD5UNEXPECTED",
	18:  "TCP_MD5FAILURE",
	19:  "SOCKET_BACKLOG",
	20:  "TCP_FLAGS",
	21:  "TCP_ZEROWINDOW",
	22:  "TCP_OLD_DATA",
	23:  "TCP_OVERWINDOW",
	24:  "TCP_OFOMERGE",
	25:  "TCP_RFC7323_PAWS",
	26:  "TCP_INVALID_SEQUENCE",
	27:  "TCP_RESET",
	28:  "TCP_INVALID_SYN",
	29:  "TCP_CLOSE",
	30:  "TCP_FASTOPEN",
	31:  "TCP_LISTEN_OVERFLOW",  // QUEUE_FULL equivalent
	32:  "TCP_OLD_ACK",
	33:  "TCP_TOO_OLD_ACK",
	34:  "TCP_ACK_UNSENT_DATA",
	35:  "TCP_OFO_QUEUE_PRUNE",
	36:  "TCP_OFO_DROP",
	37:  "IP_OUTNOROUTES",
	38:  "BPF_CGROUP_EGRESS",
	39:  "IPV6DISABLED",
	40:  "NEIGH_CREATEFAIL",
	41:  "NEIGH_FAILED",
	42:  "NEIGH_QUEUEFULL",
	43:  "NEIGH_DEAD",
	44:  "TC_EGRESS",
	45:  "QDISC_DROP",
	46:  "CPU_BACKLOG",
	47:  "XDP",
	48:  "TC_INGRESS",
	49:  "UNHANDLED_PROTO",
	50:  "SKB_CSUM",
	51:  "SKB_GSO_SEG",
	52:  "SKB_UCOPY_FAULT",
	53:  "DEV_HDR",
	54:  "DEV_READY",
	55:  "FULL_RING",
	56:  "NOMEM",
	57:  "HDR_TRUNC",
	58:  "TAP_FILTER",
	59:  "TAP_TXFILTER",
	60:  "ICMP_CSUM",
	61:  "INVALID_PROTO",
	62:  "IP_INADDRERRORS",
	63:  "IP_INNOROUTES",
	64:  "PKT_TOO_BIG",
	65:  "DUP_FRAG",
	66:  "FRAG_REASM_TIMEOUT",
	67:  "FRAG_TOO_FAR",
	68:  "TCP_MINTTL",
	69:  "IPV6_BAD_EXTHDR",
	70:  "IPV6_NDISC_FRAG",
	71:  "IPV6_NDISC_HOP_LIMIT",
	72:  "IPV6_NDISC_BAD_CODE",
	73:  "IPV6_NDISC_BAD_OPTIONS",
	74:  "IPV6_NDISC_NS_OTHERHOST",
}

// Loader manages the lifecycle of the TCP retransmit eBPF programs.
type Loader struct {
	objs  TcpRetransmitObjects
	links []link.Link
	rd    *ringbuf.Reader // retransmit events
	dropRd *ringbuf.Reader // drop events (nil if kfree_skb failed to attach)
	Events chan model.EBPFEvent
}

func NewLoader() *Loader {
	return &Loader{Events: make(chan model.EBPFEvent, 512)}
}

func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	if err := LoadTcpRetransmitObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("opening retransmit ringbuf: %w", err)
	}
	l.rd = rd

	// ── tp_btf/tcp_retransmit_skb ─────────────────────────────────────────
	// Program type is Tracing (tp_btf) – must use AttachTracing, not Tracepoint.
	tp, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.HandleTcpRetransmit,
	})
	if err != nil {
		l.cleanup()
		return fmt.Errorf("attaching tcp_retransmit_skb (tp_btf): %w", err)
	}
	l.links = append(l.links, tp)

	// ── fentry/tcp_set_state ─────────────────────────────────────────────
	// tcp_set_state is a kernel function (not a tracepoint) – fentry required.
	// Tracks ESTABLISHED timestamp for per-flow duration calculation.
	ss, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.HandleTcpSetState,
	})
	if err != nil {
		slog.Warn("tcp_retransmit: tcp_set_state attach failed (flow duration unavailable)",
			"err", err)
	} else {
		l.links = append(l.links, ss)
	}

	// ── tp_btf/kfree_skb ─────────────────────────────────────────────────
	// Drop reason field in the tracepoint requires kernel >= 5.17.
	// On older kernels the verifier rejects ctx[2] access – we log a warning
	// and continue without drop event collection.
	dropRd, err := ringbuf.NewReader(l.objs.DropEvents)
	if err == nil {
		kb, err2 := link.AttachTracing(link.TracingOptions{
			Program: l.objs.HandleKfreeSkb,
		})
		if err2 != nil {
			slog.Warn("tcp_retransmit: kfree_skb attach failed (drop events disabled)",
				"err", err2)
			dropRd.Close()
		} else {
			l.links = append(l.links, kb)
			l.dropRd = dropRd
			go l.consumeDrops(ctx)
		}
	}

	slog.Info("tcp_retransmit: started",
		"drop_events", l.dropRd != nil)
	go l.consume(ctx)
	return nil
}

func (l *Loader) Stop() { l.cleanup() }

func (l *Loader) cleanup() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	if l.rd != nil {
		l.rd.Close()
	}
	if l.dropRd != nil {
		l.dropRd.Close()
	}
	l.objs.Close()
}

// consume reads enriched retransmit events from the ring buffer.
func (l *Loader) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := l.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var raw TcpRetransmitRetransmitEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		ev := buildRetransmitEvent(&raw)
		select {
		case l.Events <- ev:
		default:
		}
	}
}

// consumeDrops reads drop events from the kfree_skb ring buffer.
func (l *Loader) consumeDrops(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := l.dropRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var raw TcpRetransmitDropEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		ev := buildDropEvent(&raw)
		select {
		case l.Events <- ev:
		default:
		}
	}
}

// ─── Event builders ───────────────────────────────────────────────────────────

func buildRetransmitEvent(raw *TcpRetransmitRetransmitEvent) model.EBPFEvent {
	var srcIP, dstIP string
	if raw.Af == 2 { // AF_INET
		srcIP = net.IP(raw.Saddr[:4]).String()
		dstIP = net.IP(raw.Daddr[:4]).String()
	} else {
		srcIP = net.IP(raw.Saddr[:]).String()
		dstIP = net.IP(raw.Daddr[:]).String()
	}

	comm := nullTermString(raw.Comm[:])
	flow := fmt.Sprintf("%s:%d → %s:%d", srcIP, raw.Sport, dstIP, raw.Dport)

	// Approximate loss rate: retransmit_count per 1 KB sent (simple heuristic).
	var lossRate float64
	if raw.BytesSent > 0 {
		lossRate = float64(raw.RetransmitCount) / float64(raw.BytesSent) * 100.0
	}

	stateName := tcpStateName(raw.TcpState)

	return model.EBPFEvent{
		Type:      model.EventTCPRetransmit,
		Timestamp: time.Now(),
		PID:       raw.Pid,
		Comm:      comm,
		Data: model.TCPRetransmitEvent{
			PID:      raw.Pid,
			Comm:     comm,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  raw.Sport,
			DstPort:  raw.Dport,
			AF:       raw.Af,
			TCPState: stateName,
			Flow:     flow,

			RTTUS:       raw.RttUs,
			RTTVarUS:    raw.RttVarUs,
			SndCwnd:     raw.SndCwnd,
			SndSsthresh: raw.SndSsthresh,

			BytesSent:     raw.BytesSent,
			BytesReceived: raw.BytesRecv,

			SendQueueBytes: raw.SendQueueBytes,
			RecvQueueBytes: raw.RecvQueueBytes,
			Backlog:        raw.SkBacklog,

			RetransmitCount: raw.RetransmitCount,
			DurationMs:      raw.DurationMs,
			LossRate:        lossRate,
		},
	}
}

func buildDropEvent(raw *TcpRetransmitDropEvent) model.EBPFEvent {
	var srcIP, dstIP string
	if raw.Af == 2 {
		srcIP = net.IP(raw.Saddr[:4]).String()
		dstIP = net.IP(raw.Daddr[:4]).String()
	} else {
		srcIP = net.IP(raw.Saddr[:]).String()
		dstIP = net.IP(raw.Daddr[:]).String()
	}

	comm := nullTermString(raw.Comm[:])
	reasonName := dropReasonName(raw.DropReason)
	flow := fmt.Sprintf("%s:%d → %s:%d", srcIP, raw.Sport, dstIP, raw.Dport)

	return model.EBPFEvent{
		Type:      model.EventTCPDrop,
		Timestamp: time.Now(),
		PID:       raw.Pid,
		Comm:      comm,
		Data: model.TCPDropEvent{
			PID:         raw.Pid,
			Comm:        comm,
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     raw.Sport,
			DstPort:     raw.Dport,
			AF:          raw.Af,
			DropReason:  raw.DropReason,
			DropName:    reasonName,
			Location:    raw.Location,
			LocationHex: fmt.Sprintf("0x%016x", raw.Location),
			Flow:        flow,
		},
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func tcpStateName(state uint8) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

func dropReasonName(reason uint32) string {
	if name, ok := skbDropReasons[reason]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", reason)
}

func nullTermString(b []int8) string {
	bs := make([]byte, 0, len(b))
	for _, v := range b {
		if v == 0 {
			break
		}
		bs = append(bs, byte(v))
	}
	return string(bs)
}
