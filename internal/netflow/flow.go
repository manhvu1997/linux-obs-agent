// internal/netflow/flow.go

// Package netflow turns the in-kernel per-(process, direction, peer, port)
// TCP counters into windowed per-process / per-family summaries and
// monotonic Prometheus counters. It depends only on the Source interface, so
// it is testable without eBPF; internal/ebpf/netflow implements Source.
package netflow

import "net/netip"

// Direction values must match DIR_IN / DIR_OUT in netflow.bpf.c.
type Direction uint8

const (
	Inbound  Direction = 1 // the process accepted the connection
	Outbound Direction = 2 // the process initiated the connection
)

func (d Direction) String() string {
	switch d {
	case Inbound:
		return "inbound"
	case Outbound:
		return "outbound"
	}
	return "unknown"
}

// FlowKey identifies one aggregation bucket. ServicePort is the local
// listening port for inbound and the remote port for outbound — never the
// client's ephemeral port.
type FlowKey struct {
	TGID        uint32
	Dir         Direction
	Peer        netip.Addr
	ServicePort uint16
}

// FlowValue holds cumulative kernel counters for a FlowKey.
type FlowValue struct {
	BytesTx uint64
	BytesRx uint64
	Opened  uint64
	Closed  uint64
}

// Source is implemented by the eBPF loader.
type Source interface {
	ReadFlows() (map[FlowKey]FlowValue, error)
	SetListenPorts(ports []uint16) error
	// InboundAccounting is "accept" when inet_csk_accept is hooked, "lazy"
	// when inbound sockets are only adopted on first bytes.
	InboundAccounting() string
}

// PeerFromBytes converts the BPF 16-byte peer (IPv4 stored v4-mapped) to an
// address, unmapping IPv4 so dual-stack clients are not counted twice.
func PeerFromBytes(b [16]byte) netip.Addr { return netip.AddrFrom16(b).Unmap() }
