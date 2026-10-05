// Package netflow loads the always-on TCP flow accounting eBPF program and
// implements internal/netflow.Source. Import it as netflowbpf.
package netflow

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	nf "github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

var _ nf.Source = (*Loader)(nil)

// Loader owns the netflow eBPF objects and links.
type Loader struct {
	includeLoopback bool
	objs            NetflowObjects
	links           []link.Link
	inbound         string
}

func NewLoader(includeLoopback bool) *Loader {
	return &Loader{includeLoopback: includeLoopback}
}

// Start loads the program and attaches all hooks. The accept kretprobe is
// optional: without it inbound sockets are adopted on first bytes.
func (l *Loader) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("netflow: removing memlock: %w", err)
	}
	spec, err := LoadNetflow()
	if err != nil {
		return fmt.Errorf("netflow: loading spec: %w", err)
	}
	var lb uint8
	if l.includeLoopback {
		lb = 1
	}
	if err := spec.Variables["include_loopback"].Set(lb); err != nil {
		return fmt.Errorf("netflow: setting include_loopback: %w", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("netflow: loading objects: %w", err)
	}

	required := []struct {
		name   string
		attach func() (link.Link, error)
	}{
		{"tracepoint sock/inet_sock_set_state", func() (link.Link, error) {
			return link.Tracepoint("sock", "inet_sock_set_state", l.objs.HandleSetState, nil)
		}},
		{"kprobe tcp_sendmsg", func() (link.Link, error) { return link.Kprobe("tcp_sendmsg", l.objs.KprobeTcpSendmsg, nil) }},
		{"kretprobe tcp_sendmsg", func() (link.Link, error) {
			return link.Kretprobe("tcp_sendmsg", l.objs.KretprobeTcpSendmsg, nil)
		}},
		{"kprobe tcp_cleanup_rbuf", func() (link.Link, error) {
			return link.Kprobe("tcp_cleanup_rbuf", l.objs.KprobeTcpCleanupRbuf, nil)
		}},
	}
	for _, h := range required {
		lnk, err := h.attach()
		if err != nil {
			l.Stop()
			return fmt.Errorf("netflow: attaching %s: %w", h.name, err)
		}
		l.links = append(l.links, lnk)
	}
	if lnk, err := link.Kretprobe("inet_csk_accept", l.objs.KretprobeInetCskAccept, nil); err != nil {
		slog.Warn("netflow: inet_csk_accept unavailable; inbound connections adopted on first bytes", "err", err)
		l.inbound = "lazy"
	} else {
		l.links = append(l.links, lnk)
		l.inbound = "accept"
	}
	slog.Info("netflow: started", "include_loopback", l.includeLoopback, "inbound_accounting", l.inbound)
	return nil
}

func (l *Loader) Stop() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	l.objs.Close()
}

func (l *Loader) InboundAccounting() string { return l.inbound }

// ReadFlows iterates flow_stats. IPv4 and v4-mapped IPv6 sockets of the
// same peer collapse into one key (the family is not part of FlowKey).
func (l *Loader) ReadFlows() (map[nf.FlowKey]nf.FlowValue, error) {
	out := make(map[nf.FlowKey]nf.FlowValue)
	var k NetflowFlowKey
	var v NetflowFlowVal
	it := l.objs.FlowStats.Iterate()
	for it.Next(&k, &v) {
		key := nf.FlowKey{TGID: k.Tgid, Dir: nf.Direction(k.Dir), Peer: nf.PeerFromBytes(k.Peer), ServicePort: k.SvcPort}
		cur := out[key]
		cur.BytesTx += v.BytesTx
		cur.BytesRx += v.BytesRx
		cur.Opened += v.Opened
		cur.Closed += v.Closed
		out[key] = cur
	}
	return out, it.Err()
}

// SetListenPorts makes listen_ports equal to ports.
func (l *Loader) SetListenPorts(ports []uint16) error {
	want := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		want[p] = true
		if err := l.objs.ListenPorts.Put(p, uint8(1)); err != nil {
			return fmt.Errorf("netflow: listen_ports put %d: %w", p, err)
		}
	}
	var (
		k     uint16
		v     uint8
		stale []uint16
	)
	it := l.objs.ListenPorts.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, p := range stale {
		if err := l.objs.ListenPorts.Delete(p); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}
