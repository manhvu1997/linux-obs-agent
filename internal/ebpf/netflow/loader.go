// Package netflow loads the always-on TCP flow accounting eBPF program and
// implements internal/netflow.Source. Import it as netflowbpf.
package netflow

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	nf "github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/netinv"
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

// Start loads the program, seeds listen_ports and attaches all hooks. The
// accept kretprobe is optional: without it inbound sockets are adopted on
// first bytes.
func (l *Loader) Start() error {
	// The probes read registers through struct x86_regs casts; on any other
	// architecture they would return plausible garbage, not "unavailable".
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("netflow: eBPF programs support only amd64 (running on %s)", runtime.GOARCH)
	}
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
	// Seed listen_ports BEFORE any hook is attached: a pre-existing inbound
	// connection adopted while the map is empty is classified outbound with
	// the client's ephemeral port as service port, for its whole lifetime.
	if socks, err := netinv.New("/proc").Listening(); err != nil {
		slog.Warn("netflow: seeding listen_ports: listing listening sockets", "err", err)
	} else if err := l.SetListenPorts(netinv.ListenPorts(socks)); err != nil {
		slog.Warn("netflow: seeding listen_ports", "err", err)
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
			return attachKretprobeMaxActive("tcp_sendmsg", l.objs.KretprobeTcpSendmsg)
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

// ReadFlows reads flow_stats and collapses it into per-FlowKey totals.
//
// Raw entries are first collected into a map keyed by the generated BPF key,
// so a key yielded twice by Iterate() overwrites instead of summing: when the
// current key is evicted from the LRU mid-walk the kernel restarts the walk
// from the first key, and summing those duplicates would over-report one poll
// and make the next poll look like an eviction to the accumulator.
func (l *Loader) ReadFlows() (map[nf.FlowKey]nf.FlowValue, error) {
	raw := make(map[NetflowFlowKey]NetflowFlowVal)
	var k NetflowFlowKey
	var v NetflowFlowVal
	it := l.objs.FlowStats.Iterate()
	for it.Next(&k, &v) {
		raw[k] = v
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return collapseFlows(raw), nil
}

// collapseFlows sums raw BPF entries that differ only in the address family
// byte: IPv4 and v4-mapped IPv6 sockets of the same peer become one FlowKey
// (the family is not part of FlowKey). Each raw key contributes exactly once.
func collapseFlows(raw map[NetflowFlowKey]NetflowFlowVal) map[nf.FlowKey]nf.FlowValue {
	out := make(map[nf.FlowKey]nf.FlowValue, len(raw))
	for k, v := range raw {
		key := nf.FlowKey{TGID: k.Tgid, Dir: nf.Direction(k.Dir), Peer: nf.PeerFromBytes(k.Peer), ServicePort: k.SvcPort}
		cur := out[key]
		cur.BytesTx += v.BytesTx
		cur.BytesRx += v.BytesRx
		cur.Opened += v.Opened
		cur.Closed += v.Closed
		out[key] = cur
	}
	return out
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

// kretprobeMaxActive raises the number of concurrent kretprobe instances.
// The kernel default is max(10, 2*NCPU); tcp_sendmsg sleeps in
// sk_stream_wait_memory for slow receivers, so sleeping senders exhaust the
// default and returns are silently dropped (nmissed) -> sent bytes undercount.
const kretprobeMaxActive = 2048

// attachKretprobeMaxActive attaches a kretprobe with RetprobeMaxActive set.
// cilium/ebpf v0.21 cannot pass maxactive through the perf_kprobe PMU and
// falls back to tracefs; when that fails (no tracefs mounted, old kernel),
// retry with default options so a required hook never fails Start because of
// the tuning alone.
func attachKretprobeMaxActive(sym string, prog *ebpf.Program) (link.Link, error) {
	krp, err := link.Kretprobe(sym, prog, &link.KprobeOptions{RetprobeMaxActive: kretprobeMaxActive})
	if err == nil {
		return krp, nil
	}
	slog.Info("netflow: RetprobeMaxActive could not be applied, retrying with defaults; "+
		"concurrent slow senders may be under-counted",
		"symbol", sym, "maxactive", kretprobeMaxActive, "err", err)
	return link.Kretprobe(sym, prog, nil)
}
