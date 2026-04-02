// Package tcp_retransmit provides on-demand TCP retransmit tracing.
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

type Loader struct {
	objs   TcpRetransmitObjects
	links  []link.Link
	rd     *ringbuf.Reader
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
		return fmt.Errorf("opening ringbuf: %w", err)
	}
	l.rd = rd

	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", l.objs.HandleTcpRetransmit, nil)
	if err != nil {
		// Fall back to BTF-based tp_btf if the plain tracepoint fails.
		slog.Warn("tcp_retransmit: plain tracepoint failed, trying tp_btf", "err", err)
		l.cleanup()
		return fmt.Errorf("attaching tcp_retransmit_skb: %w", err)
	}
	l.links = append(l.links, tp)

	slog.Info("tcp_retransmit: started")
	go l.consume(ctx)
	return nil
}

func (l *Loader) Stop() { l.cleanup() }

func (l *Loader) cleanup() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.rd != nil {
		l.rd.Close()
	}
	l.objs.Close()
}

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

		var srcIP, dstIP string
		if raw.Af == 2 { // AF_INET
			srcIP = net.IP(raw.Saddr[:4]).String()
			dstIP = net.IP(raw.Daddr[:4]).String()
		} else {
			srcIP = net.IP(raw.Saddr[:]).String()
			dstIP = net.IP(raw.Daddr[:]).String()
		}

		l.Events <- model.EBPFEvent{
			Type:      model.EventTCPRetransmit,
			Timestamp: time.Now(),
			PID:       raw.Pid,
			Comm:      nullTermString(raw.Comm[:]),
			Data: model.TCPRetransmitEvent{
				PID:     raw.Pid,
				Comm:    nullTermString(raw.Comm[:]),
				SrcIP:   srcIP,
				DstIP:   dstIP,
				SrcPort: raw.Sport,
				DstPort: raw.Dport,
				AF:      raw.Af,
			},
		}
	}
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
