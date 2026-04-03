// Package io_latency provides on-demand block IO latency tracing via eBPF.
// It attaches fentry hooks on blk_mq_start_request / blk_mq_end_request,
// calculates per-request latency in-kernel, and emits events for slow IOs.
package io_latency

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Loader manages the IO latency eBPF module.
type Loader struct {
	thresholdUs uint64
	objs        IoLatencyObjects
	links       []link.Link
	rd          *ringbuf.Reader
	Events      chan model.EBPFEvent
}

func NewLoader(thresholdUs uint64) *Loader {
	return &Loader{
		thresholdUs: thresholdUs,
		Events:      make(chan model.EBPFEvent, 512),
	}
}

func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load the CollectionSpec so we can rewrite the const volatile variable
	// BEFORE the programs are loaded.  Once loaded, .rodata becomes read-only
	// and Set() returns "resource is read-only".
	spec, err := LoadIoLatency()
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}
	if err := spec.Variables["slow_threshold_us"].Set(l.thresholdUs); err != nil {
		slog.Warn("io_latency: could not set slow_threshold_us", "err", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("opening ringbuf: %w", err)
	}
	l.rd = rd

	// Attach fentry hooks (BPF_PROG_TYPE_TRACING / fentry).
	issueLink, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.TraceRqIssue,
	})
	if err != nil {
		l.cleanup()
		return fmt.Errorf("attaching blk_mq_start_request: %w", err)
	}
	l.links = append(l.links, issueLink)

	completeLink, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.TraceRqComplete,
	})
	if err != nil {
		l.cleanup()
		return fmt.Errorf("attaching blk_mq_end_request: %w", err)
	}
	l.links = append(l.links, completeLink)

	slog.Info("io_latency: started", "threshold_us", l.thresholdUs)
	go l.consume(ctx)
	return nil
}

func (l *Loader) Stop() {
	l.cleanup()
}

func (l *Loader) cleanup() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
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
			slog.Warn("io_latency: ringbuf read error", "err", err)
			continue
		}

		var raw IoLatencyIoLatEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		op := "W"
		if raw.Op == 0 {
			op = "R"
		}

		l.Events <- model.EBPFEvent{
			Type:      model.EventIOLatency,
			Timestamp: time.Now(),
			PID:       raw.Pid,
			Comm:      nullTermString(raw.Comm[:]),
			Data: model.IOLatencyEvent{
				PID:       raw.Pid,
				Comm:      nullTermString(raw.Comm[:]),
				LatencyUs: raw.LatencyUs,
				Bytes:     raw.Bytes,
				Op:        op,
				Dev:       raw.Dev,
			},
		}
	}
}

// LatencyHistogram reads the in-kernel latency histogram.
// Returns a map of log2(us_bucket) -> count.
func (l *Loader) LatencyHistogram() map[uint32]uint64 {
	result := make(map[uint32]uint64, 64)
	var v uint64
	for i := uint32(0); i < 64; i++ {
		if err := l.objs.LatencyHist.Lookup(i, &v); err == nil && v > 0 {
			result[i] = v
		}
	}
	return result
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
