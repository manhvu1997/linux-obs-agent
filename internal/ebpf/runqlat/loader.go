// Package runqlat provides on-demand run-queue latency tracing via eBPF.
// It attaches to tp_btf/sched_wakeup, sched_wakeup_new and sched_switch to
// measure how long tasks wait on the CPU run-queue before being scheduled.
package runqlat

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

// Loader manages the runqlat eBPF module lifecycle.
type Loader struct {
	thresholdUs uint64
	objs        RunQLatObjects
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

	if err := loadRunQLatObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Optionally update the threshold global variable.
	// ebpf-go exposes kernel global vars via CollectionSpec.Variables.
	// After loadRunQLatObjects, we set via the map directly if needed.
	_ = l.thresholdUs // used in .bpf.c as const volatile

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("opening ringbuf: %w", err)
	}
	l.rd = rd

	// tp_btf programs use link.AttachTracing.
	wakeupLnk, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.HandleWakeup,
	})
	if err != nil {
		l.cleanup()
		return fmt.Errorf("attaching sched_wakeup: %w", err)
	}
	l.links = append(l.links, wakeupLnk)

	wakeupNewLnk, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.HandleWakeupNew,
	})
	if err != nil {
		l.cleanup()
		return fmt.Errorf("attaching sched_wakeup_new: %w", err)
	}
	l.links = append(l.links, wakeupNewLnk)

	switchLnk, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.HandleSwitch,
	})
	if err != nil {
		l.cleanup()
		return fmt.Errorf("attaching sched_switch: %w", err)
	}
	l.links = append(l.links, switchLnk)

	slog.Info("runqlat: started", "threshold_us", l.thresholdUs)
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
			slog.Warn("runqlat: ringbuf read error", "err", err)
			continue
		}

		var raw RunQLatRunqEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		l.Events <- model.EBPFEvent{
			Type:      model.EventRunQLat,
			Timestamp: time.Now(),
			PID:       raw.Pid,
			Comm:      nullTermString(raw.Comm[:]),
			Data: model.RunQLatEvent{
				PID:       raw.Pid,
				Comm:      nullTermString(raw.Comm[:]),
				LatencyUs: raw.LatencyUs,
			},
		}
	}
}

// Histogram reads the in-kernel runqlat latency histogram.
// Returns a slice of 64 buckets where index i = log2(us) bucket.
func (l *Loader) Histogram() [64]uint64 {
	var hist [64]uint64
	for i := uint32(0); i < 64; i++ {
		var v uint64
		_ = l.objs.Hist.Lookup(i, &v)
		hist[i] = v
	}
	return hist
}

func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
