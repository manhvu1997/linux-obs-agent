// Package runqlat provides on-demand run-queue latency tracing via eBPF.
// It attaches to tp_btf/sched_wakeup, sched_wakeup_new and sched_switch to
// measure how long tasks wait on the CPU run-queue before being scheduled.
//
// Two data paths, both aggregated in-kernel:
//   - Histogram()    – global log2(us) distribution over every context switch.
//   - TopOffenders() – per-process aggregate, used to identify which processes
//     are stalling on the run queue.
package runqlat

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// histBuckets matches the max_entries of the `hist` BPF array.
const histBuckets = 64

// Loader manages the runqlat eBPF module lifecycle.
type Loader struct {
	thresholdUs uint64
	trackMinUs  uint64
	objs        RunQLatObjects
	links       []link.Link
	rd          *ringbuf.Reader
	Events      chan model.EBPFEvent
}

// NewLoader creates a Loader.
//
//	thresholdUs – emit a ringbuf event and count a "slow event" at or above
//	              this run-queue wait (microseconds).
//	trackMinUs  – aggregation floor: waits below this are counted in the
//	              histogram but do not touch the per-process map.
//
// Zero values fall back to the defaults compiled into the eBPF program.
func NewLoader(thresholdUs, trackMinUs uint64) *Loader {
	return &Loader{
		thresholdUs: thresholdUs,
		trackMinUs:  trackMinUs,
		Events:      make(chan model.EBPFEvent, 512),
	}
}

func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load the CollectionSpec so the const volatile globals can be rewritten
	// BEFORE the programs are loaded. Once loaded, .rodata is read-only and
	// Set() fails with "resource is read-only".
	spec, err := LoadRunQLat()
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}
	if l.thresholdUs > 0 {
		if err := spec.Variables["runqlat_threshold_us"].Set(l.thresholdUs); err != nil {
			slog.Warn("runqlat: could not set runqlat_threshold_us", "err", err)
		}
	}
	if l.trackMinUs > 0 {
		if err := spec.Variables["runq_track_min_us"].Set(l.trackMinUs); err != nil {
			slog.Warn("runqlat: could not set runq_track_min_us", "err", err)
		}
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

	slog.Info("runqlat: started",
		"threshold_us", l.thresholdUs, "track_min_us", l.trackMinUs)
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

		ev := model.EBPFEvent{
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

		select {
		case l.Events <- ev:
		default:
			// Drop rather than block. Nothing drains Events once the module's
			// context is cancelled, so a blocking send would leak this
			// goroutine and the ringbuf reader on every activation.
		}
	}
}

// Histogram reads the in-kernel runqlat latency histogram.
// Returns 64 buckets where index i covers waits with log2(us+1) == i.
func (l *Loader) Histogram() [histBuckets]uint64 {
	var hist [histBuckets]uint64
	for i := uint32(0); i < histBuckets; i++ {
		var v uint64
		_ = l.objs.Hist.Lookup(i, &v)
		hist[i] = v
	}
	return hist
}

// RunQPIDStat is one process's aggregated run-queue statistics, read from the
// in-kernel LRU map.
//
// TrackedSwitches counts only waits at or above the module's track_min_us
// floor, so TotalLatencyNs/TrackedSwitches is the mean over TRACKED waits —
// not over every context switch the process made.
type RunQPIDStat struct {
	PID             uint32
	Comm            string
	TrackedSwitches uint64
	TotalLatencyNs  uint64
	MaxLatencyNs    uint64
	SlowEvents      uint64
	LastSeenTs      uint64
}

// TopOffenders returns up to n processes sorted by max run-queue wait desc.
//
//	staleNs          – ignore entries not updated within this window (0 → 60 s).
//	minMaxLatencyNs  – level-2 filter: only return processes whose MAX wait
//	                   reached this value (0 → no filter).
func (l *Loader) TopOffenders(n int, staleNs, minMaxLatencyNs uint64) []RunQPIDStat {
	if staleNs == 0 {
		staleNs = 60 * uint64(time.Second)
	}
	// CLOCK_MONOTONIC — same time base as bpf_ktime_get_ns() in the kernel.
	now := monotonicNowNs()

	var all []RunQPIDStat
	var key uint32
	var val RunQLatRunqPidStat // bpf2go-generated type

	iter := l.objs.RunqStats.Iterate()
	for iter.Next(&key, &val) {
		// Guard: if monotonicNowNs failed (returned 0) skip the stale check
		// entirely rather than wrapping around and dropping everything.
		if now > 0 && val.LastSeenTs > 0 && now-val.LastSeenTs > staleNs {
			continue
		}
		if val.TrackedSwitches == 0 {
			continue
		}
		if val.MaxLatencyNs < minMaxLatencyNs {
			continue
		}
		all = append(all, RunQPIDStat{
			PID:             key,
			Comm:            nullTermU8(val.Comm[:]),
			TrackedSwitches: val.TrackedSwitches,
			TotalLatencyNs:  val.TotalLatencyNs,
			MaxLatencyNs:    val.MaxLatencyNs,
			SlowEvents:      val.SlowEvents,
			LastSeenTs:      val.LastSeenTs,
		})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("runqlat: TopOffenders map iterate", "err", err)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].MaxLatencyNs > all[j].MaxLatencyNs
	})
	if n > 0 && len(all) > n {
		all = all[:n]
	}
	return all
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// monotonicNowNs returns CLOCK_MONOTONIC nanoseconds, matching the time base
// of bpf_ktime_get_ns(). Using the wall clock here would make every entry look
// ~54 years stale.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Should never happen on Linux; return 0 so callers disable the stale
		// check rather than silently dropping every entry.
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
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

func nullTermU8(b []uint8) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
