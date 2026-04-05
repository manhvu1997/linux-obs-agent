// Package writeback provides an always-on memory writeback and direct-reclaim
// latency tracer via eBPF tracepoints.
//
// Design: per-PID statistics (dirty pages generated, direct-reclaim count and
// latency) are aggregated in-kernel inside a BPF_MAP_TYPE_LRU_HASH.
// TopDirtyProducers() does a single batch map read every poll interval – no
// per-event userspace wakeup.  Only direct-reclaim outlier events (latency >
// slow_reclaim_threshold_ns) are emitted to the ringbuf.
//
// # Lifecycle
//
//	l := NewLoader(100_000_000)       // 100 ms slow-reclaim threshold
//	err := l.Start(ctx)               // attach tracepoints, start ringbuf consumer
//	offenders := l.TopDirtyProducers(10, 0)  // poll every 5 s
//	l.Stop()
package writeback

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Loader manages the writeback eBPF module lifecycle.
type Loader struct {
	thresholdNs uint64

	objs  WritebackObjects
	links []link.Link
	rd    *ringbuf.Reader

	// SlowEvents receives outlier direct-reclaim events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the ringbuf reader.
	SlowEvents chan model.EBPFEvent
}

// NewLoader creates a Loader.  thresholdNs is the minimum direct-reclaim
// latency in nanoseconds that causes a ringbuf event (0 → default 100 ms).
func NewLoader(thresholdNs uint64) *Loader {
	if thresholdNs == 0 {
		thresholdNs = 100_000_000 // 100 ms
	}
	return &Loader{
		thresholdNs: thresholdNs,
		SlowEvents:  make(chan model.EBPFEvent, 256),
	}
}

// Start loads the eBPF objects, sets the reclaim threshold, attaches all four
// tracepoints, and launches the ringbuf consumer goroutine.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("writeback: removing memlock: %w", err)
	}

	// Load spec before LoadAndAssign so we can rewrite const volatile vars.
	spec, err := LoadWriteback()
	if err != nil {
		return fmt.Errorf("writeback: loading eBPF spec: %w", err)
	}
	if err := spec.Variables["slow_reclaim_threshold_ns"].Set(l.thresholdNs); err != nil {
		slog.Warn("writeback: could not set slow_reclaim_threshold_ns", "err", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("writeback: loading eBPF objects: %w", err)
	}

	// Open ringbuf reader before attaching probes – avoids missing early events.
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("writeback: opening ringbuf: %w", err)
	}
	l.rd = rd

	// Attach all four tracepoints.
	type tpEntry struct {
		group string
		name  string
		prog  *ebpf.Program
	}
	tps := []tpEntry{
		{"writeback", "writeback_dirty_page", l.objs.TpWritebackDirtyPage},
		{"writeback", "writeback_start", l.objs.TpWritebackStart},
		{"vmscan", "mm_vmscan_direct_reclaim_begin", l.objs.TpDirectReclaimBegin},
		{"vmscan", "mm_vmscan_direct_reclaim_end", l.objs.TpDirectReclaimEnd},
	}
	for _, tp := range tps {
		lnk, lerr := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if lerr != nil {
			l.cleanup()
			return fmt.Errorf("writeback: attaching tracepoint %s/%s: %w",
				tp.group, tp.name, lerr)
		}
		l.links = append(l.links, lnk)
	}

	slog.Info("writeback: started",
		"threshold_ns", l.thresholdNs,
		"hooks", "writeback_dirty_page,writeback_start,direct_reclaim_begin,direct_reclaim_end")
	go l.consume(ctx)
	return nil
}

// Stop detaches all tracepoints and releases all kernel resources.
func (l *Loader) Stop() {
	l.cleanup()
	slog.Info("writeback: stopped")
}

func (l *Loader) cleanup() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	if l.rd != nil {
		l.rd.Close()
		l.rd = nil
	}
	l.objs.Close()
}

// ─── Map polling ──────────────────────────────────────────────────────────────

// WritebackPIDStat is the Go-side view of one wb_pid_val LRU entry.
type WritebackPIDStat struct {
	PID            uint32
	Comm           string
	DirtyPages     uint64
	ReclaimCount   uint64
	TotalReclaimNs uint64
	MaxReclaimNs   uint64
	LastSeenTs     uint64
}

// monotonicNowNs returns the current CLOCK_MONOTONIC time in nanoseconds.
//
// bpf_ktime_get_ns() in the kernel uses CLOCK_MONOTONIC (nanoseconds since
// boot).  time.Now().UnixNano() uses the wall clock (nanoseconds since the
// Unix epoch, ~1.7 × 10¹⁸).  Comparing the two would make every LRU entry
// appear stale, so we must use the same clock as the kernel.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Fall back to a value that disables the stale check rather than
		// silently dropping all entries.
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// TopDirtyProducers batch-reads the in-kernel LRU map and returns the top-n
// PIDs sorted by total dirty pages generated (descending).
//
// staleNs is the maximum age of the last_seen_ts before an entry is ignored
// (pass 0 for the default 60 s window).
func (l *Loader) TopDirtyProducers(n int, staleNs uint64) []WritebackPIDStat {
	return l.topPIDs(n, staleNs, func(a, b WritebackPIDStat) bool {
		return a.DirtyPages > b.DirtyPages
	})
}

// TopReclaimers batch-reads the in-kernel LRU map and returns the top-n PIDs
// sorted by total direct-reclaim time (descending).
func (l *Loader) TopReclaimers(n int, staleNs uint64) []WritebackPIDStat {
	return l.topPIDs(n, staleNs, func(a, b WritebackPIDStat) bool {
		return a.TotalReclaimNs > b.TotalReclaimNs
	})
}

// SysWritebackCount returns the system-wide writeback operation counter.
func (l *Loader) SysWritebackCount() uint64 {
	var key uint32
	var cnt uint64
	if err := l.objs.WbSysCount.Lookup(&key, &cnt); err != nil {
		return 0
	}
	return cnt
}

func (l *Loader) topPIDs(n int, staleNs uint64, less func(a, b WritebackPIDStat) bool) []WritebackPIDStat {
	if staleNs == 0 {
		staleNs = 60 * uint64(time.Second)
	}
	now := monotonicNowNs()

	var all []WritebackPIDStat
	var key uint32
	var val WritebackWbPidVal // bpf2go-generated type

	iter := l.objs.WbPidStats.Iterate()
	for iter.Next(&key, &val) {
		// Skip stale entries.  Guard: if monotonicNowNs returned 0 (clock
		// failure), skip the stale check entirely.
		if now > 0 && val.LastSeenTs > 0 && now-val.LastSeenTs > staleNs {
			continue
		}
		if val.DirtyPages == 0 && val.ReclaimCount == 0 {
			continue
		}
		all = append(all, WritebackPIDStat{
			PID:            key,
			Comm:           nullTermU8(val.Comm[:]),
			DirtyPages:     val.DirtyPages,
			ReclaimCount:   val.ReclaimCount,
			TotalReclaimNs: val.TotalReclaimNs,
			MaxReclaimNs:   val.MaxReclaimNs,
			LastSeenTs:     val.LastSeenTs,
		})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("writeback: TopPIDs map iterate", "err", err)
	}

	sort.Slice(all, func(i, j int) bool { return less(all[i], all[j]) })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// ─── Ringbuf consumer ─────────────────────────────────────────────────────────

// consume reads slow direct-reclaim events from the ringbuf and forwards them
// to SlowEvents.  Exits when ctx is cancelled or the reader is closed (Stop).
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
			slog.Warn("writeback: ringbuf read error", "err", err)
			continue
		}

		var raw WritebackWbSlowEvent // bpf2go-generated type
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		comm := nullTermU8(raw.Comm[:])
		select {
		case l.SlowEvents <- model.EBPFEvent{
			Type:      model.EventWriteback,
			Timestamp: time.Now(),
			PID:       raw.Tgid,
			Comm:      comm,
			Data: model.WritebackSlowEvent{
				PID:             raw.Tgid,
				TID:             raw.Pid,
				Comm:            comm,
				ReclaimLatencyNs: raw.ReclaimLatencyNs,
			},
		}:
		default:
			// Drop rather than block – maintain <2% CPU overhead.
		}
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// nullTermU8 converts a null-terminated uint8 slice to a Go string.
func nullTermU8(b []uint8) string {
	end := 0
	for end < len(b) && b[end] != 0 {
		end++
	}
	return string(b[:end])
}

// ReadCmdline reads /proc/<pid>/cmdline and returns the command line with
// NUL-separators replaced by spaces (best-effort).
func ReadCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
}

// ReadCgroup returns the cgroup v2 path from /proc/<pid>/cgroup (best-effort).
func ReadCgroup(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	parts := strings.SplitN(line, ":", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return ""
}
