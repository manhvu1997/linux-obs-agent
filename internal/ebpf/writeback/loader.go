// Package writeback provides an always-on memory writeback and direct-reclaim
// latency tracer via eBPF tracepoints.
//
// Design: per-PID statistics (dirty pages generated, direct-reclaim count and
// latency) are aggregated in-kernel inside a BPF_MAP_TYPE_LRU_HASH.
// TopDirtyProducers() does a single batch map read every poll interval – no
// per-event userspace wakeup.  Only direct-reclaim outlier events (latency >
// slow_reclaim_threshold_ns) are emitted to the ring buffer.
//
// Kernel compatibility:
//   - kernel >= 5.8: uses BPF_MAP_TYPE_RINGBUF (lower overhead, single buffer)
//   - kernel <  5.8: uses BPF_MAP_TYPE_PERF_EVENT_ARRAY (per-CPU, kernel >= 3.4)
//
// # Lifecycle
//
//	l := NewLoader(100_000_000)       // 100 ms slow-reclaim threshold
//	err := l.Start(ctx)               // attach tracepoints, start event consumer
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
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// eventReader is a unified interface over ringbuf.Reader and perf.Reader.
type eventReader interface {
	Read() (rawSample []byte, err error)
	Close() error
}

type ringbufEventReader struct{ r *ringbuf.Reader }

func (w *ringbufEventReader) Read() ([]byte, error) {
	rec, err := w.r.Read()
	if errors.Is(err, ringbuf.ErrClosed) {
		return nil, errReaderClosed
	}
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}
func (w *ringbufEventReader) Close() error { return w.r.Close() }

type perfEventReader struct{ r *perf.Reader }

func (w *perfEventReader) Read() ([]byte, error) {
	rec, err := w.r.Read()
	if errors.Is(err, perf.ErrClosed) {
		return nil, errReaderClosed
	}
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}
func (w *perfEventReader) Close() error { return w.r.Close() }

var errReaderClosed = errors.New("reader closed")

// Loader manages the writeback eBPF module lifecycle.
type Loader struct {
	thresholdNs uint64

	// Exactly one of objs / objsCompat is populated after Start().
	objs       WritebackObjects
	objsCompat WritebackCompatObjects

	// pidStatsMap and sysCountMap point to the maps from whichever object set is active.
	pidStatsMap *ebpf.Map
	sysCountMap *ebpf.Map

	links []link.Link
	rd    eventReader // ringbuf on kernel >= 5.8, perf on older kernels

	// useCompat is set when the compat (PERF_EVENT_ARRAY) path is active.
	useCompat bool

	// SlowEvents receives outlier direct-reclaim events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the reader.
	SlowEvents chan model.EBPFEvent
}

// NewLoader creates a Loader.  thresholdNs is the minimum direct-reclaim
// latency in nanoseconds that causes an event (0 → default 100 ms).
func NewLoader(thresholdNs uint64) *Loader {
	if thresholdNs == 0 {
		thresholdNs = 100_000_000 // 100 ms
	}
	return &Loader{
		thresholdNs: thresholdNs,
		SlowEvents:  make(chan model.EBPFEvent, 256),
	}
}

// kernelSupportsRingbuf reports whether the running kernel supports
// BPF_MAP_TYPE_RINGBUF (added in Linux 5.8).
func kernelSupportsRingbuf() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	ver := strings.TrimSpace(string(data))
	var major, minor int
	fmt.Sscanf(ver, "%d.%d", &major, &minor)
	return major > 5 || (major == 5 && minor >= 8)
}

// Start loads the eBPF objects, sets the reclaim threshold, attaches all four
// tracepoints, and launches the event consumer goroutine.
//
// On kernel >= 5.8 the RINGBUF-compiled objects are used; on older kernels
// the PERF_EVENT_ARRAY compat objects are loaded automatically.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("writeback: removing memlock: %w", err)
	}
	if kernelSupportsRingbuf() {
		return l.startRingbuf(ctx)
	}
	l.useCompat = true
	return l.startPerfEvent(ctx)
}

// startRingbuf loads the RINGBUF-compiled objects (kernel >= 5.8).
func (l *Loader) startRingbuf(ctx context.Context) error {
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
	l.pidStatsMap = l.objs.WbPidStats
	l.sysCountMap = l.objs.WbSysCount

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("writeback: opening ringbuf: %w", err)
	}
	l.rd = &ringbufEventReader{rd}

	dirtyName, err := l.attachTracepoints(
		l.objs.TpWritebackDirtyFolio, l.objs.TpWritebackDirtyPage,
		l.objs.TpWritebackStart,
		l.objs.TpDirectReclaimBegin, l.objs.TpDirectReclaimEnd,
	)
	if err != nil {
		l.cleanup()
		return err
	}

	slog.Info("writeback: started (ringbuf)",
		"threshold_ns", l.thresholdNs, "dirty_hook", dirtyName)
	go l.consume(ctx)
	return nil
}

// startPerfEvent loads the PERF_EVENT_ARRAY compat objects (kernel < 5.8).
func (l *Loader) startPerfEvent(ctx context.Context) error {
	spec, err := LoadWritebackCompat()
	if err != nil {
		return fmt.Errorf("writeback: loading eBPF compat spec: %w", err)
	}
	if err := spec.Variables["slow_reclaim_threshold_ns"].Set(l.thresholdNs); err != nil {
		slog.Warn("writeback: could not set slow_reclaim_threshold_ns", "err", err)
	}

	// PERF_EVENT_ARRAY requires max_entries >= number of possible CPUs.
	nCPU, cpuErr := ebpf.PossibleCPU()
	if cpuErr != nil || nCPU <= 0 {
		nCPU = 128
	}
	spec.Maps["events"].MaxEntries = uint32(nCPU)

	if err := spec.LoadAndAssign(&l.objsCompat, nil); err != nil {
		return fmt.Errorf("writeback: loading eBPF objects: %w", err)
	}
	l.pidStatsMap = l.objsCompat.WbPidStats
	l.sysCountMap = l.objsCompat.WbSysCount

	pr, err := perf.NewReader(l.objsCompat.Events, os.Getpagesize())
	if err != nil {
		l.objsCompat.Close()
		return fmt.Errorf("writeback: opening perf reader: %w", err)
	}
	l.rd = &perfEventReader{pr}

	dirtyName, err := l.attachTracepoints(
		l.objsCompat.TpWritebackDirtyFolio, l.objsCompat.TpWritebackDirtyPage,
		l.objsCompat.TpWritebackStart,
		l.objsCompat.TpDirectReclaimBegin, l.objsCompat.TpDirectReclaimEnd,
	)
	if err != nil {
		l.cleanup()
		return err
	}

	slog.Info("writeback: started (perf compat)",
		"threshold_ns", l.thresholdNs, "dirty_hook", dirtyName)
	go l.consume(ctx)
	return nil
}

// attachTracepoints attaches the four writeback/vmscan tracepoints.
// It tries writeback_dirty_folio first (kernel >= 5.18) and falls back to
// writeback_dirty_page for older kernels.
func (l *Loader) attachTracepoints(
	tpDirtyFolio, tpDirtyPage,
	tpWbStart,
	tpReclaimBegin, tpReclaimEnd *ebpf.Program,
) (dirtyName string, err error) {
	// Try writeback_dirty_folio first (kernel >= ~5.18), fall back to page.
	dirtyLnk, dirtyErr := link.Tracepoint("writeback", "writeback_dirty_folio",
		tpDirtyFolio, nil)
	dirtyName = "writeback_dirty_folio"
	if dirtyErr != nil {
		dirtyLnk, dirtyErr = link.Tracepoint("writeback", "writeback_dirty_page",
			tpDirtyPage, nil)
		dirtyName = "writeback_dirty_page"
	}
	if dirtyErr != nil {
		return "", fmt.Errorf("writeback: attaching dirty page/folio tracepoint: %w", dirtyErr)
	}
	l.links = append(l.links, dirtyLnk)

	type tpEntry struct {
		group string
		name  string
		prog  *ebpf.Program
	}
	tps := []tpEntry{
		{"writeback", "writeback_start", tpWbStart},
		{"vmscan", "mm_vmscan_direct_reclaim_begin", tpReclaimBegin},
		{"vmscan", "mm_vmscan_direct_reclaim_end", tpReclaimEnd},
	}
	for _, tp := range tps {
		lnk, lerr := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if lerr != nil {
			return "", fmt.Errorf("writeback: attaching tracepoint %s/%s: %w",
				tp.group, tp.name, lerr)
		}
		l.links = append(l.links, lnk)
	}
	return dirtyName, nil
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
	if l.useCompat {
		l.objsCompat.Close()
	} else {
		l.objs.Close()
	}
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
	if err := l.sysCountMap.Lookup(&key, &cnt); err != nil {
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

	iter := l.pidStatsMap.Iterate()
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

// ─── Event consumer ───────────────────────────────────────────────────────────

// consume reads slow direct-reclaim events from the ring buffer (or perf buffer
// in compat mode) and forwards them to SlowEvents.
// Exits when ctx is cancelled or the reader is closed (Stop).
func (l *Loader) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		raw_bytes, err := l.rd.Read()
		if err != nil {
			if errors.Is(err, errReaderClosed) {
				return
			}
			slog.Warn("writeback: event read error", "err", err)
			continue
		}

		var raw WritebackWbSlowEvent // bpf2go-generated type
		if err := binary.Read(bytes.NewReader(raw_bytes), binary.LittleEndian, &raw); err != nil {
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
				PID:              raw.Tgid,
				TID:              raw.Pid,
				Comm:             comm,
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
