// Package fsync provides on-demand fsync/fdatasync/sync_file_range latency
// tracing via eBPF kprobes.
//
// Design: the primary data path aggregates statistics in-kernel inside a
// BPF_MAP_TYPE_LRU_HASH (10 240 entries, auto-eviction).  TopOffenders() does
// a single batch map read every poll interval – no per-event userspace wakeup.
// Only outlier events (latency > slow_fsync_threshold_us) are emitted to the
// ring buffer, so at 10 k+ fsync/s the ring buffer consumer runs rarely.
//
// Kernel compatibility:
//   - kernel >= 5.8: uses BPF_MAP_TYPE_RINGBUF (lower overhead, single buffer)
//   - kernel <  5.8: uses BPF_MAP_TYPE_PERF_EVENT_ARRAY (per-CPU, kernel >= 3.4)
//
// # Lifecycle
//
//	l := NewLoader(5000)       // 5 ms slow threshold
//	err := l.Start(ctx)       // attach kprobes, start event consumer
//	offenders := l.TopOffenders(10, 0)  // poll every 5 s
//	l.Stop()
package fsync

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
// It lets the consume goroutine work identically regardless of which
// underlying map type the kernel supports.
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

// Loader manages the fsync eBPF module lifecycle.
type Loader struct {
	thresholdUs uint64

	// Exactly one of objs / objsCompat is populated after Start().
	objs       FsyncObjects
	objsCompat FsyncCompatObjects

	// statsMap points to FsyncStats from whichever object set is active.
	statsMap *ebpf.Map

	links []link.Link
	rd    eventReader // ringbuf on kernel >= 5.8, perf on older kernels

	// useCompat is set when the compat (PERF_EVENT_ARRAY) path is active.
	useCompat bool

	// SlowEvents receives outlier events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the reader.
	SlowEvents chan model.EBPFEvent
}

// NewLoader creates a Loader.  thresholdUs is the minimum fsync latency in
// microseconds that causes an event (0 → default 5 000 µs = 5 ms).
func NewLoader(thresholdUs uint64) *Loader {
	if thresholdUs == 0 {
		thresholdUs = 5000
	}
	return &Loader{
		thresholdUs: thresholdUs,
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
	// Format: "5.4.0-1093-gcp"  →  parse major.minor
	var major, minor int
	fmt.Sscanf(ver, "%d.%d", &major, &minor)
	return major > 5 || (major == 5 && minor >= 8)
}

// Start loads the eBPF objects, sets the latency threshold, attaches all six
// kprobe/kretprobe hooks, and launches the event consumer goroutine.
//
// On kernel >= 5.8 the RINGBUF-compiled objects are used; on older kernels
// the PERF_EVENT_ARRAY compat objects are loaded automatically.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("fsync: removing memlock: %w", err)
	}
	if kernelSupportsRingbuf() {
		return l.startRingbuf(ctx)
	}
	l.useCompat = true
	return l.startPerfEvent(ctx)
}

// startRingbuf loads the RINGBUF-compiled objects (kernel >= 5.8).
func (l *Loader) startRingbuf(ctx context.Context) error {
	spec, err := LoadFsync()
	if err != nil {
		return fmt.Errorf("fsync: loading eBPF spec: %w", err)
	}
	if err := spec.Variables["slow_fsync_threshold_us"].Set(l.thresholdUs); err != nil {
		slog.Warn("fsync: could not set slow_fsync_threshold_us", "err", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("fsync: loading eBPF objects: %w", err)
	}
	l.statsMap = l.objs.FsyncStats

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("fsync: opening ringbuf: %w", err)
	}
	l.rd = &ringbufEventReader{rd}

	if err := l.attachProbes(
		l.objs.KprobeFsync, l.objs.KretprobeFsync,
		l.objs.KprobeFdatasync, l.objs.KretprobeFdatasync,
		l.objs.KprobeSyncFileRange, l.objs.KretprobeSyncFileRange,
	); err != nil {
		l.cleanup()
		return err
	}

	slog.Info("fsync: started (ringbuf)", "threshold_us", l.thresholdUs)
	go l.consume(ctx)
	return nil
}

// startPerfEvent loads the PERF_EVENT_ARRAY compat objects (kernel < 5.8).
func (l *Loader) startPerfEvent(ctx context.Context) error {
	spec, err := LoadFsyncCompat()
	if err != nil {
		return fmt.Errorf("fsync: loading eBPF compat spec: %w", err)
	}
	if err := spec.Variables["slow_fsync_threshold_us"].Set(l.thresholdUs); err != nil {
		slog.Warn("fsync: could not set slow_fsync_threshold_us", "err", err)
	}

	// PERF_EVENT_ARRAY requires max_entries >= number of possible CPUs.
	nCPU, cpuErr := ebpf.PossibleCPU()
	if cpuErr != nil || nCPU <= 0 {
		nCPU = 128
	}
	spec.Maps["events"].MaxEntries = uint32(nCPU)

	if err := spec.LoadAndAssign(&l.objsCompat, nil); err != nil {
		return fmt.Errorf("fsync: loading eBPF objects: %w", err)
	}
	l.statsMap = l.objsCompat.FsyncStats

	pr, err := perf.NewReader(l.objsCompat.Events, os.Getpagesize())
	if err != nil {
		l.objsCompat.Close()
		return fmt.Errorf("fsync: opening perf reader: %w", err)
	}
	l.rd = &perfEventReader{pr}

	if err := l.attachProbes(
		l.objsCompat.KprobeFsync, l.objsCompat.KretprobeFsync,
		l.objsCompat.KprobeFdatasync, l.objsCompat.KretprobeFdatasync,
		l.objsCompat.KprobeSyncFileRange, l.objsCompat.KretprobeSyncFileRange,
	); err != nil {
		l.cleanup()
		return err
	}

	slog.Info("fsync: started (perf compat)", "threshold_us", l.thresholdUs)
	go l.consume(ctx)
	return nil
}

// attachProbes attaches the six kprobe/kretprobe pairs.
func (l *Loader) attachProbes(
	kprobeFsync, kretprobeFsync,
	kprobeFdatasync, kretprobeFdatasync,
	kprobeSyncFileRange, kretprobeSyncFileRange *ebpf.Program,
) error {
	type probeEntry struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}
	hooks := []probeEntry{
		{"__x64_sys_fsync", kprobeFsync, false},
		{"__x64_sys_fsync", kretprobeFsync, true},
		{"__x64_sys_fdatasync", kprobeFdatasync, false},
		{"__x64_sys_fdatasync", kretprobeFdatasync, true},
		{"__x64_sys_sync_file_range", kprobeSyncFileRange, false},
		{"__x64_sys_sync_file_range", kretprobeSyncFileRange, true},
	}
	for _, h := range hooks {
		var lnk link.Link
		var lerr error
		if h.ret {
			lnk, lerr = link.Kretprobe(h.sym, h.prog, nil)
		} else {
			lnk, lerr = link.Kprobe(h.sym, h.prog, nil)
		}
		if lerr != nil {
			return fmt.Errorf("fsync: attaching %s (ret=%v): %w", h.sym, h.ret, lerr)
		}
		l.links = append(l.links, lnk)
	}
	return nil
}

// Stop detaches all kprobes and releases all kernel resources.
func (l *Loader) Stop() {
	l.cleanup()
	slog.Info("fsync: stopped")
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

// FsyncPIDStat is the Go-side view of one fsync_pid_val LRU entry.
type FsyncPIDStat struct {
	PID            uint32
	Comm           string
	TotalCalls     uint64
	TotalLatencyNs uint64
	MaxLatencyNs   uint64
	LastSeenTs     uint64
}

// monotonicNowNs returns the current CLOCK_MONOTONIC time in nanoseconds.
//
// bpf_ktime_get_ns() in the kernel uses CLOCK_MONOTONIC (nanoseconds since
// boot).  time.Now().UnixNano() uses the wall clock (nanoseconds since the
// Unix epoch, ~1.7 × 10¹⁸).  Comparing the two would make every LRU entry
// appear stale by ~54 years, so we must use the same clock as the kernel.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Should never happen on Linux; fall back to a value that disables
		// the stale check rather than silently dropping all entries.
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// TopOffenders batch-reads the in-kernel LRU map and returns the top-n PIDs
// sorted by total fsync call count (descending).
//
// staleNs is the maximum age of the last seen timestamp before an entry is
// ignored (pass 0 for the default 60 s window).
//
// This is a pure batch read: no per-event wakeup, no ring buffer involvement.
func (l *Loader) TopOffenders(n int, staleNs uint64) []FsyncPIDStat {
	if staleNs == 0 {
		staleNs = 60 * uint64(time.Second)
	}
	// Use CLOCK_MONOTONIC — same time base as bpf_ktime_get_ns() in the kernel.
	now := monotonicNowNs()

	var all []FsyncPIDStat
	var key uint32
	var val FsyncFsyncPidVal // bpf2go-generated type

	iter := l.statsMap.Iterate()
	for iter.Next(&key, &val) {
		// Skip stale entries.  Guard: if monotonicNowNs returned 0 (clock
		// failure), skip the stale check entirely rather than wrapping around.
		if now > 0 && val.LastSeenTs > 0 && now-val.LastSeenTs > staleNs {
			continue
		}
		if val.TotalCalls == 0 {
			continue
		}
		all = append(all, FsyncPIDStat{
			PID:            key,
			Comm:           nullTermU8(val.Comm[:]),
			TotalCalls:     val.TotalCalls,
			TotalLatencyNs: val.TotalLatencyNs,
			MaxLatencyNs:   val.MaxLatencyNs,
			LastSeenTs:     val.LastSeenTs,
		})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("fsync: TopOffenders map iterate", "err", err)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].TotalCalls > all[j].TotalCalls
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// ─── Event consumer ───────────────────────────────────────────────────────────

var syscallNames = [3]string{"fsync", "fdatasync", "sync_file_range"}

// consume reads slow-fsync events from the ring buffer (or perf buffer in compat
// mode) and forwards them to SlowEvents.
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
			slog.Warn("fsync: event read error", "err", err)
			continue
		}

		var raw FsyncFsyncEvent // bpf2go-generated type
		if err := binary.Read(bytes.NewReader(raw_bytes), binary.LittleEndian, &raw); err != nil {
			continue
		}

		name := "fsync"
		if int(raw.SyscallNr) < len(syscallNames) {
			name = syscallNames[raw.SyscallNr]
		}
		comm := nullTermU8(raw.Comm[:])

		select {
		case l.SlowEvents <- model.EBPFEvent{
			Type:      model.EventFsync,
			Timestamp: time.Now(),
			PID:       raw.Tgid,
			Comm:      comm,
			Data: model.FsyncSlowEvent{
				PID:         raw.Tgid,
				TID:         raw.Pid,
				Comm:        comm,
				LatencyUs:   raw.LatencyUs,
				SyscallName: name,
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
