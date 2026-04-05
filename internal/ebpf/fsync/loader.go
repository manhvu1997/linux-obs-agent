// Package fsync provides on-demand fsync/fdatasync/sync_file_range latency
// tracing via eBPF kprobes.
//
// Design: the primary data path aggregates statistics in-kernel inside a
// BPF_MAP_TYPE_LRU_HASH (10 240 entries, auto-eviction).  TopOffenders() does
// a single batch map read every poll interval – no per-event userspace wakeup.
// Only outlier events (latency > slow_fsync_threshold_us) are emitted to the
// ringbuf, so at 10 k+ fsync/s the ringbuf consumer runs rarely.
//
// # Lifecycle
//
//	l := NewLoader(5000)       // 5 ms slow threshold
//	err := l.Start(ctx)       // attach kprobes, start ringbuf consumer
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
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Loader manages the fsync eBPF module lifecycle.
type Loader struct {
	thresholdUs uint64

	objs  FsyncObjects
	links []link.Link
	rd    *ringbuf.Reader

	// SlowEvents receives outlier events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the ringbuf reader.
	SlowEvents chan model.EBPFEvent
}

// NewLoader creates a Loader.  thresholdUs is the minimum fsync latency in
// microseconds that causes a ringbuf event (0 → default 5 000 µs = 5 ms).
func NewLoader(thresholdUs uint64) *Loader {
	if thresholdUs == 0 {
		thresholdUs = 5000
	}
	return &Loader{
		thresholdUs: thresholdUs,
		SlowEvents:  make(chan model.EBPFEvent, 256),
	}
}

// Start loads the eBPF objects, sets the latency threshold, attaches all six
// kprobe/kretprobe hooks, and launches the ringbuf consumer goroutine.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("fsync: removing memlock: %w", err)
	}

	// Load spec before LoadAndAssign so we can rewrite const volatile vars.
	// After LoadAndAssign the rodata section is read-only.
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

	// Open ringbuf reader before attaching probes – avoids missing early events.
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("fsync: opening ringbuf: %w", err)
	}
	l.rd = rd

	// Attach kprobe/kretprobe pairs for the three syscalls.
	type probeEntry struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}
	hooks := []probeEntry{
		{"__x64_sys_fsync", l.objs.KprobeFsync, false},
		{"__x64_sys_fsync", l.objs.KretprobeFsync, true},
		{"__x64_sys_fdatasync", l.objs.KprobeFdatasync, false},
		{"__x64_sys_fdatasync", l.objs.KretprobeFdatasync, true},
		{"__x64_sys_sync_file_range", l.objs.KprobeSyncFileRange, false},
		{"__x64_sys_sync_file_range", l.objs.KretprobeSyncFileRange, true},
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
			l.cleanup()
			return fmt.Errorf("fsync: attaching %s (ret=%v): %w", h.sym, h.ret, lerr)
		}
		l.links = append(l.links, lnk)
	}

	slog.Info("fsync: started",
		"threshold_us", l.thresholdUs,
		"hooks", "fsync,fdatasync,sync_file_range")
	go l.consume(ctx)
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
	l.objs.Close()
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
// This is a pure batch read: no per-event wakeup, no ringbuf involvement.
func (l *Loader) TopOffenders(n int, staleNs uint64) []FsyncPIDStat {
	if staleNs == 0 {
		staleNs = 60 * uint64(time.Second)
	}
	// Use CLOCK_MONOTONIC — same time base as bpf_ktime_get_ns() in the kernel.
	// Do NOT use time.Now().UnixNano() (wall clock since 1970 ≫ boot-relative ns).
	now := monotonicNowNs()

	var all []FsyncPIDStat
	var key uint32
	var val FsyncFsyncPidVal // bpf2go-generated type

	iter := l.objs.FsyncStats.Iterate()
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

// ─── Ringbuf consumer ─────────────────────────────────────────────────────────

var syscallNames = [3]string{"fsync", "fdatasync", "sync_file_range"}

// consume reads slow-fsync events from the ringbuf and forwards them to
// SlowEvents.  Exits when ctx is cancelled or the reader is closed (Stop).
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
			slog.Warn("fsync: ringbuf read error", "err", err)
			continue
		}

		var raw FsyncFsyncEvent // bpf2go-generated type
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
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
