// Package mongo_query provides an always-on MongoDB slow-query latency tracer
// via eBPF syscall tracepoints.
//
// Design: per-PID statistics (total/slow query counts, total/max latency) are
// aggregated in-kernel inside a BPF_MAP_TYPE_LRU_HASH.  TopSlowPIDs() does a
// single batch map read every poll interval – no per-query userspace wakeup.
// Only slow-query outlier events (latency > slow_query_threshold_ns) are emitted
// to the ringbuf.
//
// # Mechanism
//
// Four tracepoints are attached:
//  1. sys_enter_connect  – record the fd when connecting to mongo_port
//  2. sys_enter_write    – start query timer, parse OP_MSG header for op/collection
//  3. sys_enter_read /
//     sys_exit_read      – stop timer on response, emit slow event if needed
//  4. sys_enter_close    – clean up per-fd state
//
// # Lifecycle
//
//	l := NewLoader(2_000_000_000, 27017)  // 2 s threshold, port 27017
//	err := l.Start(ctx)                   // attach tracepoints, start ringbuf consumer
//	stats := l.TopSlowPIDs(10, 0)        // poll every 5 s
//	l.Stop()
package mongo_query

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

// Loader manages the mongo_query eBPF module lifecycle.
type Loader struct {
	thresholdNs uint64
	mongoPort   uint32

	objs  MongoQueryObjects
	links []link.Link
	rd    *ringbuf.Reader

	// SlowEvents receives slow-query outlier events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the ringbuf reader.
	SlowEvents chan model.EBPFEvent
}

// NewLoader creates a Loader.
//   - thresholdNs: minimum query latency in nanoseconds that triggers a ringbuf
//     event (0 → default 2 000 000 000 ns = 2 s).
//   - mongoPort: destination port used to identify MongoDB connections (0 → 27017).
func NewLoader(thresholdNs uint64, mongoPort uint32) *Loader {
	if thresholdNs == 0 {
		thresholdNs = 2_000_000_000
	}
	if mongoPort == 0 {
		mongoPort = 27017
	}
	return &Loader{
		thresholdNs: thresholdNs,
		mongoPort:   mongoPort,
		SlowEvents:  make(chan model.EBPFEvent, 256),
	}
}

// Start loads the eBPF objects, configures thresholds, attaches all tracepoints,
// and launches the ringbuf consumer goroutine.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("mongo_query: removing memlock: %w", err)
	}

	// Load spec before LoadAndAssign so we can rewrite const volatile vars.
	// After LoadAndAssign the rodata section is read-only.
	spec, err := LoadMongoQuery()
	if err != nil {
		return fmt.Errorf("mongo_query: loading eBPF spec: %w", err)
	}
	if err := spec.Variables["slow_query_threshold_ns"].Set(l.thresholdNs); err != nil {
		slog.Warn("mongo_query: could not set slow_query_threshold_ns", "err", err)
	}
	if err := spec.Variables["mongo_port"].Set(l.mongoPort); err != nil {
		slog.Warn("mongo_query: could not set mongo_port", "err", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("mongo_query: loading eBPF objects: %w", err)
	}

	// Open ringbuf reader before attaching probes – avoids missing early events.
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("mongo_query: opening ringbuf: %w", err)
	}
	l.rd = rd

	// Attach the four tracepoints.
	type tpEntry struct {
		group string
		name  string
		prog  *ebpf.Program
	}
	tps := []tpEntry{
		{"syscalls", "sys_enter_connect", l.objs.TpMongoConnect},
		{"syscalls", "sys_enter_write", l.objs.TpMongoWrite},
		{"syscalls", "sys_enter_read", l.objs.TpMongoReadEnter},
		{"syscalls", "sys_exit_read", l.objs.TpMongoReadExit},
		{"syscalls", "sys_enter_close", l.objs.TpMongoClose},
	}
	for _, tp := range tps {
		lnk, lerr := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if lerr != nil {
			l.cleanup()
			return fmt.Errorf("mongo_query: attaching tracepoint %s/%s: %w",
				tp.group, tp.name, lerr)
		}
		l.links = append(l.links, lnk)
	}

	slog.Info("mongo_query: started",
		"threshold_ns", l.thresholdNs,
		"mongo_port", l.mongoPort,
		"hooks", "connect,write,read_enter,read_exit,close")
	go l.consume(ctx)
	return nil
}

// Stop detaches all tracepoints and releases all kernel resources.
func (l *Loader) Stop() {
	l.cleanup()
	slog.Info("mongo_query: stopped")
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

// MongoPIDStat is the Go-side view of one mongo_pid_stats_t LRU entry.
type MongoPIDStat struct {
	PID            uint32
	Comm           string
	TotalQueries   uint64
	SlowQueries    uint64
	TotalLatencyNs uint64
	MaxLatencyNs   uint64
	LastSeenTs     uint64
}

// monotonicNowNs returns the current CLOCK_MONOTONIC time in nanoseconds.
// Must match the time base used by bpf_ktime_get_ns() in the kernel.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// TopSlowPIDs batch-reads the in-kernel LRU map and returns the top-n PIDs
// sorted by slow_queries descending.
//
// staleNs is the maximum age of last_seen_ts before an entry is ignored
// (pass 0 for the default 60 s window).
func (l *Loader) TopSlowPIDs(n int, staleNs uint64) []MongoPIDStat {
	if staleNs == 0 {
		staleNs = 60 * uint64(time.Second)
	}
	now := monotonicNowNs()

	var all []MongoPIDStat
	var key uint32
	var val MongoQueryMongoPidStatsT // bpf2go-generated type

	iter := l.objs.MongoPidStats.Iterate()
	for iter.Next(&key, &val) {
		if now > 0 && val.LastSeenTs > 0 && now-val.LastSeenTs > staleNs {
			continue
		}
		if val.TotalQueries == 0 {
			continue
		}
		all = append(all, MongoPIDStat{
			PID:            key,
			Comm:           nullTermU8(val.Comm[:]),
			TotalQueries:   val.TotalQueries,
			SlowQueries:    val.SlowQueries,
			TotalLatencyNs: val.TotalLatencyNs,
			MaxLatencyNs:   val.MaxLatencyNs,
			LastSeenTs:     val.LastSeenTs,
		})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("mongo_query: TopSlowPIDs map iterate", "err", err)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].SlowQueries > all[j].SlowQueries
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// ─── Ringbuf consumer ─────────────────────────────────────────────────────────

// consume reads slow-query events from the ringbuf and forwards them to
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
			slog.Warn("mongo_query: ringbuf read error", "err", err)
			continue
		}

		var raw MongoQueryMongoSlowEventT // bpf2go-generated type
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		opType := nullTermU8(raw.OpType[:])
		coll := nullTermU8(raw.Collection[:])
		comm := nullTermU8(raw.Comm[:])
		destAddr := formatDestAddr(raw.DestIp, raw.DestPort)

		select {
		case l.SlowEvents <- model.EBPFEvent{
			Type:      model.EventMongoQuery,
			Timestamp: time.Now(),
			PID:       raw.Tgid,
			Comm:      comm,
			Data: model.MongoSlowEvent{
				PID:        raw.Tgid,
				TID:        raw.Pid,
				FD:         raw.Fd,
				RequestID:  raw.RequestId,
				LatencyMs:  float64(raw.LatencyNs) / 1e6,
				OpType:     opType,
				Collection: coll,
				DestAddr:   destAddr,
				Comm:       comm,
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

// formatDestAddr converts a network-byte-order IPv4 address and host-byte-order
// port into a "a.b.c.d:port" string suitable for display.
func formatDestAddr(ipNetOrder uint32, port uint16) string {
	if ipNetOrder == 0 {
		return ""
	}
	ip := net.IP{
		byte(ipNetOrder & 0xFF),
		byte((ipNetOrder >> 8) & 0xFF),
		byte((ipNetOrder >> 16) & 0xFF),
		byte((ipNetOrder >> 24) & 0xFF),
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
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
