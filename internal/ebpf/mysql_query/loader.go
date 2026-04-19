// Package mysql_query provides an always-on MySQL slow-query latency tracer
// via eBPF uprobes on the mysqld binary.
//
// Design: per-PID statistics (total/slow query counts, total/max latency) are
// aggregated in-kernel inside a BPF_MAP_TYPE_LRU_HASH.  TopSlowPIDs() does a
// single batch map read every poll interval – no per-query userspace wakeup.
// Only slow-query outlier events (latency > slow_query_threshold_ns) are emitted
// to the ringbuf.
//
// # Mechanism
//
// Two uprobes are attached to the mysqld binary:
//  1. uprobe  dispatch_command – record start timestamp + SQL text on entry
//  2. uretprobe dispatch_command – compute latency on return, emit if slow
//
// Only COM_QUERY commands (command type == 3) are traced; all other MySQL
// internal commands are filtered out at the uprobe level.
//
// # Lifecycle
//
//	l := NewLoader(100_000_000, "/usr/sbin/mysqld")  // 100ms threshold
//	err := l.Start(ctx)                              // attach uprobes, start consumer
//	stats := l.TopSlowPIDs(10, 0)                   // poll every 5 s
//	l.Stop()
package mysql_query

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Loader manages the mysql_query eBPF module lifecycle.
type Loader struct {
	thresholdNs uint64
	mysqldPath  string // absolute path to the mysqld binary

	objs  MysqlQueryObjects
	links []link.Link
	rd    *ringbuf.Reader

	// SlowEvents receives slow-query outlier events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the ringbuf reader.
	SlowEvents chan model.EBPFEvent
}

// NewLoader creates a Loader.
//   - thresholdNs: minimum query latency in nanoseconds that triggers a ringbuf
//     event (0 → default 100 000 000 ns = 100 ms).
//   - mysqldPath: absolute path to the mysqld binary (0 → "/usr/sbin/mysqld").
func NewLoader(thresholdNs uint64, mysqldPath string) *Loader {
	if thresholdNs == 0 {
		thresholdNs = 100_000_000 // 100 ms
	}
	if mysqldPath == "" {
		mysqldPath = "/usr/sbin/mysqld"
	}
	return &Loader{
		thresholdNs: thresholdNs,
		mysqldPath:  mysqldPath,
		SlowEvents:  make(chan model.EBPFEvent, 256),
	}
}

// Start loads the eBPF objects, configures the slow-query threshold, attaches
// uprobes to dispatch_command in mysqld, and launches the ringbuf consumer.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("mysql_query: removing memlock: %w", err)
	}

	// Load the eBPF spec so we can rewrite const volatile variables before
	// LoadAndAssign commits the rodata section as read-only.
	spec, err := LoadMysqlQuery()
	if err != nil {
		return fmt.Errorf("mysql_query: loading eBPF spec: %w", err)
	}
	if err := spec.Variables["slow_query_threshold_ns"].Set(l.thresholdNs); err != nil {
		slog.Warn("mysql_query: could not set slow_query_threshold_ns", "err", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("mysql_query: loading eBPF objects: %w", err)
	}

	// Open ringbuf reader before attaching probes to avoid missing early events.
	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("mysql_query: opening ringbuf: %w", err)
	}
	l.rd = rd

	// Open the mysqld executable for uprobe attachment.
	// link.OpenExecutable resolves the binary's build-ID from the ELF headers,
	// which is required by the kernel to attach uprobes reliably.
	exe, err := link.OpenExecutable(l.mysqldPath)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: opening executable %s: %w", l.mysqldPath, err)
	}

	// dispatch_command is a C++ function; its ELF symbol name is mangled
	// (e.g. "_Z17dispatch_commandP3THDPK8COM_DATA19enum_server_command").
	// Resolve the actual mangled name by scanning the binary's symbol table
	// so the uprobe attachment works across all MySQL 5.7/8.x builds.
	symbol, err := findCPPSymbol(l.mysqldPath, "dispatch_command")
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: resolving dispatch_command symbol in %s: %w (is mysqld stripped?)", l.mysqldPath, err)
	}
	slog.Debug("mysql_query: resolved dispatch_command symbol", "mangled", symbol)

	// Attach uprobe at dispatch_command entry.
	up, err := exe.Uprobe(symbol, l.objs.UprobeDispatchCommand, nil)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: attaching uprobe %s: %w", symbol, err)
	}
	l.links = append(l.links, up)

	// Attach uretprobe at dispatch_command return.
	urp, err := exe.Uretprobe(symbol, l.objs.UretprobeDispatchCommand, nil)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: attaching uretprobe %s: %w", symbol, err)
	}
	l.links = append(l.links, urp)

	slog.Info("mysql_query: started",
		"threshold_ns", l.thresholdNs,
		"mysqld_path", l.mysqldPath,
		"symbol", symbol,
		"hooks", "uprobe+uretprobe/dispatch_command")
	go l.consume(ctx)
	return nil
}

// Stop detaches all uprobes and releases all kernel resources.
func (l *Loader) Stop() {
	l.cleanup()
	slog.Info("mysql_query: stopped")
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

// MySQLPIDStat is the Go-side view of one mysql_pid_stats_t LRU entry.
type MySQLPIDStat struct {
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
func (l *Loader) TopSlowPIDs(n int, staleNs uint64) []MySQLPIDStat {
	if staleNs == 0 {
		staleNs = 60 * uint64(time.Second)
	}
	now := monotonicNowNs()

	var all []MySQLPIDStat
	var key uint32
	var val MysqlQueryMysqlPidStatsT // bpf2go-generated type

	iter := l.objs.MysqlPidStats.Iterate()
	for iter.Next(&key, &val) {
		if now > 0 && val.LastSeenTs > 0 && now-val.LastSeenTs > staleNs {
			continue
		}
		if val.TotalQueries == 0 {
			continue
		}
		all = append(all, MySQLPIDStat{
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
		slog.Warn("mysql_query: TopSlowPIDs map iterate", "err", err)
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
			slog.Warn("mysql_query: ringbuf read error", "err", err)
			continue
		}

		var raw MysqlQueryMysqlSlowEventT // bpf2go-generated type
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		comm := nullTermU8(raw.Comm[:])
		query := nullTermU8(raw.Query[:])

		select {
		case l.SlowEvents <- model.EBPFEvent{
			Type:      model.EventMySQLQuery,
			Timestamp: time.Now(),
			PID:       raw.Pid,
			Comm:      comm,
			Data: model.MySQLSlowEvent{
				PID:       raw.Pid,
				TID:       raw.Tid,
				LatencyMs: float64(raw.LatencyNs) / 1e6,
				Query:     query,
				Comm:      comm,
				Timestamp: time.Now(),
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

// findCPPSymbol scans the ELF binary at binaryPath for the first function
// symbol whose raw (C++-mangled) name contains substr.
//
// dispatch_command in mysqld is a C++ function, so its ELF symbol name is
// mangled — for example:
//
//	MySQL 8.0: _Z17dispatch_commandP3THDPK8COM_DATA19enum_server_command
//	MySQL 5.7: _Z17dispatch_commandP3THD19enum_server_commandPK8COM_DATA
//
// The mangled name differs across versions and platforms. Searching by
// substring ("dispatch_command") is robust: it matches every known variant
// without hard-coding a version-specific string.
//
// Search order: .symtab (full symbol table, present in unstripped binaries)
// then .dynsym (dynamic symbols, always present). Returns an error when the
// binary is fully stripped and no matching symbol is found.
func findCPPSymbol(binaryPath, substr string) (string, error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return "", fmt.Errorf("elf.Open: %w", err)
	}
	defer f.Close()

	search := func(syms []elf.Symbol) string {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && strings.Contains(s.Name, substr) {
				return s.Name
			}
		}
		return ""
	}

	// Prefer .symtab (full debug symbols) over .dynsym.
	if syms, err := f.Symbols(); err == nil {
		if name := search(syms); name != "" {
			return name, nil
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		if name := search(syms); name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("no function symbol containing %q found in %s", substr, binaryPath)
}

