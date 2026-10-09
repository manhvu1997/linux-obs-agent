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
// Every command is measured (wall, on-CPU, run-queue wait, bytes) and emitted
// on cmd_events; COM_QUERY additionally feeds the per-PID stats map and
// slow-query events. With emitAll == false only COM_QUERY is tracked and no
// per-command events are emitted (legacy behaviour).
//
// Prepared statements: COM_STMT_EXECUTE carries only a statement id. Two
// optional uprobes recover its SQL text — Prepared_statement::prepare stores
// the text per Prepared_statement*, Prepared_statement::execute_loop links
// the executing thread to it — so the execute is reported with the text sent
// by the earlier COM_STMT_PREPARE. Both need the symbols in mysqld's symbol
// table; otherwise PreparedTextTracking() is false and executes stay
// anonymous.
//
// Result bytes come from optional kretprobes on tcp_sendmsg and
// unix_stream_sendmsg; when either symbol is unavailable bytes_out stays 0.
//
// # Lifecycle
//
//	l := NewLoader(100_000_000, "/usr/sbin/mysqld", true) // 100ms threshold
//	err := l.Start(ctx)                                    // attach probes, start consumers
//	stats := l.TopSlowPIDs(10, 0)                         // poll every 5 s
//	ev := <-l.CmdEvents                                   // one per command
//	l.Stop()
package mysql_query

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/mysqldsym"
)

// Loader manages the mysql_query eBPF module lifecycle.
type Loader struct {
	thresholdNs uint64
	mysqldPath  string // absolute path to the mysqld binary
	emitAll     bool

	objs        MysqlQueryObjects
	links       []link.Link
	rd          *ringbuf.Reader
	cmdRd       *ringbuf.Reader
	userDropped atomic.Uint64
	psTracking  atomic.Bool

	// SlowEvents receives slow-query outlier events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the ringbuf reader.
	SlowEvents chan model.EBPFEvent

	// CmdEvents receives one record per dispatch_command call when emitAll
	// is set. Buffered; when full, events are dropped and counted.
	CmdEvents chan CmdEvent
}

// CmdEvent is one MySQL command measured in the kernel.
type CmdEvent struct {
	PID, TID, Command, QueryLen uint32
	WallNs, CPUNs, RunqNs       uint64
	BytesIn, BytesOut           uint64
	Comm, Query                 string
}

const cmdEventSize = 584 // sizeof(struct mysql_cmd_event_t)

// decodeCmdEvent reads struct mysql_cmd_event_t by fixed offsets. At up to
// 20k events/s, reflection-based binary.Read would cost several percent of
// a core; this costs a few hundred nanoseconds.
func decodeCmdEvent(b []byte) (CmdEvent, bool) {
	if len(b) < cmdEventSize {
		return CmdEvent{}, false
	}
	le := binary.LittleEndian
	return CmdEvent{
		PID: le.Uint32(b[0:]), TID: le.Uint32(b[4:]), Command: le.Uint32(b[8:]), QueryLen: le.Uint32(b[12:]),
		WallNs: le.Uint64(b[16:]), CPUNs: le.Uint64(b[24:]), RunqNs: le.Uint64(b[32:]),
		BytesIn: le.Uint64(b[40:]), BytesOut: le.Uint64(b[48:]),
		Comm:  nullTermU8(b[56:72]),
		Query: nullTermU8(b[72:cmdEventSize]),
	}, true
}

// PreparedTextTracking reports whether the prepared-statement text uprobes
// are attached, i.e. COM_STMT_EXECUTE events carry recovered SQL text unless
// the statement was prepared before the agent attached.
func (l *Loader) PreparedTextTracking() bool { return l.psTracking.Load() }

// Dropped returns command events lost in the kernel (ring buffer full) plus
// events dropped because CmdEvents was full. Safe to call before Start.
func (l *Loader) Dropped() uint64 {
	total := l.userDropped.Load()
	var perCPU []uint64
	if l.objs.Dropped != nil {
		if err := l.objs.Dropped.Lookup(uint32(0), &perCPU); err == nil {
			for _, v := range perCPU {
				total += v
			}
		}
	}
	return total
}

// NewLoader creates a Loader.
//   - thresholdNs: minimum query latency in nanoseconds that triggers a ringbuf
//     event (0 → default 100 000 000 ns = 100 ms).
//   - mysqldPath: absolute path to the mysqld binary (0 → "/usr/sbin/mysqld").
//   - emitAll: measure every command and emit it on CmdEvents; false keeps the
//     legacy COM_QUERY-only stats + slow events.
func NewLoader(thresholdNs uint64, mysqldPath string, emitAll bool) *Loader {
	if thresholdNs == 0 {
		thresholdNs = 100_000_000 // 100 ms
	}
	if mysqldPath == "" {
		mysqldPath = "/usr/sbin/mysqld"
	}
	return &Loader{
		thresholdNs: thresholdNs,
		mysqldPath:  mysqldPath,
		emitAll:     emitAll,
		SlowEvents:  make(chan model.EBPFEvent, 256),
		CmdEvents:   make(chan CmdEvent, 8192),
	}
}

// Start loads the eBPF objects, configures the slow-query threshold, attaches
// uprobes to dispatch_command in mysqld, and launches the ringbuf consumer.
func (l *Loader) Start(ctx context.Context) error {
	// The probes read registers through struct x86_regs casts; on any other
	// architecture they would return plausible garbage, not "unavailable".
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("mysql_query: eBPF programs support only amd64 (running on %s)", runtime.GOARCH)
	}
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
	var emit uint8
	if l.emitAll {
		emit = 1
	}
	if err := spec.Variables["emit_all_queries"].Set(emit); err != nil {
		slog.Warn("mysql_query: could not set emit_all_queries", "err", err)
	}
	// Resolve every hook before loading: the prepare() register layout is a
	// load-time constant, and an unsupported mysqld must be refused before
	// anything is attached (mysqldsym never guesses a signature).
	syms, err := mysqldsym.ReadELF(l.mysqldPath)
	if err != nil {
		return fmt.Errorf("mysql_query: reading symbols of %s: %w (is mysqld stripped?)", l.mysqldPath, err)
	}
	hooks, err := mysqldsym.Resolve(syms)
	if err != nil {
		return fmt.Errorf("mysql_query: %s: %w", l.mysqldPath, err)
	}
	psErr := hooks.PreparedErr
	if psErr == nil {
		var hasTHD uint8
		if hooks.PrepareLayout == mysqldsym.THDFirst {
			hasTHD = 1
		}
		if err := spec.Variables["ps_prepare_has_thd"].Set(hasTHD); err != nil {
			psErr = fmt.Errorf("setting ps_prepare_has_thd: %w", err)
		}
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

	cmdRd, err := ringbuf.NewReader(l.objs.CmdEvents)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: opening cmd ringbuf: %w", err)
	}
	l.cmdRd = cmdRd

	// Open the mysqld executable for uprobe attachment.
	// link.OpenExecutable resolves the binary's build-ID from the ELF headers,
	// which is required by the kernel to attach uprobes reliably.
	exe, err := link.OpenExecutable(l.mysqldPath)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: opening executable %s: %w", l.mysqldPath, err)
	}

	symbol := hooks.Dispatch

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

	// Prepared-statement text recovery. Optional: without it COM_STMT_EXECUTE
	// is reported under a "text unavailable" placeholder.
	if psErr == nil {
		psErr = l.attachPrepared(exe, hooks)
	}
	if psErr != nil {
		slog.Warn("mysql_query: prepared-statement text tracking unavailable; "+
			"COM_STMT_EXECUTE will be reported without SQL text",
			"mysqld_path", l.mysqldPath, "err", psErr)
	} else {
		l.psTracking.Store(true)
		slog.Info("mysql_query: prepared-statement text tracking enabled",
			"prepare", hooks.Prepare, "execute_loop", hooks.ExecuteLoop, "layout", hooks.PrepareLayout)
	}
	hooks.PreparedErr = psErr // the summary reports what is attached, not what resolved
	slog.Info("mysql_query: mysqld hooks: "+hooks.Summary(), "mysqld_path", l.mysqldPath)

	// Result bytes per command. Optional: without them bytes_out stays 0.
	for _, fn := range []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"tcp_sendmsg", l.objs.KretprobeTcpSendmsg},
		{"unix_stream_sendmsg", l.objs.KretprobeUnixStreamSendmsg},
	} {
		krp, err := attachKretprobeMaxActive(fn.sym, fn.prog)
		if err != nil {
			slog.Warn("mysql_query: bytes_out hook unavailable", "symbol", fn.sym, "err", err)
			continue
		}
		l.links = append(l.links, krp)
	}

	slog.Info("mysql_query: started",
		"threshold_ns", l.thresholdNs,
		"mysqld_path", l.mysqldPath,
		"symbol", symbol,
		"emit_all", l.emitAll,
		"hooks", "uprobe+uretprobe/dispatch_command")
	go l.consume(ctx)
	go l.consumeCmd(ctx)
	return nil
}

// Stop detaches all uprobes and releases all kernel resources.
func (l *Loader) Stop() {
	l.cleanup()
	slog.Info("mysql_query: stopped")
}

func (l *Loader) cleanup() {
	l.psTracking.Store(false)
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	if l.rd != nil {
		l.rd.Close()
		l.rd = nil
	}
	if l.cmdRd != nil {
		l.cmdRd.Close()
		l.cmdRd = nil
	}
	l.objs.Close()
}

// attachPrepared attaches both prepared-statement uprobes, or neither: with
// only one of them every execute would still lack its text.
func (l *Loader) attachPrepared(exe *link.Executable, h mysqldsym.Hooks) error {
	prep, err := exe.Uprobe(h.Prepare, l.objs.UprobePsPrepare, nil)
	if err != nil {
		return fmt.Errorf("attaching uprobe %s: %w", h.Prepare, err)
	}
	run, err := exe.Uprobe(h.ExecuteLoop, l.objs.UprobePsExecuteLoop, nil)
	if err != nil {
		prep.Close()
		return fmt.Errorf("attaching uprobe %s: %w", h.ExecuteLoop, err)
	}
	l.links = append(l.links, prep, run)
	return nil
}

// kretprobeMaxActive raises the number of concurrent kretprobe instances.
// The kernel default is max(10, 2*NCPU); tcp_sendmsg sleeps in
// sk_stream_wait_memory for slow clients (the large-result case), so sleeping
// senders exhaust the default and returns are silently dropped (nmissed).
const kretprobeMaxActive = 2048

// attachKretprobeMaxActive attaches a kretprobe with RetprobeMaxActive set.
// cilium/ebpf v0.21 cannot pass maxactive through the perf_kprobe PMU and
// falls back to tracefs; when that fails (no tracefs mounted, old kernel),
// retry with default options so the hook still attaches.
func attachKretprobeMaxActive(sym string, prog *ebpf.Program) (link.Link, error) {
	krp, err := link.Kretprobe(sym, prog, &link.KprobeOptions{RetprobeMaxActive: kretprobeMaxActive})
	if err == nil {
		return krp, nil
	}
	slog.Info("mysql_query: RetprobeMaxActive could not be applied, retrying with defaults; "+
		"concurrent slow senders may be under-counted",
		"symbol", sym, "maxactive", kretprobeMaxActive, "err", err)
	return link.Kretprobe(sym, prog, nil)
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
		// Never an anonymous blank row: an execute whose text was not
		// recovered gets the same placeholder as its digest.
		query := cmdmap.SlowQueryText(raw.Command, nullTermU8(raw.Query[:]), l.psTracking.Load())

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

// consumeCmd forwards per-command events. Never blocks the reader: a full
// channel drops the event and counts it in Dropped().
func (l *Loader) consumeCmd(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rec, err := l.cmdRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("mysql_query: cmd ringbuf read error", "err", err)
			continue
		}
		ev, ok := decodeCmdEvent(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case l.CmdEvents <- ev:
		default:
			l.userDropped.Add(1)
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
