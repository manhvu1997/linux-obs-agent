// Package mysql_query provides an always-on MySQL slow-query latency tracer
// via eBPF uprobes on the mysqld binary.
//
// Design: statements are aggregated in-kernel and drained once per poll
// interval (DrainAgg) – no per-query userspace wakeup. Only slow-query outlier
// events (latency > slow_query_threshold_ns) are emitted to the slow ringbuf.
//
// # Mechanism
//
// Two uprobes are attached to the mysqld binary:
//  1. uprobe  dispatch_command – record start timestamp + SQL text on entry
//  2. uretprobe dispatch_command – compute latency on return, emit if slow
//
// Every command is measured in the kernel and added to an aggregation map
// keyed by {tgid, command, text hash}; DrainAgg returns the sums. Statement
// text is sent once per (command, hash) on TextEvents. CmdEvents carries only
// commands that could not be aggregated (map full, or a hash marked unsafe).
// COM_QUERY and COM_STMT_EXECUTE additionally feed slow-query events.
// With emitAll == false only COM_QUERY is tracked and no per-command events
// are emitted (legacy behaviour).
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
// Disk bytes (ioac) and block-I/O wait (delay accounting) are per-thread
// deltas inside dispatch_command; commit wait comes from optional uprobes on
// InnoDB log_write_up_to. Accounting() and RedoTracking() say which of them
// the running kernel and mysqld provide.
//
// # Lifecycle
//
//	l := NewLoader(100_000_000, "/usr/sbin/mysqld", true) // 100ms threshold
//	err := l.Start(ctx)                                    // attach probes, start consumers
//	rows, _ := l.DrainAgg()                               // per-interval sums, every command
//	ev := <-l.CmdEvents                                   // only commands that could not be aggregated
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
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/mysqldsym"
)

// Loader manages the mysql_query eBPF module lifecycle.
type Loader struct {
	thresholdNs uint64
	mysqldPath  string // absolute path to the mysqld binary
	emitAll     bool

	objs         MysqlQueryObjects
	links        []link.Link
	rd           *ringbuf.Reader
	cmdRd        *ringbuf.Reader
	textRd       *ringbuf.Reader
	aggActive    uint32        // which agg map the kernel writes (mirrors agg_active)
	userDropped  atomic.Uint64 // CmdEvents channel full: commands lost
	textDropped  atomic.Uint64 // TextEvents channel full: re-requested, not lost
	psTracking   atomic.Bool
	redoTracking atomic.Bool
	literalSkip  atomic.Bool
	acct         Accounting // set in Start before any probe runs, read-only afterwards

	// SlowEvents receives slow-query outlier events (latency > threshold).
	// Buffered to 256 so the consume goroutine never blocks the ringbuf reader.
	SlowEvents chan model.EBPFEvent

	// CmdEvents receives the commands that could not be aggregated in the
	// kernel (aggregation map full, or the statement hash marked unsafe via
	// MarkUnsafe), one record per command; every other command is only
	// visible through DrainAgg. Buffered; when full, events are dropped and
	// counted.
	CmdEvents chan CmdEvent

	// TextEvents receives statement texts (first sight and verification
	// samples). Buffered; when full, events are dropped and counted in
	// TextDropped() (a dropped first-sight text is re-requested from the
	// kernel, so no command is lost).
	TextEvents chan TextEvent
}

// CmdEvent is one MySQL command measured in the kernel.
type CmdEvent struct {
	PID, TID, Command, QueryLen                         uint32
	WallNs, CPUNs, RunqNs, BytesOut                     uint64
	DiskReadBytes, DiskWriteBytes, IOWaitNs, RedoWaitNs uint64
	Comm, Query                                         string
}

const cmdEventSize = 608 // sizeof(struct mysql_cmd_event_t)

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
		WallNs: le.Uint64(b[16:]), CPUNs: le.Uint64(b[24:]), RunqNs: le.Uint64(b[32:]), BytesOut: le.Uint64(b[40:]),
		DiskReadBytes: le.Uint64(b[48:]), DiskWriteBytes: le.Uint64(b[56:]), IOWaitNs: le.Uint64(b[64:]), RedoWaitNs: le.Uint64(b[72:]),
		Comm:  nullTermU8(b[80:96]),
		Query: nullTermU8(b[96:cmdEventSize]),
	}, true
}

// Accounting says which per-statement signals the running kernel provides.
type Accounting struct {
	DiskBytes  bool // task_struct.ioac.read_bytes/write_bytes (CONFIG_TASK_IO_ACCOUNTING)
	BlkioDelay bool // task_struct.delays (CONFIG_TASK_DELAY_ACCT); also needs delay accounting switched on
	Redo       bool // log_write_up_to uprobes attached
}

// Accounting is valid after Start.
func (l *Loader) Accounting() Accounting {
	a := l.acct
	a.Redo = l.redoTracking.Load()
	return a
}

// RedoTracking reports whether commit wait (log_write_up_to) is measured.
func (l *Loader) RedoTracking() bool { return l.redoTracking.Load() }

// PreparedTextTracking reports whether the prepared-statement text uprobes
// are attached, i.e. COM_STMT_EXECUTE events carry recovered SQL text unless
// the statement was prepared before the agent attached.
func (l *Loader) PreparedTextTracking() bool { return l.psTracking.Load() }

// Dropped returns commands genuinely lost: fallback command events the
// kernel could not reserve (cmd ring buffer full) plus those dropped in
// userspace because CmdEvents was full. Text events dropped on a full
// TextEvents are not included (see TextDropped). Safe to call before Start.
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

// TextDropped returns text events dropped because TextEvents was full. A
// first-sight text is re-requested from the kernel (its hash's commands are
// attributed once the resend arrives, or to the "text unavailable"
// placeholder after one poll); a verification sample is simply skipped. No
// command is lost, so these are not part of Dropped. Safe to call before
// Start.
func (l *Loader) TextDropped() uint64 { return l.textDropped.Load() }

// LiteralSkip reports whether the kernel hashes statement texts with the
// literal-skipping rule (sqlhash.KernelHash). False after the verifier
// rejected the skipping loop and the module was loaded with exact-text
// hashing (plain FNV-1a): digests are still exact, the kernel just keeps one
// aggregation entry per distinct text instead of per statement shape.
func (l *Loader) LiteralSkip() bool { return l.literalSkip.Load() }

// NewLoader creates a Loader.
//   - thresholdNs: minimum query latency in nanoseconds that triggers a ringbuf
//     event (0 → default 100 000 000 ns = 100 ms).
//   - mysqldPath: absolute path to the mysqld binary (0 → "/usr/sbin/mysqld").
//   - emitAll: measure every command (aggregated in the kernel, read with
//     DrainAgg; CmdEvents only carries commands that could not be
//     aggregated); false keeps the legacy COM_QUERY-only stats + slow events.
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
		TextEvents:  make(chan TextEvent, 4096),
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
	skip, err := loadLiteralSkipFallback(
		func() error { return spec.LoadAndAssign(&l.objs, nil) },
		func() error {
			v := spec.Variables["literal_skip"]
			if v == nil {
				return errors.New("variable literal_skip not found")
			}
			return v.Set(uint8(0))
		})
	if err != nil {
		return fmt.Errorf("mysql_query: loading eBPF objects: %w", err)
	}
	l.literalSkip.Store(skip)
	l.aggActive = 0 // agg_active starts at 0 in every fresh load (also after Stop/Start)

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

	textRd, err := ringbuf.NewReader(l.objs.TextEvents)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: opening text ringbuf: %w", err)
	}
	l.textRd = textRd

	ioac, delays := kernelTaskFields()
	l.acct = Accounting{DiskBytes: ioac, BlkioDelay: delays}

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

	// Commit wait. Optional, and only meaningful when commands are aggregated.
	if l.emitAll {
		if err := hooks.RedoErr; err != nil {
			slog.Warn("mysql_query: commit wait unavailable (no log_write_up_to symbol)", "mysqld_path", l.mysqldPath, "err", err)
		} else if err := l.attachRedo(exe, hooks.Redo); err != nil {
			slog.Warn("mysql_query: commit wait unavailable", "symbol", hooks.Redo, "err", err)
			hooks.RedoErr = err
		} else {
			l.redoTracking.Store(true)
		}
	} else {
		hooks.RedoErr = errors.New("not attached: emit_all_queries is off")
	}
	// The summary reports what is attached, not what resolved.
	hooks.PreparedErr = psErr
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
		"literal_skip", skip,
		"disk_bytes", l.acct.DiskBytes,
		"blkio_delay", l.acct.BlkioDelay,
		"commit_wait", l.redoTracking.Load(),
		"hooks", "uprobe+uretprobe/dispatch_command")
	// The readers are passed by value: cleanup() nils the fields.
	go l.consume(ctx, rd)
	go l.consumeCmd(ctx, cmdRd)
	go l.consumeText(ctx, textRd)
	return nil
}

// loadLiteralSkipFallback runs load. If it fails with a verifier error — the
// 511-iteration literal-skipping loop in text_hash is the program most likely
// to exceed an old kernel's verifier budget — it calls disable (sets the
// read-only literal_skip to 0, so the verifier dead-code-eliminates the loop)
// and retries once. It reports whether literal skipping is in effect.
func loadLiteralSkipFallback(load, disable func() error) (literalSkip bool, err error) {
	err = load()
	if err == nil {
		return true, nil
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return false, err
	}
	if derr := disable(); derr != nil {
		return false, fmt.Errorf("%w (exact-text hashing fallback unavailable: %v)", err, derr)
	}
	if rerr := load(); rerr != nil {
		return false, fmt.Errorf("retry with exact-text hashing after verifier rejection (%v): %w", err, rerr)
	}
	slog.Warn("mysql_query: the verifier rejected literal-skipping text hashing; loaded with exact-text hashing. "+
		"Digests and totals stay exact, but the kernel keeps one aggregation entry per distinct text "+
		"(statements differing only in literals no longer share an entry: more agg map entries, text events and overflow risk)",
		"verifier_error", err)
	return false, nil
}

// Stop detaches all uprobes and releases all kernel resources.
func (l *Loader) Stop() {
	l.cleanup()
	slog.Info("mysql_query: stopped")
}

func (l *Loader) cleanup() {
	l.psTracking.Store(false)
	l.redoTracking.Store(false)
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
	if l.textRd != nil {
		l.textRd.Close()
		l.textRd = nil
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

// attachRedo attaches both log_write_up_to probes, or neither: an entry
// without its return would leave frames open.
func (l *Loader) attachRedo(exe *link.Executable, sym string) error {
	up, err := exe.Uprobe(sym, l.objs.UprobeLogWriteUpTo, nil)
	if err != nil {
		return fmt.Errorf("attaching uprobe %s: %w", sym, err)
	}
	ret, err := exe.Uretprobe(sym, l.objs.UretprobeLogWriteUpTo, nil)
	if err != nil {
		up.Close()
		return fmt.Errorf("attaching uretprobe %s: %w", sym, err)
	}
	l.links = append(l.links, up, ret)
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

// ─── Ringbuf consumer ─────────────────────────────────────────────────────────

// recordReader is the subset of *ringbuf.Reader the consumers use.
type recordReader interface {
	Read() (ringbuf.Record, error)
}

// readErrorBackoff is the pause after an unexpected ring buffer read error,
// so a persistent error does not spin a core.
const readErrorBackoff = 100 * time.Millisecond

// readLoop calls handle for every record read from rd until ctx is cancelled
// or rd is closed (Stop). rd is the reader captured when the goroutine was
// started, never a Loader field (cleanup() nils those). os.ErrDeadlineExceeded
// is retried at once; any other error is logged and retried after
// readErrorBackoff.
func readLoop(ctx context.Context, rd recordReader, name string, handle func([]byte)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			slog.Warn("mysql_query: ring buffer read error", "ringbuf", name, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(readErrorBackoff):
			}
			continue
		}
		handle(rec.RawSample)
	}
}

// consume reads slow-query events from the ringbuf and forwards them to
// SlowEvents.  Exits when ctx is cancelled or the reader is closed (Stop).
func (l *Loader) consume(ctx context.Context, rd recordReader) {
	readLoop(ctx, rd, "events", l.handleSlow)
}

// handleSlow decodes one slow-query event and forwards it to SlowEvents.
func (l *Loader) handleSlow(sample []byte) {
	var raw MysqlQueryMysqlSlowEventT // bpf2go-generated type
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return
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

// consumeCmd forwards per-command events. Never blocks the reader: a full
// channel drops the event and counts it in Dropped().
func (l *Loader) consumeCmd(ctx context.Context, rd recordReader) {
	readLoop(ctx, rd, "cmd_events", func(sample []byte) {
		ev, ok := decodeCmdEvent(sample)
		if !ok {
			return
		}
		select {
		case l.CmdEvents <- ev:
		default:
			l.userDropped.Add(1)
		}
	})
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
