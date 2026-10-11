// Package pg_query is the thin loader of the PostgreSQL statement tracer
// (pg_query.bpf.c). It implements pgtrace.Tracer; all logic lives in
// internal/postgres.
package pg_query

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/kfeat"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// Loader manages the pg_query module. Attach/Detach may be called from the
// discovery goroutine while DrainAgg runs on the poll goroutine.
type Loader struct {
	slowNs uint64

	objs        PgQueryObjects
	mu          sync.Mutex
	links       map[pgtrace.BinaryKey][]link.Link
	textRd      *ringbuf.Reader
	cmdRd       *ringbuf.Reader
	slowRd      *ringbuf.Reader
	attached    map[pgtrace.BinaryKey]pgtrace.Attached
	exitLink    link.Link
	ready       atomic.Bool // objects loaded; false before Start, after a failed Start and after Stop
	aggActive   uint32
	literalSkip atomic.Bool
	acct        pgtrace.Accounting
	textDropped atomic.Uint64
	userDropped atomic.Uint64

	texts chan pgtrace.TextEvent
	cmds  chan pgtrace.CmdEvent
	slows chan pgtrace.SlowEvent
}

var _ pgtrace.Tracer = (*Loader)(nil)

var errNotStarted = errors.New("pg_query: not started")

// NewLoader: slowNs is the slow-interval threshold (0 → 100 ms).
func NewLoader(slowNs uint64) *Loader {
	if slowNs == 0 {
		slowNs = 100_000_000
	}
	return &Loader{slowNs: slowNs, links: map[pgtrace.BinaryKey][]link.Link{}, attached: map[pgtrace.BinaryKey]pgtrace.Attached{},
		texts: make(chan pgtrace.TextEvent, 4096), cmds: make(chan pgtrace.CmdEvent, 8192), slows: make(chan pgtrace.SlowEvent, 256)}
}

func (l *Loader) Texts() <-chan pgtrace.TextEvent { return l.texts }
func (l *Loader) Cmds() <-chan pgtrace.CmdEvent   { return l.cmds }
func (l *Loader) Slows() <-chan pgtrace.SlowEvent { return l.slows }
func (l *Loader) LiteralSkip() bool               { return l.literalSkip.Load() }
func (l *Loader) Accounting() pgtrace.Accounting  { return l.acct }

// Start loads the objects and starts the ring-buffer consumers. Nothing is
// attached until Attach.
func (l *Loader) Start(ctx context.Context) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("pg_query: eBPF programs support only amd64 (running on %s)", runtime.GOARCH)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("pg_query: removing memlock: %w", err)
	}
	spec, err := LoadPgQuery()
	if err != nil {
		return fmt.Errorf("pg_query: loading eBPF spec (kernel >= 5.5 with BTF required; Ubuntu 20.04 needs linux-generic-hwe-20.04): %w", err)
	}
	if err := spec.Variables["slow_threshold_ns"].Set(l.slowNs); err != nil {
		slog.Warn("pg_query: could not set slow_threshold_ns", "err", err)
	}
	skip, err := loadWithFallback(
		func() error { return spec.LoadAndAssign(&l.objs, nil) },
		func() error {
			v := spec.Variables["literal_skip"]
			if v == nil {
				return errors.New("variable literal_skip not found")
			}
			return v.Set(uint8(0))
		})
	if err != nil {
		return fmt.Errorf("pg_query: loading eBPF objects: %w", err)
	}
	l.literalSkip.Store(skip)
	l.aggActive = 0
	for _, r := range []struct {
		m   *ebpf.Map
		dst **ringbuf.Reader
	}{{l.objs.TextEvents, &l.textRd}, {l.objs.CmdEvents, &l.cmdRd}, {l.objs.SlowEvents, &l.slowRd}} {
		rd, err := ringbuf.NewReader(r.m)
		if err != nil {
			l.Stop()
			return fmt.Errorf("pg_query: opening ringbuf: %w", err)
		}
		*r.dst = rd
	}
	// One exit hook per loader: drops a dead task's session so a reused tid
	// never closes a stale interval.
	lk, err := link.Tracepoint("sched", "sched_process_exit", l.objs.TpProcessExit, nil)
	if err != nil {
		l.Stop()
		return fmt.Errorf("pg_query: attaching sched_process_exit: %w", err)
	}
	l.exitLink = lk
	ioac, delays := kfeat.TaskFields()
	l.acct = pgtrace.Accounting{DiskBytes: ioac, BlkioDelay: delays}
	l.ready.Store(true)
	l.consume(ctx)
	slog.Info("pg_query: loaded", "literal_skip", skip, "disk_bytes", ioac, "blkio_delay", delays)
	return nil
}

// loadWithFallback retries once with literal skipping off when the verifier
// rejects the hashing loop (see mysql_query.loadLiteralSkipFallback).
func loadWithFallback(load, disable func() error) (bool, error) {
	err := load()
	if err == nil {
		return true, nil
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return false, err
	}
	if derr := disable(); derr != nil {
		return false, fmt.Errorf("%w (exact-text fallback unavailable: %v)", err, derr)
	}
	if rerr := load(); rerr != nil {
		return false, fmt.Errorf("retry with exact-text hashing after verifier rejection (%v): %w", err, rerr)
	}
	slog.Warn("pg_query: the verifier rejected literal-skipping text hashing; loaded with exact-text hashing (one aggregation entry per distinct text)", "verifier_error", err)
	return false, nil
}

// SetClusters replaces the clusters map: postmaster tgid → BackendState values.
func (l *Loader) SetClusters(m map[uint32]pgtrace.ClusterConst) error {
	if !l.ready.Load() {
		return errNotStarted
	}
	var k uint32
	var v PgQueryClusterCfgT
	var stale []uint32
	it := l.objs.Clusters.Iterate()
	for it.Next(&k, &v) {
		if _, ok := m[k]; !ok {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range stale {
		if err := l.objs.Clusters.Delete(&stale[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	for pm, c := range m {
		pm := pm
		if err := l.objs.Clusters.Put(&pm, &PgQueryClusterCfgT{StateRunning: c.Running, StateFastpath: c.Fastpath}); err != nil {
			return fmt.Errorf("pg_query: clusters map: %w", err)
		}
	}
	return nil
}

// Attach attaches the probes to one binary. Repeat calls return the stored
// result, attaching only a hook (SyncRep, QueryID) newly requested. Required
// hooks failing detaches everything for that binary; optional ones degrade.
func (l *Loader) Attach(b pgtrace.Binary) (pgtrace.Attached, error) {
	if !l.ready.Load() {
		return pgtrace.Attached{}, errNotStarted
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	got, existing := l.attached[b.Key]
	needSyncRep := b.SyncRep && !got.SyncRep && b.Hooks.SyncRep != ""
	needQueryID := b.QueryID && !got.QueryID && b.Hooks.QueryID != ""
	if existing && !needSyncRep && !needQueryID {
		return got, nil
	}
	exe, err := link.OpenExecutable(b.Path)
	if err != nil {
		return got, fmt.Errorf("pg_query: opening %s: %w", b.Path, err)
	}
	ls := l.links[b.Key]
	closeAll := func() {
		for _, lk := range ls {
			lk.Close()
		}
	}
	probe := func(sym string, prog *ebpf.Program, ret bool) error {
		var lk link.Link
		var err error
		if ret {
			lk, err = exe.Uretprobe(sym, prog, nil)
		} else {
			lk, err = exe.Uprobe(sym, prog, nil)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", sym, err)
		}
		ls = append(ls, lk)
		return nil
	}
	pair := func(sym string, up, ret *ebpf.Program) bool {
		if sym == "" {
			return false
		}
		n := len(ls)
		if err := probe(sym, up, false); err != nil {
			slog.Warn("pg_query: optional hook unavailable", "path", b.Path, "err", err)
			return false
		}
		if err := probe(sym, ret, true); err != nil {
			ls[n].Close()
			ls = ls[:n]
			slog.Warn("pg_query: optional hook unavailable", "path", b.Path, "err", err)
			return false
		}
		return true
	}
	if !existing {
		if err := probe(b.Hooks.Activity, l.objs.UprobeReportActivity, false); err != nil {
			closeAll()
			return got, fmt.Errorf("pg_query: %s: %w", b.Path, err)
		}
		if err := probe(b.Hooks.PortalRun, l.objs.UprobePortalRun, false); err != nil {
			closeAll()
			return got, fmt.Errorf("pg_query: %s: %w", b.Path, err)
		}
		got.WAL = pair(b.Hooks.XLogFlush, l.objs.UprobeXlogFlush, l.objs.UretprobeXlogFlush)
		got.Parallel = pair(b.Hooks.Parallel, l.objs.UprobeParallelMain, l.objs.UretprobeParallelMain)
	}
	if b.SyncRep && !got.SyncRep {
		got.SyncRep = pair(b.Hooks.SyncRep, l.objs.UprobeSyncRep, l.objs.UretprobeSyncRep)
	}
	if b.QueryID && !got.QueryID && b.Hooks.QueryID != "" {
		if err := probe(b.Hooks.QueryID, l.objs.UprobeQueryId, false); err != nil {
			slog.Warn("pg_query: queryid hook unavailable", "path", b.Path, "err", err)
		} else {
			got.QueryID = true
		}
	}
	l.links[b.Key] = ls
	l.attached[b.Key] = got
	return got, nil
}

// Detach removes one binary's probes.
func (l *Loader) Detach(key pgtrace.BinaryKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, lk := range l.links[key] {
		lk.Close()
	}
	delete(l.links, key)
	delete(l.attached, key)
}

// DetachAll removes every probe (circuit breaker, Stop).
func (l *Loader) DetachAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, ls := range l.links {
		for _, lk := range ls {
			lk.Close()
		}
		delete(l.links, k)
		delete(l.attached, k)
	}
}

// Stop detaches and releases everything.
func (l *Loader) Stop() {
	l.ready.Store(false)
	l.DetachAll()
	if l.exitLink != nil {
		l.exitLink.Close()
		l.exitLink = nil
	}
	for _, rd := range []**ringbuf.Reader{&l.textRd, &l.cmdRd, &l.slowRd} {
		if *rd != nil {
			(*rd).Close()
			*rd = nil
		}
	}
	l.objs.Close()
}
