// Package offcpu provides off-CPU (blocked-time) profiling via eBPF.
//
// Where cpu_profile answers "what is this process running?", offcpu answers
// "what is it waiting on?" — the question behind high iowait, D-state stalls
// and latency that does not show up as CPU usage.
//
// All aggregation happens in-kernel in an LRU map; there is no ring buffer and
// no per-event userspace wakeup. Userspace reads the map once, on demand.
package offcpu

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const maxStackDepth = 64

// Track* are the bits of Config.TrackState.
const (
	// TrackInterruptible attributes ordinary sleeps (epoll, futex, nanosleep).
	// Usually overwhelming noise — enable only when hunting a specific stall.
	TrackInterruptible uint8 = 0x01
	// TrackUninterruptible attributes D-state sleeps. This is the state behind
	// iowait and is the default.
	TrackUninterruptible uint8 = 0x02
)

// defaultMaxEntries matches the max_entries compiled into the .bpf.c maps.
const defaultMaxEntries = 10240

// Config controls how the off-CPU profiler is loaded.
type Config struct {
	// TargetTGID restricts profiling to a single process (0 = system-wide).
	TargetTGID uint32
	// MinBlockUs ignores blocking intervals shorter than this (0 → 1000).
	MinBlockUs uint64
	// MaxBlockUs ignores intervals longer than this sanity cap (0 → 60s).
	MaxBlockUs uint64
	// TrackState is a bitmask of Track* (0 → TrackUninterruptible).
	TrackState uint8
	// MaxEntries overrides the counts / stack_traces map sizes (0 → 10240).
	MaxEntries uint32
}

// Loader manages the off-CPU profiler lifecycle.
type Loader struct {
	cfg      Config
	objs     OffCpuObjects
	links    []link.Link
	stopOnce sync.Once
}

// New creates a Loader. Call Start to activate it.
func New(cfg Config) *Loader {
	if cfg.MinBlockUs == 0 {
		cfg.MinBlockUs = 1000
	}
	if cfg.MaxBlockUs == 0 {
		cfg.MaxBlockUs = 60_000_000
	}
	if cfg.TrackState == 0 {
		cfg.TrackState = TrackUninterruptible
	}
	return &Loader{cfg: cfg}
}

// Start loads the eBPF program and attaches it to sched_switch.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Rewrite the const volatile globals before load; .rodata is read-only
	// once the programs are in the kernel.
	spec, err := LoadOffCpu()
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}
	if l.cfg.TargetTGID != 0 {
		if err := spec.Variables["target_tgid"].Set(l.cfg.TargetTGID); err != nil {
			return fmt.Errorf("setting target_tgid: %w", err)
		}
	}
	if err := spec.Variables["min_block_us"].Set(l.cfg.MinBlockUs); err != nil {
		slog.Warn("offcpu: could not set min_block_us", "err", err)
	}
	if err := spec.Variables["max_block_us"].Set(l.cfg.MaxBlockUs); err != nil {
		slog.Warn("offcpu: could not set max_block_us", "err", err)
	}
	if err := spec.Variables["track_state"].Set(l.cfg.TrackState); err != nil {
		slog.Warn("offcpu: could not set track_state", "err", err)
	}
	if n := l.cfg.MaxEntries; n > 0 && n < defaultMaxEntries {
		for _, name := range []string{"counts", "stack_traces"} {
			if m := spec.Maps[name]; m != nil {
				m.MaxEntries = n
			}
		}
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	lnk, err := link.AttachTracing(link.TracingOptions{Program: l.objs.HandleSwitch})
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("attaching sched_switch: %w", err)
	}
	l.links = append(l.links, lnk)

	slog.Info("offcpu: started",
		"target_tgid", l.cfg.TargetTGID,
		"min_block_us", l.cfg.MinBlockUs,
		"track_state", l.cfg.TrackState)
	return nil
}

// Stop detaches and releases everything. Safe to call more than once.
func (l *Loader) Stop() {
	l.stopOnce.Do(func() {
		for _, lnk := range l.links {
			lnk.Close()
		}
		l.links = nil
		l.objs.Close()
	})
}

// StackEntry is one aggregated blocking site read from the counts map.
type StackEntry struct {
	PID         uint32 // thread id
	TGID        uint32 // process id
	Comm        string
	KernStackID int32
	UserStackID int32
	TotalNs     uint64
	Events      uint64
	MaxNs       uint64
}

// AllStacks iterates the counts map and returns every entry.
// The caller aggregates by TGID, resolves stacks, and computes weights.
func (l *Loader) AllStacks() []StackEntry {
	var entries []StackEntry
	iter := l.objs.Counts.Iterate()
	var k OffCpuOffcpuKey
	var v OffCpuOffcpuVal
	for iter.Next(&k, &v) {
		if v.TotalNs == 0 {
			continue
		}
		entries = append(entries, StackEntry{
			PID:         k.Pid,
			TGID:        k.Tgid,
			Comm:        nullTermU8(k.Comm[:]),
			KernStackID: k.KernStackId,
			UserStackID: k.UserStackId,
			TotalNs:     v.TotalNs,
			Events:      v.Events,
			MaxNs:       v.MaxNs,
		})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("offcpu: AllStacks map iterate", "err", err)
	}
	return entries
}

// StackAddresses resolves a stack ID to instruction pointer addresses.
// Returns nil when stackID < 0 or the entry has been evicted.
func (l *Loader) StackAddresses(stackID int32) []uint64 {
	if stackID < 0 {
		return nil
	}
	var addrs [maxStackDepth]uint64
	if err := l.objs.StackTraces.Lookup(uint32(stackID), unsafe.Pointer(&addrs[0])); err != nil {
		return nil
	}
	var out []uint64
	for _, a := range addrs {
		if a == 0 {
			break
		}
		out = append(out, a)
	}
	return out
}

func nullTermU8(b []uint8) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
