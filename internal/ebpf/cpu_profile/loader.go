// Package cpu_profile provides an on-demand CPU profiling eBPF module.
// It attaches a perf_event program to every online CPU at a configurable Hz
// and streams stack-trace samples via a ring buffer.
package cpu_profile

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
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	maxStackDepth = 64
	// defaultMaxEntries matches the max_entries compiled into the .bpf.c maps.
	defaultMaxEntries = 10240
)

// Config controls how the CPU profiler is loaded.
type Config struct {
	// SampleHz is the perf_event sampling frequency.
	SampleHz uint64
	// TargetTGID restricts sampling to a single process (0 = system-wide).
	// Filtering happens in-kernel, so non-target samples cost one comparison.
	TargetTGID uint32
	// EmitEvents enables the per-sample ringbuf stream. Leave false for
	// targeted profiles: the aggregated counts map holds the same data and
	// consuming the stream costs two map lookups per sample.
	EmitEvents bool
	// MaxEntries overrides the counts / stack_traces map sizes (0 = default
	// 10240). Targeted profiles use a smaller value to bound memory.
	MaxEntries uint32
}

// Loader manages the lifecycle of the CPU profiling eBPF program.
type Loader struct {
	cfg      Config
	objs     CpuProfileObjects
	perfFDs  []int // raw perf event fds attached via ioctl
	rd       *ringbuf.Reader
	Events   chan model.EBPFEvent
	done     chan struct{}
	stopOnce sync.Once
}

// New creates a Loader from an explicit Config. Call Start to activate it.
func New(cfg Config) *Loader {
	return &Loader{
		cfg:    cfg,
		Events: make(chan model.EBPFEvent, 512),
		done:   make(chan struct{}),
	}
}

// NewLoader creates a system-wide profiler with the per-sample event stream
// enabled — the configuration used by the trigger-driven cpu_profile module.
func NewLoader(sampleHz uint64) *Loader {
	return New(Config{SampleHz: sampleHz, EmitEvents: true})
}

// Start loads the eBPF program and begins sampling.
func (l *Loader) Start(ctx context.Context) error {
	// Kernels <5.11 need memlock rlimit lifted.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load the CollectionSpec so the const volatile globals and map sizes can
	// be rewritten BEFORE the programs are loaded. Once loaded, .rodata is
	// read-only and Set() fails with "resource is read-only".
	spec, err := LoadCpuProfile()
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}
	if l.cfg.TargetTGID != 0 {
		if err := spec.Variables["target_tgid"].Set(l.cfg.TargetTGID); err != nil {
			return fmt.Errorf("setting target_tgid: %w", err)
		}
	}
	if !l.cfg.EmitEvents {
		if err := spec.Variables["emit_events"].Set(uint8(0)); err != nil {
			slog.Warn("cpu_profile: could not disable emit_events", "err", err)
		}
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

	// Open a ring-buffer reader only when the event stream is in use.
	if l.cfg.EmitEvents {
		rd, err := ringbuf.NewReader(l.objs.Events)
		if err != nil {
			l.objs.Close()
			return fmt.Errorf("opening ringbuf: %w", err)
		}
		l.rd = rd
	}

	// Attach to every online CPU via perf_event using ioctl
	// (link.AttachPerfEvent is not public in cilium/ebpf v0.21.0).
	numCPU := runtime.NumCPU()
	for cpu := 0; cpu < numCPU; cpu++ {
		fd, err := openPerfEvent(l.cfg.SampleHz, cpu)
		if err != nil {
			slog.Warn("cpu_profile: skipping cpu", "cpu", cpu, "err", err)
			continue
		}
		if err := unix.IoctlSetInt(int(fd), unix.PERF_EVENT_IOC_SET_BPF, l.objs.ProfileCpu.FD()); err != nil {
			unix.Close(int(fd))
			slog.Warn("cpu_profile: SET_BPF failed", "cpu", cpu, "err", err)
			continue
		}
		if err := unix.IoctlSetInt(int(fd), unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			unix.Close(int(fd))
			slog.Warn("cpu_profile: ENABLE failed", "cpu", cpu, "err", err)
			continue
		}
		l.perfFDs = append(l.perfFDs, int(fd))
	}

	if len(l.perfFDs) == 0 {
		l.cleanup()
		return errors.New("no CPUs could be attached")
	}

	slog.Info("cpu_profile: started",
		"cpus", len(l.perfFDs), "hz", l.cfg.SampleHz, "target_tgid", l.cfg.TargetTGID)
	if l.cfg.EmitEvents {
		go l.consume(ctx)
	}
	return nil
}

// Stop detaches all links and cleans up. Safe to call more than once.
func (l *Loader) Stop() {
	l.stopOnce.Do(func() {
		close(l.done)
		l.cleanup()
	})
}

func (l *Loader) cleanup() {
	for _, fd := range l.perfFDs {
		unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0) //nolint:errcheck
		unix.Close(fd)
	}
	l.perfFDs = nil
	if l.rd != nil {
		l.rd.Close()
	}
	l.objs.Close()
}

// consume reads events from the ring buffer and publishes them.
func (l *Loader) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.done:
			return
		default:
		}

		rec, err := l.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("cpu_profile: ringbuf read error", "err", err)
			continue
		}

		var raw CpuProfileCpuSampleEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		ev := model.EBPFEvent{
			Type:      model.EventCPUProfile,
			Timestamp: time.Now(),
			PID:       raw.Pid,
			Comm:      nullTermString(raw.Comm[:]),
			Data: model.CPUProfileEvent{
				PID:         raw.Pid,
				Comm:        nullTermString(raw.Comm[:]),
				KernStackID: raw.KernStackId,
				UserStackID: raw.UserStackId,
				// Resolve stacks lazily from the map if needed.
				Ustack: l.resolveStack(raw.UserStackId),
				Kstack: l.resolveStack(raw.KernStackId),
			},
		}

		select {
		case l.Events <- ev:
		default:
			// Drop if consumer is slow – we never block the ring buffer reader.
		}
	}
}

// resolveStack reads a stack trace from the kernel-side stack_traces map.
func (l *Loader) resolveStack(stackID int32) []uint64 {
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

// CountEntry is one raw aggregated sample entry from the in-kernel counts map.
// It corresponds to one unique (pid, tgid, kern_stack_id, user_stack_id, comm) tuple.
type CountEntry struct {
	PID         uint32
	TGID        uint32
	Comm        string
	KernStackID int32
	UserStackID int32
	Count       uint64
}

// AllCounts iterates the full counts map and returns every entry.
// The caller aggregates by TGID, resolves stacks, and computes weights.
func (l *Loader) AllCounts() []CountEntry {
	var entries []CountEntry
	iter := l.objs.Counts.Iterate()
	var k CpuProfileCpuCountKey
	var v uint64
	for iter.Next(&k, &v) {
		entries = append(entries, CountEntry{
			PID:         k.Pid,
			TGID:        k.Tgid,
			Comm:        nullTermString(k.Comm[:]),
			KernStackID: k.KernStackId,
			UserStackID: k.UserStackId,
			Count:       v,
		})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("cpu_profile: AllCounts map iterate", "err", err)
	}
	return entries
}

// StackAddresses resolves a stack ID to a slice of instruction pointer addresses
// by reading the kernel-side stack_traces BPF_MAP_TYPE_STACK_TRACE map.
// Returns nil if stackID < 0 or the entry is not found.
func (l *Loader) StackAddresses(stackID int32) []uint64 {
	return l.resolveStack(stackID)
}

// TopPIDs returns the top-N hottest (pid, stack) entries from the aggregated
// counts map, sorted by sample count desc.
//
// Note this is per unique (pid, tgid, stack-pair, comm) key, not per process —
// a process spread across many stacks occupies several entries. Use
// cpuprofile.BuildReport for a per-process view.
func (l *Loader) TopPIDs(n int) []model.CPUProfileEvent {
	type entry struct {
		key   CpuProfileCpuCountKey
		count uint64
	}

	var entries []entry
	iter := l.objs.Counts.Iterate()
	var k CpuProfileCpuCountKey
	var v uint64
	for iter.Next(&k, &v) {
		entries = append(entries, entry{k, v})
	}
	if err := iter.Err(); err != nil {
		slog.Warn("cpu_profile: TopPIDs map iterate", "err", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	if n > len(entries) {
		n = len(entries)
	}
	result := make([]model.CPUProfileEvent, n)
	for i := 0; i < n; i++ {
		result[i] = model.CPUProfileEvent{
			PID:         entries[i].key.Pid,
			Comm:        nullTermString(entries[i].key.Comm[:]),
			KernStackID: entries[i].key.KernStackId,
			UserStackID: entries[i].key.UserStackId,
			SampleCount: entries[i].count,
		}
	}
	return result
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// openPerfEvent opens a software perf event for CPU clock sampling.
func openPerfEvent(hz uint64, cpu int) (uintptr, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitFreq,
		Sample: hz,
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, -1 /*all procs*/, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return 0, &os.PathError{Op: "perf_event_open", Path: fmt.Sprintf("cpu%d", cpu), Err: err}
	}
	return uintptr(fd), nil
}

func nullTermString(b []int8) string {
	bs := make([]byte, 0, len(b))
	for _, v := range b {
		if v == 0 {
			break
		}
		bs = append(bs, byte(v))
	}
	return string(bs)
}

// Ensure ebpf.Map type is used (avoids import cycle if objs change).
var _ *ebpf.Map
