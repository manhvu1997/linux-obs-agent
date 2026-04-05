// Package ebpf provides the eBPF module manager.
// All eBPF programs are DISABLED at startup and only loaded into the kernel
// when explicitly activated by the trigger engine.  Each activation has an
// automatic expiry after cfg.ActiveDuration, and a cool-down prevents
// re-activation within cfg.CoolDown.
package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/cpuprofile"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/cpu_profile"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/disk_write"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/io_latency"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/runqlat"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/tcp_retransmit"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// ModuleID identifies a specific eBPF module.
type ModuleID string

const (
	ModCPUProfile    ModuleID = "cpu_profile"
	ModIOLatency     ModuleID = "io_latency"
	ModRunQLat       ModuleID = "runqlat"
	ModTCPRetransmit ModuleID = "tcp_retransmit"
	ModDiskWrite     ModuleID = "disk_write"
)

// moduleState tracks the lifecycle of one eBPF module.
type moduleState struct {
	active      bool
	stopFn      context.CancelFunc
	activeSince time.Time
	lastStop    time.Time
}

// Manager owns all eBPF loaders and multiplexes their event channels.
type Manager struct {
	cfg    *config.EBPFConfig
	Events chan model.EBPFEvent

	mu      sync.Mutex
	modules map[ModuleID]*moduleState

	// Concrete loaders – created on first activation.
	cpuLoader  *cpu_profile.Loader
	ioLoader   *io_latency.Loader
	rqLoader   *runqlat.Loader
	tcpLoader  *tcp_retransmit.Loader
	diskLoader *disk_write.Loader
}

func NewManager(cfg *config.EBPFConfig) *Manager {
	return &Manager{
		cfg:     cfg,
		Events:  make(chan model.EBPFEvent, 2048),
		modules: make(map[ModuleID]*moduleState),
	}
}

// Activate starts the given module (if not already active and not in cool-down).
// It returns an error if the kernel rejects the program.
func (m *Manager) Activate(ctx context.Context, id ModuleID) error {
	if !m.cfg.Enabled {
		return fmt.Errorf("eBPF globally disabled")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.modules[id]
	if state == nil {
		state = &moduleState{}
		m.modules[id] = state
	}

	if state.active {
		slog.Debug("ebpf: already active", "module", id)
		return nil
	}

	// Respect cool-down.
	if !state.lastStop.IsZero() && time.Since(state.lastStop) < m.cfg.CoolDown {
		remaining := m.cfg.CoolDown - time.Since(state.lastStop)
		slog.Debug("ebpf: in cool-down", "module", id, "remaining", remaining.Round(time.Second))
		return nil
	}

	modCtx, cancel := context.WithTimeout(ctx, m.cfg.ActiveDuration)

	if err := m.startModule(modCtx, id); err != nil {
		cancel()
		return fmt.Errorf("starting module %s: %w", id, err)
	}

	state.active = true
	state.stopFn = cancel
	state.activeSince = time.Now()

	slog.Info("ebpf: activated", "module", id, "duration", m.cfg.ActiveDuration)

	// Auto-stop after ActiveDuration.
	go func() {
		<-modCtx.Done()
		m.deactivate(id)
	}()

	return nil
}

// Deactivate explicitly stops a module before its timeout.
func (m *Manager) Deactivate(id ModuleID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deactivateUnlocked(id)
}

func (m *Manager) deactivate(id ModuleID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deactivateUnlocked(id)
}

func (m *Manager) deactivateUnlocked(id ModuleID) {
	state := m.modules[id]
	if state == nil || !state.active {
		return
	}
	state.stopFn()
	m.stopModule(id)
	state.active = false
	state.lastStop = time.Now()
	slog.Info("ebpf: deactivated", "module", id,
		"was_active", time.Since(state.activeSince).Round(time.Second))
}

// ActiveModules returns the list of currently running modules.
func (m *Manager) ActiveModules() []ModuleID {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ModuleID
	for id, s := range m.modules {
		if s.active {
			out = append(out, id)
		}
	}
	return out
}

// ─── Internal start/stop ─────────────────────────────────────────────────────

func (m *Manager) startModule(ctx context.Context, id ModuleID) error {
	switch id {
	case ModCPUProfile:
		l := cpu_profile.NewLoader(m.cfg.SampleHz)
		if err := l.Start(ctx); err != nil {
			return err
		}
		m.cpuLoader = l
		go m.fanIn(ctx, l.Events)

	case ModIOLatency:
		l := io_latency.NewLoader(m.cfg.SlowIOThresholdUs)
		if err := l.Start(ctx); err != nil {
			return err
		}
		m.ioLoader = l
		go m.fanIn(ctx, l.Events)

	case ModRunQLat:
		l := runqlat.NewLoader(m.cfg.RunQLatThresholdUs)
		if err := l.Start(ctx); err != nil {
			return err
		}
		m.rqLoader = l
		go m.fanIn(ctx, l.Events)

	case ModTCPRetransmit:
		l := tcp_retransmit.NewLoader()
		if err := l.Start(ctx); err != nil {
			return err
		}
		m.tcpLoader = l
		go m.fanIn(ctx, l.Events)

	case ModDiskWrite:
		l := disk_write.NewLoader()
		if err := l.Start(ctx); err != nil {
			return err
		}
		m.diskLoader = l
		go m.fanIn(ctx, l.Events)

	default:
		return fmt.Errorf("unknown module: %s", id)
	}
	return nil
}

func (m *Manager) stopModule(id ModuleID) {
	switch id {
	case ModCPUProfile:
		if m.cpuLoader != nil {
			m.cpuLoader.Stop()
			m.cpuLoader = nil
		}
	case ModIOLatency:
		if m.ioLoader != nil {
			m.ioLoader.Stop()
			m.ioLoader = nil
		}
	case ModRunQLat:
		if m.rqLoader != nil {
			m.rqLoader.Stop()
			m.rqLoader = nil
		}
	case ModTCPRetransmit:
		if m.tcpLoader != nil {
			m.tcpLoader.Stop()
			m.tcpLoader = nil
		}
	case ModDiskWrite:
		if m.diskLoader != nil {
			m.diskLoader.Stop()
			m.diskLoader = nil
		}
	}
}

// fanIn reads from a module-specific event channel and multiplexes into Events.
func (m *Manager) fanIn(ctx context.Context, src chan model.EBPFEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-src:
			if !ok {
				return
			}
			select {
			case m.Events <- ev:
			default:
				// Drop rather than block – maintain <2% CPU overhead.
			}
		}
	}
}

// CPUTopPIDs returns hot pids from the cpu profiler (if active).
func (m *Manager) CPUTopPIDs(n int) []model.CPUProfileEvent {
	m.mu.Lock()
	l := m.cpuLoader
	m.mu.Unlock()
	if l == nil {
		return nil
	}
	return l.TopPIDs(n)
}

// DiskTopWriters returns the top-n processes by bytes written from the
// disk_write eBPF module (only populated when disk_write is active).
func (m *Manager) DiskTopWriters(n int) []model.DiskWriteProcess {
	m.mu.Lock()
	l := m.diskLoader
	m.mu.Unlock()
	if l == nil {
		return nil
	}
	return l.TopWriters(n)
}

// BuildCPUProfileReport builds a fully-aggregated, symbolized CPUProfileReport
// from the active cpu_profile eBPF loader.  Returns nil when the loader is not
// active or has no data.
//
// This is called on-demand from GET /api/diagnose; symbol resolution (kallsyms
// + ELF) adds a few milliseconds on first call but is cached thereafter.
func (m *Manager) BuildCPUProfileReport() *model.CPUProfileReport {
	m.mu.Lock()
	l := m.cpuLoader
	m.mu.Unlock()
	if l == nil {
		return nil
	}
	return cpuprofile.BuildReport(l)
}
