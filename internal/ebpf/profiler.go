package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/cpuprofile"
	"github.com/manhvu1997/linux-obs-agent/internal/ebpf/cpu_profile"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/runq"
)

// Errors returned by ProfilePID. Callers map these onto HTTP status codes.
var (
	// ErrProfileBusy means another profile is already sampling. Profiling is
	// deliberately single-flight: two concurrent perf_event sets would double
	// the sampling cost on an already-stressed node.
	ErrProfileBusy = errors.New("a profile is already running")
	// ErrNoSuchProcess means the requested PID is not present in /proc.
	ErrNoSuchProcess = errors.New("no such process")
	// ErrProfileDisabled means eBPF or on-demand profiling is switched off.
	ErrProfileDisabled = errors.New("on-demand profiling is disabled")
)

// minReuseSamples is the sample floor for reusing the live system-wide
// profiler instead of opening a dedicated sampling window. At 99 Hz this is
// roughly a tenth of a second of on-CPU time.
const minReuseSamples = 10

// ProfileRequest describes one on-demand profiling run.
type ProfileRequest struct {
	// PID is the target process (TGID). All of its threads are sampled.
	PID uint32
	// Duration is the sampling window. Ignored on a cache hit or when the
	// system-wide profiler can be reused.
	Duration time.Duration
	// Folded additionally renders the profile in folded-stacks format.
	Folded bool
}

// ProfileResult is one completed profile.
type ProfileResult struct {
	PID       uint32
	Comm      string
	StartedAt time.Time
	Duration  time.Duration
	SampleHz  uint64
	Report    *model.CPUProfileReport
	Folded    []byte
	// Cached: served from the result cache without sampling.
	Cached bool
	// Reused: extracted from the already-running system-wide profiler
	// without starting a new sampling window.
	Reused bool
}

type profileCacheEntry struct {
	result *ProfileResult
	at     time.Time
}

// profiler holds the on-demand profiling state. It has its own mutex rather
// than reusing Manager.mu, which is held across BPF program loads.
type profiler struct {
	mu      sync.Mutex
	running bool
	cache   map[uint32]profileCacheEntry
}

// ProfilePID samples one process's on-CPU stacks and returns a symbolized,
// flamegraph-ready profile. This is the endpoint behind the ProfileURL on each
// run-queue offender.
//
// Resolution order, cheapest first:
//
//  1. Result cache — a recent profile for the same PID is returned as-is.
//  2. Live system-wide profiler — when the trigger engine has already
//     activated cpu_profile (i.e. the node is hot, which is exactly when an
//     operator clicks through), the target's stacks are already in its counts
//     map. Extract them: zero extra sampling, instant response.
//  3. Dedicated PID-filtered profiler — load a fresh cpu_profile instance
//     filtered to this TGID in-kernel, sample for req.Duration, tear it down.
//
// Deliberately independent of the Activate/cool-down state machine: an
// operator's click must never be silently swallowed by a cool-down window.
func (m *Manager) ProfilePID(ctx context.Context, req ProfileRequest) (*ProfileResult, error) {
	if !m.cfg.Enabled || m.profileCfg == nil || !m.profileCfg.Enabled {
		return nil, ErrProfileDisabled
	}
	if req.PID == 0 {
		return nil, ErrNoSuchProcess
	}
	if req.Duration <= 0 {
		req.Duration = m.profileCfg.DefaultDuration
	}

	// ── 1. Cache ─────────────────────────────────────────────────────────
	if r := m.cachedProfile(req); r != nil {
		return r, nil
	}

	comm, err := readComm(req.PID)
	if err != nil {
		return nil, ErrNoSuchProcess
	}

	// ── 2. Reuse the live system-wide profiler ───────────────────────────
	m.mu.Lock()
	live := m.cpuLoader
	m.mu.Unlock()
	if live != nil {
		// Only reuse when it has collected enough samples for the target to be
		// worth showing; a profiler that started moments ago would otherwise
		// return a handful of samples and hide the real picture.
		if report := cpuprofile.BuildReportForPID(live, req.PID); report != nil &&
			report.System.TotalSamples >= minReuseSamples {
			res := &ProfileResult{
				PID:       req.PID,
				Comm:      comm,
				StartedAt: time.Now(),
				SampleHz:  m.cfg.SampleHz,
				Report:    report,
				Reused:    true,
			}
			if req.Folded {
				res.Folded = renderFolded(live, req.PID)
			}
			m.storeProfile(req.PID, res)
			slog.Debug("profile: reused system-wide profiler", "pid", req.PID)
			return res, nil
		}
		// Too few samples for this PID in the live profiler (it may have just
		// started, or the process is off-CPU) — fall through and sample it
		// directly for the full window.
	}

	// ── 3. Dedicated PID-filtered sampling window ────────────────────────
	if !m.acquireProfileSlot() {
		return nil, ErrProfileBusy
	}
	defer m.releaseProfileSlot()

	profCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	l := cpu_profile.New(cpu_profile.Config{
		SampleHz:   m.cfg.SampleHz,
		TargetTGID: req.PID,
		EmitEvents: false, // counts map is the only data source we need
		MaxEntries: m.profileCfg.MaxMapEntries,
	})
	if err := l.Start(profCtx); err != nil {
		return nil, fmt.Errorf("starting profiler for pid %d: %w", req.PID, err)
	}

	startedAt := time.Now()
	timer := time.NewTimer(req.Duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		// Client went away: stop burning CPU on a profile nobody will read.
		l.Stop()
		return nil, ctx.Err()
	}

	// Build everything BEFORE Stop() — the BPF maps must still be open.
	res := &ProfileResult{
		PID:       req.PID,
		Comm:      comm,
		StartedAt: startedAt,
		Duration:  time.Since(startedAt),
		SampleHz:  m.cfg.SampleHz,
		Report:    cpuprofile.BuildReportForPID(l, req.PID),
	}
	if req.Folded {
		res.Folded = renderFolded(l, req.PID)
	}
	l.Stop()

	m.storeProfile(req.PID, res)
	slog.Info("profile: completed", "pid", req.PID, "comm", comm,
		"duration", res.Duration.Round(time.Millisecond))
	return res, nil
}

// ─── Internal helpers ────────────────────────────────────────────────────────

// cachedProfile returns a copy of the cached result for req, or nil.
// A cached entry without folded output is not reused for a folded request.
func (m *Manager) cachedProfile(req ProfileRequest) *ProfileResult {
	ttl := m.profileCfg.CacheTTL
	if ttl <= 0 {
		return nil
	}
	m.prof.mu.Lock()
	defer m.prof.mu.Unlock()

	e, ok := m.prof.cache[req.PID]
	if !ok || time.Since(e.at) > ttl {
		return nil
	}
	if req.Folded && e.result.Folded == nil {
		return nil
	}

	cp := *e.result
	cp.Cached = true
	if !req.Folded {
		cp.Folded = nil
	}
	return &cp
}

func (m *Manager) storeProfile(pid uint32, res *ProfileResult) {
	if m.profileCfg.CacheTTL <= 0 {
		return
	}
	m.prof.mu.Lock()
	defer m.prof.mu.Unlock()

	if m.prof.cache == nil {
		m.prof.cache = make(map[uint32]profileCacheEntry)
	}
	// Evict expired entries so the map cannot grow without bound across a
	// long-running agent's lifetime.
	for k, v := range m.prof.cache {
		if time.Since(v.at) > m.profileCfg.CacheTTL {
			delete(m.prof.cache, k)
		}
	}
	m.prof.cache[pid] = profileCacheEntry{result: res, at: time.Now()}
}

func (m *Manager) acquireProfileSlot() bool {
	m.prof.mu.Lock()
	defer m.prof.mu.Unlock()
	if m.prof.running {
		return false
	}
	m.prof.running = true
	return true
}

func (m *Manager) releaseProfileSlot() {
	m.prof.mu.Lock()
	m.prof.running = false
	m.prof.mu.Unlock()
}

func renderFolded(l *cpu_profile.Loader, pid uint32) []byte {
	var buf bytes.Buffer
	if _, err := cpuprofile.WriteFolded(l, pid, &buf); err != nil {
		slog.Warn("profile: folded render failed", "pid", pid, "err", err)
		return nil
	}
	return buf.Bytes()
}

// readComm reads /proc/<pid>/comm. Its error doubles as the liveness check for
// the target process.
func readComm(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ─── Run-queue report ────────────────────────────────────────────────────────

// BuildRunQueueReport builds the level-2 run-queue report from the active
// runqlat loader. Returns nil when the module is not active (i.e. the node
// never breached the level-1 threshold) or no process breached level 2.
//
// Called on-demand from GET /api/diagnose; there is no background polling.
func (m *Manager) BuildRunQueueReport(metrics model.NodeMetrics, opt runq.Options) *model.RunQueueAnalysis {
	m.mu.Lock()
	l := m.rqLoader
	m.mu.Unlock()
	if l == nil {
		return nil
	}
	return runq.BuildReport(l, metrics, opt)
}
