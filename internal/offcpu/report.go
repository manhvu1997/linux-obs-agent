// Package offcpu builds the off-CPU (blocked-time) diagnostic report.
//
// It is a pure on-demand builder — no goroutines, no polling — mirroring
// internal/cpuprofile, whose symbol caches it reuses.
package offcpu

import (
	"math"
	"sort"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/cpuprofile"
	ebpfoffcpu "github.com/manhvu1997/linux-obs-agent/internal/ebpf/offcpu"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/procinfo"
)

// Options tunes how much detail the report carries.
type Options struct {
	// TopN caps the number of processes reported (0 → 10).
	TopN int
	// MaxStacksPerProc caps blocking sites per process (0 → 5).
	MaxStacksPerProc int
	// MinBlockUs / TrackedStates are echoed into the report so a consumer can
	// interpret it without reading the agent's config.
	MinBlockUs    uint64
	TrackedStates string
}

const (
	defaultTopN             = 10
	defaultMaxStacksPerProc = 5
	// minStackPct drops blocking sites contributing less than this share of a
	// process's blocked time.
	minStackPct = 1.0
)

// BuildReport reads the off-CPU eBPF maps and produces a symbolized report.
// Returns nil when nothing has blocked yet.
func BuildReport(l *ebpfoffcpu.Loader, opt Options) *model.OffCPUReport {
	return buildReport(l, 0, opt)
}

// BuildReportForPID is BuildReport scoped to a single process.
func BuildReportForPID(l *ebpfoffcpu.Loader, tgid uint32, opt Options) *model.OffCPUReport {
	return buildReport(l, tgid, opt)
}

func buildReport(l *ebpfoffcpu.Loader, filterTGID uint32, opt Options) *model.OffCPUReport {
	if opt.TopN <= 0 {
		opt.TopN = defaultTopN
	}
	if opt.MaxStacksPerProc <= 0 {
		opt.MaxStacksPerProc = defaultMaxStacksPerProc
	}

	entries := l.AllStacks()
	if len(entries) == 0 {
		return nil
	}

	// ── Aggregate by process ──────────────────────────────────────────────
	type stackAgg struct {
		kernID, userID int32
		totalNs        uint64
		maxNs          uint64
		events         uint64
	}
	type procData struct {
		tgid    uint32
		comm    string
		threads map[uint32]bool
		totalNs uint64
		maxNs   uint64
		events  uint64
		// keyed by (kern,user) stack pair so identical blocking sites from
		// different threads of the same process fold together.
		stacks map[[2]int32]*stackAgg
	}

	byProc := make(map[uint32]*procData)
	var systemNs, systemEvents uint64

	for _, e := range entries {
		if filterTGID != 0 && e.TGID != filterTGID {
			continue
		}
		p := byProc[e.TGID]
		if p == nil {
			p = &procData{
				tgid:    e.TGID,
				comm:    e.Comm,
				threads: make(map[uint32]bool),
				stacks:  make(map[[2]int32]*stackAgg),
			}
			byProc[e.TGID] = p
		}
		p.threads[e.PID] = true
		p.totalNs += e.TotalNs
		p.events += e.Events
		if e.MaxNs > p.maxNs {
			p.maxNs = e.MaxNs
		}

		k := [2]int32{e.KernStackID, e.UserStackID}
		s := p.stacks[k]
		if s == nil {
			s = &stackAgg{kernID: e.KernStackID, userID: e.UserStackID}
			p.stacks[k] = s
		}
		s.totalNs += e.TotalNs
		s.events += e.Events
		if e.MaxNs > s.maxNs {
			s.maxNs = e.MaxNs
		}

		systemNs += e.TotalNs
		systemEvents += e.Events
	}
	if len(byProc) == 0 || systemNs == 0 {
		return nil
	}

	procs := make([]*procData, 0, len(byProc))
	for _, p := range byProc {
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].totalNs > procs[j].totalNs })
	if len(procs) > opt.TopN {
		procs = procs[:opt.TopN]
	}

	// ── Symbolize ─────────────────────────────────────────────────────────
	out := make([]model.OffCPUProcess, 0, len(procs))
	for _, p := range procs {
		sites := make([]*stackAgg, 0, len(p.stacks))
		for _, s := range p.stacks {
			sites = append(sites, s)
		}
		sort.Slice(sites, func(i, j int) bool { return sites[i].totalNs > sites[j].totalNs })

		var topStacks []model.OffCPUStack
		for _, s := range sites {
			if len(topStacks) >= opt.MaxStacksPerProc {
				break
			}
			pct := round2dp(float64(s.totalNs) / float64(p.totalNs) * 100)
			if pct < minStackPct {
				break // sorted: everything after is smaller too
			}
			syms := combinedStack(l, p.tgid, s.userID, s.kernID)
			if len(syms) == 0 {
				continue // nothing resolved — no signal to show
			}
			topStacks = append(topStacks, model.OffCPUStack{
				SymbolStack:  syms,
				BlockedMs:    nsToMs(s.totalNs),
				MaxBlockedMs: nsToMs(s.maxNs),
				Events:       s.events,
				Percent:      pct,
			})
		}

		// The eBPF comm is a per-thread name (dragonfly names its threads
		// Proactor0, Proactor1, ...). Prefer the process name from /proc so
		// the report identifies the process the PID actually refers to.
		comm := p.comm
		if procComm := procinfo.ReadComm(p.tgid); procComm != "" {
			comm = procComm
		}

		out = append(out, model.OffCPUProcess{
			PID:            p.tgid,
			Comm:           comm,
			Cmdline:        procinfo.ReadCmdline(p.tgid),
			CgroupPath:     procinfo.ReadCgroup(p.tgid),
			BlockedMs:      nsToMs(p.totalNs),
			MaxBlockedMs:   nsToMs(p.maxNs),
			Events:         p.events,
			ThreadsSampled: len(p.threads),
			PercentOfTotal: round2dp(float64(p.totalNs) / float64(systemNs) * 100),
			TopStacks:      topStacks,
		})
	}

	cpuprofile.PurgeUserCache(2 * time.Minute)

	return &model.OffCPUReport{
		Type:      "offcpu_profile",
		Timestamp: time.Now(),
		Window: model.OffCPUWindow{
			MinBlockUs:    opt.MinBlockUs,
			TrackedStates: opt.TrackedStates,
		},
		System: model.OffCPUSystemInfo{
			TotalBlockedMs: nsToMs(systemNs),
			TotalEvents:    systemEvents,
			Processes:      len(byProc),
		},
		Processes: out,
	}
}

// combinedStack renders one blocking site as a single call stack: user frames
// first (outermost → innermost), then the kernel frames that actually blocked,
// each tagged "_[k]".
//
// For off-CPU analysis the combined view is the useful one — the kernel frames
// name the wait (io_schedule, wait_on_page_bit, ...) and the user frames say
// which application path led there.
func combinedStack(l *ebpfoffcpu.Loader, tgid uint32, userID, kernID int32) []string {
	var out []string
	appendFrames(&out, l.StackAddresses(userID), func(a uint64) string {
		return cpuprofile.ResolveUser(tgid, a)
	}, "")
	appendFrames(&out, l.StackAddresses(kernID), cpuprofile.ResolveKernel, "_[k]")
	return out
}

// appendFrames reverses a stack (the kernel returns innermost-first) and
// appends the resolvable frames.
func appendFrames(out *[]string, addrs []uint64, resolve func(uint64) string, suffix string) {
	for i := len(addrs) - 1; i >= 0; i-- {
		if addrs[i] == 0 {
			continue
		}
		if s := resolve(addrs[i]); s != "" {
			*out = append(*out, s+suffix)
		}
	}
}

func nsToMs(ns uint64) float64 { return round2dp(float64(ns) / 1e6) }

func round2dp(f float64) float64 { return math.Round(f*100) / 100 }
