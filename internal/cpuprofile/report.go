package cpuprofile

import (
	"math"
	"sort"
	"time"

	cpu_profile "github.com/manhvu1997/linux-obs-agent/internal/ebpf/cpu_profile"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Processing constants (see spec requirements).
const (
	maxUserStacksPerProc   = 5
	maxKernStacksPerProc   = 5
	maxKernelAggFunctions  = 10
	minProcessPctThreshold = 1.0 // drop processes contributing < 1% of total
	minStackPctThreshold   = 1.0 // drop individual stacks contributing < 1% of process
)

// BuildReport reads the current cpu_profile eBPF maps and produces a
// fully-aggregated, symbolized CPUProfileReport.
//
// Pipeline:
//  1. Read all (key, count) entries from the in-kernel counts map.
//  2. Aggregate by TGID (process): total, per-user-stack, per-kernel-stack.
//  3. For each process sort stacks by count; take top-N; resolve addresses.
//  4. Compute percent weights (rounded to 2 dp).
//  5. Drop stacks where all addresses fail symbol resolution.
//  6. Build system-wide kernel function aggregate (top-10).
//
// Returns nil when the loader has no data yet or every process is below the
// noise threshold.
func BuildReport(l *cpu_profile.Loader) *model.CPUProfileReport {
	counts := l.AllCounts()
	if len(counts) == 0 {
		return nil
	}

	// ── 1. Aggregate by TGID ──────────────────────────────────────────────
	type procData struct {
		comm        string
		tgid        uint32
		threads     map[uint32]bool
		userStacks  map[int32]uint64 // user_stack_id → sample count
		kernStacks  map[int32]uint64 // kern_stack_id → sample count
		total       uint64
		userTotal   uint64
		kernTotal   uint64
	}

	byProc := make(map[uint32]*procData)
	for _, e := range counts {
		p := byProc[e.TGID]
		if p == nil {
			p = &procData{
				comm:       e.Comm,
				tgid:       e.TGID,
				threads:    make(map[uint32]bool),
				userStacks: make(map[int32]uint64),
				kernStacks: make(map[int32]uint64),
			}
			byProc[e.TGID] = p
		}
		p.threads[e.PID] = true
		p.total += e.Count
		if e.UserStackID >= 0 {
			p.userStacks[e.UserStackID] += e.Count
			p.userTotal += e.Count
		}
		if e.KernStackID >= 0 {
			p.kernStacks[e.KernStackID] += e.Count
			p.kernTotal += e.Count
		}
	}

	// ── 2. Compute system totals ──────────────────────────────────────────
	var totalSamples, userSamples, kernelSamples uint64
	for _, p := range byProc {
		totalSamples += p.total
		userSamples += p.userTotal
		kernelSamples += p.kernTotal
	}
	if totalSamples == 0 {
		return nil
	}

	// ── 3. Sort processes by total samples desc ───────────────────────────
	procs := make([]*procData, 0, len(byProc))
	for _, p := range byProc {
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].total > procs[j].total
	})

	// ── 4. Build per-process output + feed kernel aggregate ───────────────
	kernFuncAgg := make(map[string]uint64) // symbol → total samples

	var outProcs []model.CPUProfileProcess
	for _, p := range procs {
		pctOfSystem := float64(p.total) / float64(totalSamples) * 100
		if pctOfSystem < minProcessPctThreshold {
			break // list is sorted; all remaining are also below threshold
		}

		// Resolve top user stacks.
		topUser := resolveTopStacks(
			p.userStacks, p.total, maxUserStacksPerProc,
			func(id int32) []uint64 { return l.StackAddresses(id) },
			func(addr uint64) string { return resolveUser(p.tgid, addr) },
		)

		// Resolve top kernel stacks + contribute to global kernel aggregate.
		topKern := resolveTopStacks(
			p.kernStacks, p.total, maxKernStacksPerProc,
			func(id int32) []uint64 { return l.StackAddresses(id) },
			func(addr uint64) string { return resolveKernel(addr) },
		)

		// Feed kernel aggregate: attribute samples to each function in the stack.
		// Each address in a kernel stack shares the stack's sample weight.
		for kernID, cnt := range p.kernStacks {
			addrs := l.StackAddresses(kernID)
			for _, addr := range addrs {
				if sym := resolveKernel(addr); sym != "" {
					kernFuncAgg[sym] += cnt
				}
			}
		}

		op := model.CPUProfileProcess{
			PID:     p.tgid,
			Comm:    p.comm,
			Samples: p.total,
			Threads: len(p.threads),
		}
		if p.userTotal > 0 {
			op.UserSamples = p.userTotal
		}
		if p.kernTotal > 0 {
			op.KernelSamples = p.kernTotal
		}
		if len(topUser) > 0 {
			op.TopUserStacks = topUser
		}
		if len(topKern) > 0 {
			op.TopKernStacks = topKern
		}
		outProcs = append(outProcs, op)
	}

	// ── 5. Build kernel function aggregate (top-10) ───────────────────────
	type kfEntry struct {
		sym     string
		samples uint64
	}
	kfList := make([]kfEntry, 0, len(kernFuncAgg))
	for sym, cnt := range kernFuncAgg {
		kfList = append(kfList, kfEntry{sym, cnt})
	}
	sort.Slice(kfList, func(i, j int) bool {
		return kfList[i].samples > kfList[j].samples
	})
	if len(kfList) > maxKernelAggFunctions {
		kfList = kfList[:maxKernelAggFunctions]
	}

	var kernAgg []model.KernelAggEntry
	for _, e := range kfList {
		if kernelSamples == 0 {
			break
		}
		pct := round2dp(float64(e.samples) / float64(kernelSamples) * 100)
		if pct < minStackPctThreshold {
			continue
		}
		kernAgg = append(kernAgg, model.KernelAggEntry{
			Symbol:  e.sym,
			Samples: e.samples,
			Percent: pct,
		})
	}

	// ── 6. Evict stale user-symbol caches ─────────────────────────────────
	purgeUserCache(2 * time.Minute)

	return &model.CPUProfileReport{
		Type:      "cpu_profile_v2",
		Timestamp: time.Now(),
		System: model.CPUProfileSystemInfo{
			TotalSamples:  totalSamples,
			UserSamples:   userSamples,
			KernelSamples: kernelSamples,
		},
		Processes:       outProcs,
		KernelAggregate: kernAgg,
	}
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// resolveTopStacks sorts stack entries by sample count, resolves addresses to
// symbols, and returns the top-N CPUStack entries above the noise threshold.
//
// Stacks are dropped (not included in output) when:
//   - All addresses in the stack fail symbol resolution (no signal).
//   - The stack's sample count is below minStackPctThreshold of procTotal.
func resolveTopStacks(
	stackCounts map[int32]uint64,
	procTotal uint64,
	topN int,
	getAddrs func(int32) []uint64,
	resolveAddr func(uint64) string,
) []model.CPUStack {
	type entry struct {
		id    int32
		count uint64
	}
	entries := make([]entry, 0, len(stackCounts))
	for id, cnt := range stackCounts {
		entries = append(entries, entry{id, cnt})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	var out []model.CPUStack
	for _, e := range entries {
		if len(out) >= topN {
			break
		}
		pct := round2dp(float64(e.count) / float64(procTotal) * 100)
		if pct < minStackPctThreshold {
			break // sorted: all remaining are also below threshold
		}

		addrs := getAddrs(e.id)
		if len(addrs) == 0 {
			continue // stack ID not in map (already evicted)
		}

		// Resolve addresses; drop zero-address sentinels and empty results.
		var syms []string
		for _, addr := range addrs {
			if addr == 0 {
				break
			}
			if s := resolveAddr(addr); s != "" {
				syms = append(syms, s)
			}
		}
		if len(syms) == 0 {
			continue // all addresses failed resolution → drop per spec
		}

		out = append(out, model.CPUStack{
			SymbolStack: syms,
			Samples:     e.count,
			Percent:     pct,
		})
	}
	return out
}

// round2dp rounds f to 2 decimal places.
func round2dp(f float64) float64 {
	return math.Round(f*100) / 100
}
