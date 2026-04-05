// Package cpuprofile transforms raw eBPF cpu_profile samples into a compact,
// symbolized, weighted JSON report optimized for downstream LLM analysis.
package cpuprofile

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Kernel symbol resolution via /proc/kallsyms ──────────────────────────────

type ksym struct {
	addr uint64
	name string
}

type kallsymsResolver struct {
	mu      sync.RWMutex
	entries []ksym    // sorted by addr ascending
	loaded  time.Time
}

var globalKallsyms = &kallsymsResolver{}

// resolveKernel translates a kernel virtual address to the nearest function name.
// Returns "" when the address is 0, the resolver is unavailable, or no symbol
// precedes the address.
//
// /proc/kallsyms is cached for 60 minutes; re-read when the cache expires so
// dynamically loaded modules (KVM, vendor drivers) are eventually reflected.
func resolveKernel(addr uint64) string {
	if addr == 0 {
		return ""
	}
	globalKallsyms.ensure()
	return globalKallsyms.lookup(addr)
}

// ensure loads (or reloads after TTL expiry) the symbol table.
func (r *kallsymsResolver) ensure() {
	r.mu.RLock()
	fresh := !r.loaded.IsZero() && time.Since(r.loaded) < 60*time.Minute
	r.mu.RUnlock()
	if fresh {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Double-check after acquiring write lock.
	if !r.loaded.IsZero() && time.Since(r.loaded) < 60*time.Minute {
		return
	}
	r.load()
}

func (r *kallsymsResolver) load() {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return
	}
	defer f.Close()

	var entries []ksym
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		// Keep only function symbols: T/t = text, W/w = weak.
		// Skip data (D/d/B/b), absolute (A/a), etc.
		switch parts[1] {
		case "T", "t", "W", "w":
		default:
			continue
		}
		name := parts[2]
		entries = append(entries, ksym{addr: addr, name: name})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].addr < entries[j].addr
	})
	r.entries = entries
	r.loaded = time.Now()
}

// lookup performs a binary search for the largest addr ≤ target.
func (r *kallsymsResolver) lookup(addr uint64) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.entries) == 0 {
		return ""
	}
	// Find first entry with addr > target, then step back one.
	idx := sort.Search(len(r.entries), func(i int) bool {
		return r.entries[i].addr > addr
	}) - 1
	if idx < 0 {
		return ""
	}
	return r.entries[idx].name
}
