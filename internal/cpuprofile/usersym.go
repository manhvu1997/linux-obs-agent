package cpuprofile

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── User-space symbol resolution via /proc/<pid>/maps + ELF symtabs ──────────
//
// Algorithm for one address:
//  1. Find the executable mapping that contains the address in /proc/<pid>/maps.
//  2. Open the backing ELF file; load .symtab + .dynsym (FUNC symbols only).
//  3. For ET_DYN (PIE/shared lib): load_bias = map_start - map_offset.
//     For ET_EXEC (non-PIE):       load_bias = 0 (sym.Value is absolute).
//  4. Binary-search for the largest sym.Value + load_bias ≤ address.
//
// Cache policy: per-TGID, refreshed every 30 s (covers process lifetime and
// library dlopen events without reading /proc on every stack lookup).
//
// Degraded mode: when ELF loading fails (stripped binary, JVM JIT, etc.) we
// return "libname+offset" so the LLM still knows which library was hot.

type vmMap struct {
	start  uint64
	end    uint64
	offset uint64 // file offset where this mapping starts
	path   string
}

type resolvedSym struct {
	addr uint64 // runtime virtual address
	name string
}

type pidCache struct {
	maps     []vmMap
	syms     []resolvedSym // sorted by addr
	loadedAt time.Time
}

var userCache struct {
	mu    sync.RWMutex
	pids  map[uint32]*pidCache
}

func init() {
	userCache.pids = make(map[uint32]*pidCache)
}

// resolveUser translates a user-space virtual address for process tgid to a
// function name.  Returns "" when resolution is impossible (exited process,
// stripped binary with no symbols and no mapping match).
func resolveUser(tgid uint32, addr uint64) string {
	if addr == 0 {
		return ""
	}
	c := getOrBuildCache(tgid)
	if c == nil {
		return ""
	}
	return c.lookup(addr)
}

func getOrBuildCache(tgid uint32) *pidCache {
	userCache.mu.RLock()
	c, ok := userCache.pids[tgid]
	userCache.mu.RUnlock()
	if ok && time.Since(c.loadedAt) < 30*time.Second {
		return c
	}

	userCache.mu.Lock()
	defer userCache.mu.Unlock()
	// Re-check after lock upgrade.
	c, ok = userCache.pids[tgid]
	if ok && time.Since(c.loadedAt) < 30*time.Second {
		return c
	}
	c = buildCache(tgid)
	if c != nil {
		userCache.pids[tgid] = c
	}
	return c
}

func buildCache(tgid uint32) *pidCache {
	maps := parseMaps(tgid)
	if len(maps) == 0 {
		return nil
	}
	c := &pidCache{maps: maps, loadedAt: time.Now()}

	// Load ELF symbols for each unique backing file.
	seen := make(map[string]bool)
	for _, m := range maps {
		if m.path == "" || strings.HasPrefix(m.path, "[") || seen[m.path] {
			continue
		}
		seen[m.path] = true
		c.syms = append(c.syms, loadELFSyms(m.path, m.start, m.offset)...)
	}

	sort.Slice(c.syms, func(i, j int) bool {
		return c.syms[i].addr < c.syms[j].addr
	})
	return c
}

// parseMaps reads /proc/<tgid>/maps and returns executable-permission entries.
func parseMaps(tgid uint32) []vmMap {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", tgid))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []vmMap
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Format: addr-addr perms offset dev inode [path]
		parts := strings.Fields(sc.Text())
		if len(parts) < 5 {
			continue
		}
		perms := parts[1]
		if len(perms) < 3 || perms[2] != 'x' {
			continue // skip non-executable mappings
		}
		bounds := strings.SplitN(parts[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, e1 := strconv.ParseUint(bounds[0], 16, 64)
		end, e2 := strconv.ParseUint(bounds[1], 16, 64)
		off, e3 := strconv.ParseUint(parts[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		var path string
		if len(parts) >= 6 {
			path = parts[5]
		}
		out = append(out, vmMap{start: start, end: end, offset: off, path: path})
	}
	return out
}

// loadELFSyms loads FUNC symbols from an ELF file and computes their runtime
// virtual addresses for the mapping that starts at mapStart with file offset
// mapOffset.
//
// Load-bias calculation:
//   - ET_DYN (PIE executable or shared library): sym.Value is relative to the
//     load base.  load_bias = mapStart - mapOffset.
//     (mapOffset accounts for cases where the mapping starts mid-file, which
//     happens for the text segment of libraries mapped with a non-zero offset.)
//   - ET_EXEC (non-PIE): sym.Value is already the runtime virtual address;
//     load_bias = 0.
func loadELFSyms(path string, mapStart, mapOffset uint64) []resolvedSym {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	loadBias := uint64(0)
	if f.Type == elf.ET_DYN {
		loadBias = mapStart - mapOffset
	}

	// Collect from both .symtab (stripped binaries may only have .dynsym).
	var raw []elf.Symbol
	if s, err := f.Symbols(); err == nil {
		raw = append(raw, s...)
	}
	if s, err := f.DynamicSymbols(); err == nil {
		raw = append(raw, s...)
	}

	out := make([]resolvedSym, 0, len(raw))
	for _, sym := range raw {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Value == 0 || sym.Name == "" {
			continue
		}
		out = append(out, resolvedSym{
			addr: sym.Value + loadBias,
			name: sym.Name,
		})
	}
	return out
}

// lookup finds the nearest symbol for addr, falling back to "basename+offset"
// when no ELF symbols are available but the mapping is known.
func (c *pidCache) lookup(addr uint64) string {
	// Binary-search: largest sym.addr ≤ addr.
	if len(c.syms) > 0 {
		idx := sort.Search(len(c.syms), func(i int) bool {
			return c.syms[i].addr > addr
		}) - 1
		if idx >= 0 {
			return c.syms[idx].name
		}
	}

	// Degraded: return "libname+offset" so the LLM knows which library was hot.
	for _, m := range c.maps {
		if addr >= m.start && addr < m.end && m.path != "" && !strings.HasPrefix(m.path, "[") {
			base := filepath.Base(m.path)
			return fmt.Sprintf("%s+0x%x", base, addr-m.start+m.offset)
		}
	}
	return ""
}

// purgeUserCache removes stale entries older than maxAge.
// Called periodically by the report builder to prevent unbounded growth.
func purgeUserCache(maxAge time.Duration) {
	userCache.mu.Lock()
	defer userCache.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for pid, c := range userCache.pids {
		if c.loadedAt.Before(cutoff) {
			delete(userCache.pids, pid)
		}
	}
}
