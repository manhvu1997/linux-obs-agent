// Package diskscanner implements a low-overhead directory-size scanner with
// growth detection.
//
// Design constraints (from requirements):
//   - Scans only the configured root dirs (/var /home /data /opt /root by default)
//   - Depth-limited walk (default 3 levels) to avoid full-filesystem crawls
//   - Concurrency capped at MaxWorkers (default 5) via a semaphore channel
//   - Scan rate-limited to ScanInterval (default 10 min) — never spams the disk
//   - Skips symlinks, NFS/CIFS mounts, and user-specified ignore patterns
//   - Stores one previous snapshot in memory for growth detection
//   - Triggers a callback when any directory grows > GrowthThresholdPct (20 %)
package diskscanner

import (
	"bufio"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// GrowthCallback is called (in its own goroutine) when abnormal growth is detected.
type GrowthCallback func(events []model.DiskGrowthEvent)

// Scanner periodically measures directory sizes and detects abnormal growth.
type Scanner struct {
	cfg      *config.DiskScanConfig
	onGrowth GrowthCallback

	mu        sync.RWMutex
	prev      *model.DirSnapshot
	curr      *model.DirSnapshot
	growth    []model.DiskGrowthEvent
	nfsMounts map[string]struct{}
}

// New creates a Scanner with the given config.
// onGrowth may be nil if no callback is needed.
func New(cfg *config.DiskScanConfig, onGrowth GrowthCallback) *Scanner {
	return &Scanner{
		cfg:       cfg,
		onGrowth:  onGrowth,
		nfsMounts: make(map[string]struct{}),
	}
}

// Run starts the periodic scan loop.  Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	if !s.cfg.Enabled {
		slog.Info("diskscanner: disabled via config")
		return
	}

	s.refreshNFSMounts()
	// First scan runs immediately so /api/diagnose has data right away.
	s.scan()

	tick := time.NewTicker(s.cfg.ScanInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.refreshNFSMounts()
			s.scan()
		}
	}
}

// Snapshot returns the latest completed scan result (nil if no scan yet).
func (s *Scanner) Snapshot() *model.DirSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.curr
}

// GrowthEvents returns growth events detected in the most recent cycle.
// Returns a copy; safe to read without holding the lock.
func (s *Scanner) GrowthEvents() []model.DiskGrowthEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.DiskGrowthEvent, len(s.growth))
	copy(out, s.growth)
	return out
}

// ─── Internal scan logic ──────────────────────────────────────────────────────

func (s *Scanner) scan() {
	start := time.Now()

	// Semaphore limits concurrent goroutines to MaxWorkers.
	sem := make(chan struct{}, s.cfg.MaxWorkers)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		entries []model.DirEntry
	)

	for _, root := range s.cfg.Dirs {
		// Skip roots that don't exist on this host.
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}

		// Measure each immediate sub-directory independently so that the
		// goroutine fan-out is effective.  Falls back to the root itself when
		// the directory has no sub-directories or is unreadable.
		targets := s.immediateSubdirs(root)

		for _, target := range targets {
			target := target // capture
			wg.Add(1)
			sem <- struct{}{} // acquire slot
			go func() {
				defer wg.Done()
				defer func() { <-sem }() // release slot

				size, count := s.dirSize(target)
				mu.Lock()
				entries = append(entries, model.DirEntry{
					Path:      target,
					SizeBytes: size,
					FileCount: count,
				})
				mu.Unlock()
			}()
		}
	}
	wg.Wait()

	// Sort descending by size; top 10 is a prefix slice (no copy needed).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SizeBytes > entries[j].SizeBytes
	})
	top10 := entries
	if len(top10) > 10 {
		top10 = top10[:10]
	}

	snap := &model.DirSnapshot{
		ScannedAt: start,
		Top10:     top10,
		All:       entries,
	}

	// Swap snapshots and detect growth under a single lock.
	s.mu.Lock()
	s.prev = s.curr
	s.curr = snap
	var growthEvents []model.DiskGrowthEvent
	if s.prev != nil {
		growthEvents = s.detectGrowth(s.prev.All, snap.All)
	}
	s.growth = growthEvents
	s.mu.Unlock()

	elapsed := time.Since(start)
	slog.Debug("diskscanner: scan complete",
		"dirs", len(entries),
		"elapsed", elapsed.Round(time.Millisecond),
		"growth_alerts", len(growthEvents),
	)

	if len(growthEvents) > 0 {
		slog.Warn("diskscanner: abnormal growth detected",
			"count", len(growthEvents),
			"top_path", growthEvents[0].Path,
			"top_growth_pct", growthEvents[0].GrowthPercent,
		)
		if s.onGrowth != nil {
			go s.onGrowth(growthEvents)
		}
	}
}

// immediateSubdirs returns the direct children of root that are directories,
// not ignored, and not on a skip-list mount.  If none are found, returns
// []string{root} so the root itself is measured.
func (s *Scanner) immediateSubdirs(root string) []string {
	des, err := os.ReadDir(root)
	if err != nil {
		slog.Debug("diskscanner: cannot read dir", "path", root, "err", err)
		return []string{root}
	}

	out := make([]string, 0, len(des))
	for _, de := range des {
		if !de.IsDir() {
			continue
		}
		if s.shouldIgnore(de.Name()) {
			continue
		}
		full := filepath.Join(root, de.Name())
		if s.isSkippedMount(full) {
			slog.Debug("diskscanner: skipping mount", "path", full)
			continue
		}
		out = append(out, full)
	}
	if len(out) == 0 {
		return []string{root}
	}
	return out
}

// dirSize walks root up to MaxDepth levels and sums file sizes.
// Symlinks are never followed.  Unreadable entries are silently skipped.
func (s *Scanner) dirSize(root string) (totalBytes int64, fileCount int64) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries without aborting
		}

		// Enforce depth limit relative to root.
		rel, _ := filepath.Rel(root, path)
		if pathDepth(rel) > s.cfg.MaxDepth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// Never follow symlinks — avoids loops and cross-filesystem traversal.
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() && path != root {
			if s.isSkippedMount(path) || s.shouldIgnore(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}

		if !d.IsDir() {
			info, infoErr := d.Info()
			if infoErr == nil {
				totalBytes += info.Size()
				fileCount++
			}
		}
		return nil
	})
	return
}

// detectGrowth compares two entry lists and returns events for directories
// whose size grew by more than GrowthThresholdPct.
func (s *Scanner) detectGrowth(prev, curr []model.DirEntry) []model.DiskGrowthEvent {
	prevMap := make(map[string]int64, len(prev))
	for _, e := range prev {
		prevMap[e.Path] = e.SizeBytes
	}

	now := time.Now()
	var events []model.DiskGrowthEvent
	for _, e := range curr {
		prevSize, seen := prevMap[e.Path]
		if !seen || prevSize == 0 {
			continue
		}
		delta := e.SizeBytes - prevSize
		if delta <= 0 {
			continue
		}
		pct := float64(delta) / float64(prevSize) * 100.0
		if pct >= s.cfg.GrowthThresholdPct {
			events = append(events, model.DiskGrowthEvent{
				Path:          e.Path,
				PrevSizeBytes: prevSize,
				CurrSizeBytes: e.SizeBytes,
				GrowthBytes:   delta,
				GrowthPercent: pct,
				DetectedAt:    now,
			})
		}
	}
	// Sort by growth percentage descending so the worst offender is first.
	sort.Slice(events, func(i, j int) bool {
		return events[i].GrowthPercent > events[j].GrowthPercent
	})
	return events
}

// ─── Mount / ignore helpers ───────────────────────────────────────────────────

// refreshNFSMounts reads /proc/mounts and rebuilds the skip-mount set.
// Called once at startup and then at each scan tick.
func (s *Scanner) refreshNFSMounts() {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return // /proc not available (e.g. macOS in tests); silently skip
	}
	defer f.Close()

	mounts := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		fsType, mountPoint := fields[2], fields[1]

		// Always skip kernel virtual filesystems.
		if strings.HasPrefix(mountPoint, "/proc") ||
			strings.HasPrefix(mountPoint, "/sys") ||
			strings.HasPrefix(mountPoint, "/dev") {
			mounts[mountPoint] = struct{}{}
			continue
		}

		// Skip network/FUSE filesystems when SkipNFS is set.
		if s.cfg.SkipNFS {
			switch fsType {
			case "nfs", "nfs4", "cifs", "smbfs", "fuse", "fuse.sshfs",
				"fuse.s3fs", "davfs", "afs":
				mounts[mountPoint] = struct{}{}
			}
		}
	}

	s.mu.Lock()
	s.nfsMounts = mounts
	s.mu.Unlock()
}

// isSkippedMount reports whether path is a known skip-list mount point.
// Caller must not hold s.mu.
func (s *Scanner) isSkippedMount(path string) bool {
	// Take a quick read-lock to access the mount map.
	s.mu.RLock()
	_, ok := s.nfsMounts[path]
	s.mu.RUnlock()
	return ok
}

// shouldIgnore reports whether a directory name matches any ignore pattern.
// Comparison is case-sensitive (Linux filesystems are).
func (s *Scanner) shouldIgnore(name string) bool {
	for _, pat := range s.cfg.IgnorePatterns {
		if name == pat {
			return true
		}
	}
	return false
}

// pathDepth returns the number of path components in a relative path.
// "." and "" are depth 0.
func pathDepth(rel string) int {
	if rel == "." || rel == "" {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}
