package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// BlockingHookCollector finds userspace hooks that put OTHER processes into
// uninterruptible sleep.
//
// Why this exists: PSI io pressure and iowait can be high while the block
// device is completely idle. The classic cause is an on-access antivirus or
// audit agent holding a fanotify descriptor in *permission* mode
// (FAN_CLASS_CONTENT / FAN_CLASS_PRE_CONTENT). Every open/read of a watched
// file then blocks the calling task inside fanotify_handle_event() until the
// scanner replies — D state, charged to iowait, with zero disk traffic because
// the file is already in page cache.
//
// Nothing else in the agent can see this: the disk is idle, throughput is
// zero, and a CPU profile cannot observe a sleeping task.
type BlockingHookCollector struct {
	mu       sync.Mutex
	cached   model.BlockingHooks
	cachedAt time.Time
	ttl      time.Duration
}

// fanotify class bits from <linux/fanotify.h>. NOTIF is passive; the other two
// make the kernel wait for a userspace verdict before letting the access
// proceed — that is what turns a scanner into a source of D-state.
const (
	fanClassContent    = 0x04
	fanClassPreContent = 0x08
	fanClassBlocking   = fanClassContent | fanClassPreContent
)

func NewBlockingHookCollector(ttl time.Duration) *BlockingHookCollector {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &BlockingHookCollector{ttl: ttl}
}

// Collect enumerates fanotify holders.
//
// The scan walks /proc/<pid>/fdinfo/<fd> for every process, which is far more
// expensive than the other collectors — so it is cached for ttl and the caller
// only asks for it when I/O pressure is actually elevated.
func (b *BlockingHookCollector) Collect() model.BlockingHooks {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.cachedAt.IsZero() && time.Since(b.cachedAt) < b.ttl {
		return b.cached
	}

	out := model.BlockingHooks{Available: true}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return model.BlockingHooks{}
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		if h, ok := scanFanotify(uint32(pid64), e.Name()); ok {
			out.Fanotify = append(out.Fanotify, h)
			if h.Blocking {
				out.BlockingCount++
			}
		}
	}

	b.cached = out
	b.cachedAt = time.Now()
	return out
}

// scanFanotify reports whether a process holds any fanotify descriptor, and
// whether any of them is in a class that blocks the accessing task.
func scanFanotify(pid uint32, name string) (model.FanotifyHolder, bool) {
	dir := "/proc/" + name + "/fdinfo"
	fds, err := os.ReadDir(dir)
	if err != nil {
		return model.FanotifyHolder{}, false // permission denied or exited
	}

	var h model.FanotifyHolder
	found := false

	for _, fd := range fds {
		f, err := os.Open(dir + "/" + fd.Name())
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "fanotify") {
				continue
			}
			found = true
			// "fanotify flags:10 event-flags:0" — the class bits live here.
			if rest, ok := strings.CutPrefix(line, "fanotify flags:"); ok {
				valStr, _, _ := strings.Cut(rest, " ")
				if v, err := strconv.ParseUint(valStr, 16, 32); err == nil {
					if v&fanClassBlocking != 0 {
						h.Blocking = true
					}
				}
			}
			// "fanotify mnt_id:12 mflags:40 mask:38 ..." — one line per mark.
			if strings.HasPrefix(line, "fanotify mnt_id:") ||
				strings.HasPrefix(line, "fanotify ino:") {
				h.Marks++
			}
		}
		f.Close()
	}

	if !found {
		return model.FanotifyHolder{}, false
	}

	h.PID = pid
	h.Comm = readProcComm(name)
	h.Cmdline = readProcCmdline(name)
	return h, true
}

func readProcComm(name string) string {
	data, err := os.ReadFile("/proc/" + name + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(name string) string {
	data, err := os.ReadFile("/proc/" + name + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
}
