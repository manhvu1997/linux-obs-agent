package offcpu

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/cpuprofile"
	ebpfoffcpu "github.com/manhvu1997/linux-obs-agent/internal/ebpf/offcpu"
	"github.com/manhvu1997/linux-obs-agent/internal/procinfo"
)

// WriteFolded streams the off-CPU profile as folded stacks:
//
//	comm;frame;frame;frame_[k] <microseconds-blocked>
//
// The weight is blocked time in **microseconds**, not sample count — that is
// the off-CPU flamegraph convention, and it makes the flame width read directly
// as "time spent waiting here". Rendered with flamegraph.pl or speedscope this
// produces the standard off-CPU flame graph.
//
// Output goes straight to w so a long profile does not balloon agent memory.
// tgid == 0 emits every process. Returns the number of stacks written.
func WriteFolded(l *ebpfoffcpu.Loader, tgid uint32, w io.Writer) (int, error) {
	entries := l.AllStacks()
	if len(entries) == 0 {
		return 0, nil
	}

	bw := bufio.NewWriter(w)
	written := 0
	commCache := make(map[uint32]string)

	for _, e := range entries {
		if tgid != 0 && e.TGID != tgid {
			continue
		}
		// Blocked time under 1us would fold to a zero-weight line.
		us := e.TotalNs / 1000
		if us == 0 {
			continue
		}

		comm, ok := commCache[e.TGID]
		if !ok {
			comm = procinfo.ReadComm(e.TGID)
			if comm == "" {
				comm = e.Comm
			}
			if comm == "" {
				comm = "pid-" + strconv.FormatUint(uint64(e.TGID), 10)
			}
			commCache[e.TGID] = comm
		}
		bw.WriteString(sanitizeFrame(comm))

		frames := combinedStack(l, e.TGID, e.UserStackID, e.KernStackID)
		if len(frames) == 0 {
			bw.WriteString(";[unknown]")
		}
		for _, f := range frames {
			bw.WriteByte(';')
			bw.WriteString(sanitizeFrame(f))
		}

		bw.WriteByte(' ')
		bw.WriteString(strconv.FormatUint(us, 10))
		bw.WriteByte('\n')
		written++
	}

	cpuprofile.PurgeUserCache(2 * time.Minute)

	// bufio.Writer latches the first write error and no-ops afterwards, so one
	// check here covers the whole stream.
	return written, bw.Flush()
}

// sanitizeFrame strips the two characters that are structural in the folded
// format (';' separates frames, ' ' separates the stack from its weight).
func sanitizeFrame(s string) string {
	if !strings.ContainsAny(s, "; ") {
		return s
	}
	return strings.NewReplacer(";", "_", " ", "_").Replace(s)
}
