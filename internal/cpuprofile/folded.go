package cpuprofile

import (
	"bufio"
	"io"
	"strconv"
	"time"

	cpu_profile "github.com/manhvu1997/linux-obs-agent/internal/ebpf/cpu_profile"
)

// WriteFolded streams the profile as Brendan Gregg's "folded stacks" format:
//
//	comm;frame;frame;frame <count>
//
// one line per unique stack, frames ordered outermost → innermost. Kernel
// frames are suffixed with "_[k]" so they are visually distinguishable, which
// is the convention flamegraph.pl and speedscope both understand.
//
// Output is written straight through to w (an http.ResponseWriter in practice)
// rather than being buffered into a string, so a long profile does not balloon
// agent memory.
//
// tgid == 0 emits every process; otherwise only the matching one.
// Returns the number of stacks written.
func WriteFolded(l *cpu_profile.Loader, tgid uint32, w io.Writer) (int, error) {
	counts := l.AllCounts()
	if len(counts) == 0 {
		return 0, nil
	}

	bw := bufio.NewWriter(w)
	written := 0

	for _, e := range counts {
		if tgid != 0 && e.TGID != tgid {
			continue
		}

		comm := e.Comm
		if comm == "" {
			comm = "pid-" + strconv.FormatUint(uint64(e.TGID), 10)
		}
		bw.WriteString(comm)

		// User stack first (outermost → innermost), then kernel frames on top:
		// that ordering makes the kernel portion appear at the tip of the
		// flame, matching how on-CPU flamegraphs are conventionally read.
		wroteFrame := writeStack(bw, l, e.UserStackID, func(a uint64) string {
			return resolveUser(e.TGID, a)
		}, "")
		wroteFrame = writeStack(bw, l, e.KernStackID, resolveKernel, "_[k]") || wroteFrame

		if !wroteFrame {
			// No symbol resolved anywhere in this stack — nothing to show.
			bw.WriteString(";[unknown]")
		}

		bw.WriteByte(' ')
		bw.WriteString(strconv.FormatUint(e.Count, 10))
		bw.WriteByte('\n')
		written++
	}

	// Evict stale per-PID symbol caches, as BuildReport does.
	purgeUserCache(2 * time.Minute)

	// bufio.Writer latches the first write error and no-ops afterwards, so a
	// single check here covers the whole stream.
	return written, bw.Flush()
}

// writeStack appends the frames of one stack ID in outermost-first order.
// Returns true if at least one frame resolved to a symbol.
func writeStack(
	bw *bufio.Writer,
	l *cpu_profile.Loader,
	stackID int32,
	resolve func(uint64) string,
	suffix string,
) bool {
	if stackID < 0 {
		return false
	}
	addrs := l.StackAddresses(stackID)
	if len(addrs) == 0 {
		return false
	}

	// StackAddresses returns innermost-first; folded format wants the reverse.
	any := false
	for i := len(addrs) - 1; i >= 0; i-- {
		if addrs[i] == 0 {
			continue
		}
		sym := resolve(addrs[i])
		if sym == "" {
			continue
		}
		bw.WriteByte(';')
		bw.WriteString(sanitizeFrame(sym))
		bw.WriteString(suffix)
		any = true
	}
	return any
}

// sanitizeFrame strips the two characters that are structural in the folded
// format (';' separates frames, ' ' separates the stack from its count).
func sanitizeFrame(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] == ';' || s[i] == ' ' {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] == ';' || b[i] == ' ' {
			b[i] = '_'
		}
	}
	return string(b)
}
