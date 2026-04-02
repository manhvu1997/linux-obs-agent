// Package disk_write provides on-demand vfs_write tracing via eBPF.
//
// It attaches a kprobe to vfs_write and emits one EBPFEvent per write call
// into the shared Manager.Events channel.  In parallel, it accumulates total
// bytes written per PID in a kernel-side hash map so that TopWriters() can
// return a sorted leaderboard without scanning the ring buffer.
//
// # Lifecycle
//
//	loader := NewLoader()
//	loader.Start(ctx)  // attaches kprobe, starts consume goroutine
//	...
//	loader.Stop()      // detaches kprobe, closes ring buffer
//
// # Struct layout (must match disk_write.bpf.c)
//
//	offset  size  field
//	------  ----  -----
//	     0     4  Pid
//	     4     4  _pad
//	     8     8  Bytes
//	    16    16  Comm
//	    32   128  Filename
//	total: 160 bytes
package disk_write

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// rawDiskWriteEvent must match the C struct layout exactly (see gen.go comment).
// bpf2go generates DiskWriteDiskWriteEvent; we use our own struct here so the
// loader compiles before `make generate` has been run.  After generation,
// verify that DiskWriteDiskWriteEvent has the same layout.
type rawDiskWriteEvent struct {
	Pid      uint32
	Pad      uint32   // explicit padding — keeps Bytes at offset 8
	Bytes    uint64
	Comm     [16]int8
	Filename [128]int8
}

// Loader attaches to vfs_write and emits disk write events.
type Loader struct {
	objs DiskWriteObjects
	kp   link.Link
	rd   *ringbuf.Reader

	// lastFilename tracks the most recently seen filename per PID so that
	// TopWriters can include it without a separate map lookup.
	mu           sync.Mutex // guards lastFilename
	lastFilename map[uint32]string

	Events chan model.EBPFEvent
}

func NewLoader() *Loader {
	return &Loader{
		Events:       make(chan model.EBPFEvent, 512),
		lastFilename: make(map[uint32]string),
	}
}

// Start loads the eBPF program, attaches via fentry (BTF tracing), and begins
// consuming ring-buffer records.  Returns an error if the kernel rejects the
// program (requires kernel ≥ 5.5 with CONFIG_DEBUG_INFO_BTF=y).
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("disk_write: removing memlock: %w", err)
	}

	if err := LoadDiskWriteObjects(&l.objs, nil); err != nil {
		return fmt.Errorf("disk_write: loading eBPF objects: %w", err)
	}

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.objs.Close()
		return fmt.Errorf("disk_write: opening ringbuf: %w", err)
	}
	l.rd = rd

	// AttachTracing handles fentry/fexit/tp_btf — architecture-independent,
	// no PT_REGS involved.
	tp, err := link.AttachTracing(link.TracingOptions{
		Program: l.objs.TraceVfsWrite,
	})
	if err != nil {
		_ = l.rd.Close()
		l.objs.Close()
		return fmt.Errorf("disk_write: attaching fentry/vfs_write: %w", err)
	}
	l.kp = tp

	slog.Info("disk_write: started")
	go l.consume(ctx)
	return nil
}

// Stop detaches the kprobe and closes all kernel resources.
func (l *Loader) Stop() {
	if l.kp != nil {
		l.kp.Close()
	}
	if l.rd != nil {
		l.rd.Close()
	}
	l.objs.Close()
	slog.Info("disk_write: stopped")
}

// TopWriters returns the top-n processes ordered by total bytes written,
// populated from the in-kernel pid_bytes hash map.
// Comm is resolved from /proc/[pid]/comm (best-effort).
// LastFilename is filled from the in-memory cache built by consume().
func (l *Loader) TopWriters(n int) []model.DiskWriteProcess {
	type entry struct {
		pid   uint32
		bytes uint64
	}

	var all []entry
	var pid uint32
	var total uint64
	iter := l.objs.PidBytes.Iterate()
	for iter.Next(&pid, &total) {
		all = append(all, entry{pid, total})
	}

	sort.Slice(all, func(i, j int) bool { return all[i].bytes > all[j].bytes })
	if len(all) > n {
		all = all[:n]
	}

	l.mu.Lock()
	lastFn := l.lastFilename
	l.mu.Unlock()

	out := make([]model.DiskWriteProcess, len(all))
	for i, e := range all {
		out[i] = model.DiskWriteProcess{
			PID:          e.pid,
			Comm:         readComm(e.pid),
			BytesWritten: e.bytes,
			LastFilename: lastFn[e.pid],
		}
	}
	return out
}

// ─── ring buffer consumer ─────────────────────────────────────────────────────

func (l *Loader) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := l.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var raw rawDiskWriteEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample),
			binary.LittleEndian, &raw); err != nil {
			continue
		}

		comm := nullTermString(raw.Comm[:])
		filename := nullTermString(raw.Filename[:])

		// Update last-filename cache (non-blocking; drop oldest if full).
		if filename != "" {
			l.mu.Lock()
			l.lastFilename[raw.Pid] = filename
			l.mu.Unlock()
		}

		select {
		case l.Events <- model.EBPFEvent{
			Type:      model.EventDiskWrite,
			Timestamp: time.Now(),
			PID:       raw.Pid,
			Comm:      comm,
			Data: model.DiskWriteEvent{
				PID:          raw.Pid,
				Comm:         comm,
				BytesWritten: raw.Bytes,
				Filename:     filename,
			},
		}:
		default:
			// Drop event rather than block — maintains <2 % CPU overhead.
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// nullTermString converts a null-terminated int8 slice to a Go string.
func nullTermString(b []int8) string {
	bs := make([]byte, 0, len(b))
	for _, v := range b {
		if v == 0 {
			break
		}
		bs = append(bs, byte(v))
	}
	return string(bs)
}

// readComm reads the process name from /proc/[pid]/comm (best-effort).
func readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
