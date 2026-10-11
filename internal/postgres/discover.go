// Package postgres attributes PostgreSQL CPU and disk load to query digests,
// background backend types and the cluster's process family, from the
// pg_query eBPF tracer (through pgtrace.Tracer), /proc and, optionally,
// pg_stat_statements.
package postgres

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
)

// procFS is the /proc access discovery needs; tests use a fake.
type procFS interface {
	PIDs() ([]uint32, error)
	Comm(pid uint32) (string, error)
	PPID(pid uint32) (uint32, error)
	Cmdline(pid uint32) (string, error)
	ExeKey(pid uint32) (pgtrace.BinaryKey, error)
	ReadFile(name string) ([]byte, error)
	Cgroup(pid uint32) (string, error)
}

// Postmaster is one running PostgreSQL cluster's main process.
type Postmaster struct {
	PID     uint32
	Exe     string // /proc/<pid>/exe: reaches a binary replaced on disk
	Key     pgtrace.BinaryKey
	DataDir string
	Port    int
	Unit    string // innermost *.service of its cgroup, "" when none
	Cgroup  string // full /proc/<pid>/cgroup content
}

// Discover returns every postmaster, by PID. A postmaster is a process named
// "postgres" whose parent is not, and whose command line is not a backend
// title ("postgres: …") — an orphaned backend reparented to init is not a
// postmaster.
func Discover(p procFS) ([]Postmaster, error) {
	pids, err := p.PIDs()
	if err != nil {
		return nil, err
	}
	var out []Postmaster
	for _, pid := range pids {
		if comm, err := p.Comm(pid); err != nil || comm != "postgres" {
			continue
		}
		if cmd, err := p.Cmdline(pid); err != nil || strings.HasPrefix(cmd, "postgres: ") {
			continue
		}
		ppid, err := p.PPID(pid)
		if err != nil {
			continue
		}
		if pc, err := p.Comm(ppid); err == nil && pc == "postgres" {
			continue
		}
		key, err := p.ExeKey(pid)
		if err != nil {
			continue
		}
		pm := Postmaster{PID: pid, Exe: fmt.Sprintf("/proc/%d/exe", pid), Key: key}
		// postmaster.pid in the data directory (its cwd): line 2 data dir,
		// line 4 port. Read through /proc/<pid>/cwd, which crosses mount
		// namespaces (containers).
		if b, err := p.ReadFile(fmt.Sprintf("/proc/%d/cwd/postmaster.pid", pid)); err == nil {
			pm.DataDir, pm.Port = parsePostmasterPid(b)
		}
		if cg, err := p.Cgroup(pid); err == nil {
			pm.Cgroup = cg
			if f := process.FamilyKey(cg, process.FamilyBySystemdUnit); strings.HasSuffix(f, ".service") {
				pm.Unit = f
			}
		}
		out = append(out, pm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

func parsePostmasterPid(b []byte) (dataDir string, port int) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan() && n <= 4; n++ {
		switch n {
		case 2:
			dataDir = strings.TrimSpace(sc.Text())
		case 4:
			port, _ = strconv.Atoi(strings.TrimSpace(sc.Text()))
		}
	}
	return dataDir, port
}

var containerID = regexp.MustCompile(`[0-9a-f]{12,64}`)

// containerOf returns the first 12 hex digits of the innermost container id in
// a /proc/<pid>/cgroup content ("docker-<64 hex>.scope", ".../cri-containerd-<id>.scope",
// ".../<id>"), or "".
func containerOf(cgroup string) string {
	best := ""
	for _, line := range strings.Split(cgroup, "\n") {
		_, p, ok := strings.Cut(line, "::")
		if !ok {
			if parts := strings.SplitN(line, ":", 3); len(parts) == 3 {
				p = parts[2]
			} else {
				continue
			}
		}
		for _, seg := range strings.Split(p, "/") {
			if id := containerID.FindString(seg); id != "" {
				best = id[:12]
			}
		}
	}
	return best
}

// ClusterName is the systemd unit when the postmaster has its own, else
// "<major>/<data directory basename>" made unique by the container id
// ("@<id12>") or, without one, the port (":<port>"). Two pods running the same
// image share the basename (…/data), so it alone is not an identity. The name
// never contains a PID: it labels Prometheus series and must survive a restart.
func ClusterName(pm Postmaster, major int) string {
	if pm.Unit != "" {
		return pm.Unit
	}
	base := "unknown"
	if pm.DataDir != "" {
		base = path.Base(pm.DataDir)
	}
	name := fmt.Sprintf("%d/%s", major, base)
	switch id := containerOf(pm.Cgroup); {
	case id != "":
		return name + "@" + id
	case pm.Port > 0:
		return fmt.Sprintf("%s:%d", name, pm.Port)
	}
	return name
}

// realProc reads the host's /proc (the agent runs with hostPID).
type realProc struct{}

func (realProc) PIDs() ([]uint32, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, e := range ents {
		if n, err := strconv.ParseUint(e.Name(), 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out, nil
}

func (realProc) Comm(pid uint32) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(b)), err
}

func (realProc) PPID(pid uint32) (uint32, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, fmt.Errorf("bad stat")
	}
	f := bytes.Fields(b[i+1:]) // f[0] state, f[1] ppid
	if len(f) < 2 {
		return 0, fmt.Errorf("short stat")
	}
	n, err := strconv.ParseUint(string(f[1]), 10, 32)
	return uint32(n), err
}

func (realProc) Cmdline(pid uint32) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return strings.TrimRight(strings.ReplaceAll(string(b), "\x00", " "), " "), err
}

func (realProc) ExeKey(pid uint32) (pgtrace.BinaryKey, error) {
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return pgtrace.BinaryKey{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return pgtrace.BinaryKey{}, fmt.Errorf("no stat_t")
	}
	return pgtrace.BinaryKey{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, nil
}

func (realProc) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

func (realProc) Cgroup(pid uint32) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	return string(b), err
}
