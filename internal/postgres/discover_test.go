package postgres

import (
	"fmt"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

type fakeProc struct {
	comm    map[uint32]string
	ppid    map[uint32]uint32
	cmdline map[uint32]string
	exe     map[uint32]pgtrace.BinaryKey
	files   map[string]string
	cgroup  map[uint32]string
}

func (f *fakeProc) PIDs() ([]uint32, error) {
	var out []uint32
	for pid := range f.comm {
		out = append(out, pid)
	}
	return out, nil
}
func (f *fakeProc) Comm(pid uint32) (string, error) {
	c, ok := f.comm[pid]
	if !ok {
		return "", fmt.Errorf("no pid %d", pid)
	}
	return c, nil
}
func (f *fakeProc) PPID(pid uint32) (uint32, error)    { return f.ppid[pid], nil }
func (f *fakeProc) Cmdline(pid uint32) (string, error) { return f.cmdline[pid], nil }
func (f *fakeProc) ExeKey(pid uint32) (pgtrace.BinaryKey, error) {
	k, ok := f.exe[pid]
	if !ok {
		return k, fmt.Errorf("no exe")
	}
	return k, nil
}
func (f *fakeProc) ReadFile(name string) ([]byte, error) {
	s, ok := f.files[name]
	if !ok {
		return nil, fmt.Errorf("no file %s", name)
	}
	return []byte(s), nil
}
func (f *fakeProc) Cgroup(pid uint32) (string, error) { return f.cgroup[pid], nil }

func hostProcs() *fakeProc {
	return &fakeProc{
		comm: map[uint32]string{1: "systemd", 100: "postgres", 101: "postgres", 102: "postgres",
			200: "postgres", 300: "postgres", 400: "bash"},
		ppid: map[uint32]uint32{100: 1, 101: 100, 102: 100, 200: 1, 300: 1, 400: 1},
		cmdline: map[uint32]string{
			100: "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main -c config_file=/etc/postgresql/16/main/postgresql.conf",
			101: "postgres: 16/main: checkpointer",
			102: "postgres: 16/main: app shop 10.0.0.5(51234) idle",
			200: "/usr/lib/postgresql/18/bin/postgres -D /var/lib/postgresql/18/main",
			// An orphaned backend: its postmaster crashed, init adopted it.
			300: "postgres: 17/main: app shop [local] idle",
		},
		exe: map[uint32]pgtrace.BinaryKey{100: {Dev: 1, Ino: 16}, 101: {Dev: 1, Ino: 16}, 102: {Dev: 1, Ino: 16},
			200: {Dev: 1, Ino: 18}, 300: {Dev: 1, Ino: 17}},
		files: map[string]string{
			"/proc/100/cwd/postmaster.pid": "100\n/var/lib/postgresql/16/main\n1760000000\n5432\n/var/run/postgresql\n*\n",
			"/proc/200/cwd/postmaster.pid": "1\n/var/lib/postgresql/18/main\n1760000000\n5433\n",
		},
		cgroup: map[uint32]string{100: "0::/system.slice/system-postgresql.slice/postgresql@16-main.service\n",
			200: "0::/system.slice/docker-abc.scope\n"},
	}
}

func TestDiscoverPostmasters(t *testing.T) {
	pms, err := Discover(hostProcs())
	if err != nil {
		t.Fatal(err)
	}
	if len(pms) != 2 || pms[0].PID != 100 || pms[1].PID != 200 {
		t.Fatalf("postmasters %+v", pms)
	}
	a := pms[0]
	if a.Port != 5432 || a.DataDir != "/var/lib/postgresql/16/main" || a.Unit != "postgresql@16-main.service" ||
		a.Exe != "/proc/100/exe" || a.Key != (pgtrace.BinaryKey{Dev: 1, Ino: 16}) {
		t.Fatalf("pm 100 %+v", a)
	}
	if ClusterName(a, 16) != "postgresql@16-main.service" {
		t.Fatalf("name %q", ClusterName(a, 16))
	}
	if b := pms[1]; b.Unit != "" || ClusterName(b, 18) != "18/main:5433" || b.Port != 5433 {
		t.Fatalf("pm 200 %+v name %q", b, ClusterName(b, 18))
	}
}

// Review Focus 2.
func TestOrphanBackendIsNotPostmaster(t *testing.T) {
	pms, _ := Discover(hostProcs())
	for _, pm := range pms {
		if pm.PID == 300 {
			t.Fatal("an orphaned backend (title postgres: …) must not be a postmaster")
		}
	}
}

func TestClusterNameFallbacks(t *testing.T) {
	if got := ClusterName(Postmaster{PID: 9}, 17); got != "17/unknown" {
		t.Fatalf("got %q", got)
	}
}
