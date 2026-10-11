package postgres

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClusterCPUCgroupV2(t *testing.T) {
	sys := t.TempDir()
	dir := filepath.Join(sys, "fs/cgroup/system.slice/postgresql@16-main.service")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(usec string) {
		if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec "+usec+"\nuser_usec 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := cgroupCPUReader(sys, "0::/system.slice/postgresql@16-main.service\n", "postgresql@16-main.service")
	if read == nil {
		t.Fatal("v2 reader expected")
	}
	c := &clusterCPU{cgroupRead: read}
	write("1000")
	if _, partial := c.sample(); !partial {
		t.Fatal("first sample is a baseline")
	}
	write("4000")
	if d, partial := c.sample(); partial || d != 3_000_000 {
		t.Fatalf("delta %d partial %v", d, partial)
	}
	if cgroupCPUReader(sys, "0::/system.slice/docker-x.scope\n", "") != nil {
		t.Fatal("no unit → per-PID mode")
	}
}

func TestClusterCPUPerPID(t *testing.T) {
	vals := map[uint32]uint64{100: 10, 101: 20}
	pids := []uint32{100, 101}
	c := &clusterCPU{pids: func() []uint32 { return pids }, pidCPU: func(p uint32) (uint64, error) {
		v, ok := vals[p]
		if !ok {
			return 0, errors.New("gone")
		}
		return v, nil
	}}
	c.sample()
	vals[100], vals[101] = 15, 30
	if d, partial := c.sample(); partial || d != 15 {
		t.Fatalf("delta %d partial %v", d, partial)
	}
	pids = []uint32{100} // 101 exited
	vals[100] = 20
	if d, partial := c.sample(); !partial || d != 5 {
		t.Fatalf("exit must mark partial: %d %v", d, partial)
	}
}
