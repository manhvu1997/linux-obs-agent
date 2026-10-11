package postgres

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestBackendType(t *testing.T) {
	cases := map[string]string{
		"postgres: 16/main: checkpointer":                                            BackendCheckpointer,
		"postgres: checkpointer":                                                     BackendCheckpointer,
		"postgres: 16/main: background writer":                                       BackendBgwriter,
		"postgres: 16/main: walwriter":                                               BackendWalwriter,
		"postgres: 16/main: autovacuum launcher":                                     BackendAutovacuum,
		"postgres: 16/main: autovacuum worker shop":                                  BackendAutovacuum,
		"postgres: 16/main: walsender repl 10.0.0.2(4100) streaming 0/3000148":       BackendWalsender,
		"postgres: 18/main: io worker 0":                                             BackendIOWorker,
		"postgres: 16/main: parallel worker for PID 4242":                            BackendParallel,
		"postgres: 17/main: logical replication apply worker for subscription 16400": BackendLogical,
		"postgres: 16/main: app shop 10.0.0.5(51234) idle":                           BackendClient,
		"postgres: app shop [local] SELECT":                                          BackendClient,
		"postgres: 17/main: walsummarizer":                                           BackendOther,
		"/usr/lib/postgresql/16/bin/postgres -D /x":                                  BackendOther,
	}
	for in, want := range cases {
		if got := BackendType(in); got != want {
			t.Errorf("BackendType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBackendSamplerWindowAndLife(t *testing.T) {
	b := NewBackendSampler(60*time.Second, true)
	b.EnableDrain()
	pms := map[uint32]bool{100: true}
	t0 := time.Unix(1_800_000_000, 0)
	procs := []model.ProcessStats{
		{PID: 100, PPID: 1, CPUPercent: 1},
		{PID: 101, PPID: 100, Cmdline: "postgres: 16/main: autovacuum worker shop", CPUPercent: 25, ReadBytesPerSec: 10 << 20},
		{PID: 102, PPID: 100, Cmdline: "postgres: 16/main: app shop 10.0.0.5(1) idle", CPUPercent: 12.5},
		{PID: 500, PPID: 1, Cmdline: "nginx", CPUPercent: 50},
	}
	b.Observe(procs, pms, 8, t0)
	b.Observe(procs, pms, 8, t0.Add(10*time.Second))
	cores, reads, ok := b.Window(100)
	if !ok || cores[BackendAutovacuum] != 2 || cores[BackendClient] != 1 || reads[BackendAutovacuum] != 10 {
		t.Fatalf("cores %v reads %v", cores, reads)
	}
	if _, _, ok := b.Window(500); ok {
		t.Fatal("nginx is not a cluster")
	}
	if l := b.Life(100)[BackendAutovacuum]; l.CPUSeconds != 20 {
		t.Fatalf("life %+v", l)
	}
	d := b.DrainBackends()
	var av BackendDelta
	for _, x := range d {
		if x.Type == BackendAutovacuum {
			av = x
		}
	}
	if av.CPUNs != 20e9 || av.ReadBytes != 100<<20 || av.ProcessesMax != 1 {
		t.Fatalf("drain %+v", d)
	}
	if len(b.DrainBackends()) != 0 {
		t.Fatal("second drain must be empty")
	}
	// Scans older than the window fall out.
	b.Observe(nil, pms, 8, t0.Add(200*time.Second))
	if _, _, ok := b.Window(100); ok {
		t.Fatal("window must be empty after the cluster disappears for a full window")
	}
}
