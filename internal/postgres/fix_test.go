package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/pgdrain"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pghash"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgstat"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

var t0 = time.Unix(1_800_000_000, 0)

func cluster100(t *testing.T, a *Analyzer) ClusterView {
	t.Helper()
	for _, v := range a.Views() {
		if v.PostmasterPID == 100 {
			return v
		}
	}
	t.Fatal("no view for postmaster 100")
	return ClusterView{}
}

func sumCPU(d []querystats.DigestDelta) (n uint64) {
	for _, x := range d {
		n += x.CPUNs
	}
	return n
}

// Finding 1: the command comes from the raw statement, not the folded digest.
func TestAutovacuumOnCatalogStaysAutovacuum(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	h := learn(a, "autovacuum: VACUUM ANALYZE pg_catalog.pg_attribute")
	tr.entries = [][]pgtrace.AggEntry{{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 1, WallNs: 5e9, CPUNs: 4e9}}}
	a.poll(t0)
	v := cluster100(t, a)
	if got := v.Snapshot.TopByCPU[0]; got.Command != CommandAutovacuum || got.DigestText != "<system catalogs>" {
		t.Fatalf("digest %+v", got)
	}
	if len(v.Overload.TopDigests) != 0 {
		t.Fatalf("must not be a query candidate: %+v", v.Overload.TopDigests)
	}
	a.recordSlow(pgtrace.SlowEvent{Postmaster: 100, PID: 1, Hash: h, WallNs: 9e9, At: t0})
	if len(a.cluster(100).recent) != 0 {
		t.Fatal("autovacuum must not be a slow query")
	}
}

// Finding 2: after a shed the first poll must not book the cooldown's CPU.
func TestResumeRebaselines(t *testing.T) {
	var cpu uint64
	a, tr := testAnalyzer(t, hostProcs())
	a.d.PIDCPU = func(uint32) (uint64, error) { return cpu, nil }
	a.opts.MaxStatementsPerSec = 100
	a.brk.max = 100
	a.EnableDrain(100, 10)
	cpu = 1e9
	a.discover(time.Unix(0, 0))
	h := learn(a, "select 1")
	big := []pgtrace.AggEntry{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 10_000, WallNs: 1e9, CPUNs: 1e8}}
	tr.entries = [][]pgtrace.AggEntry{big, big}
	a.poll(t0)
	cpu = 2e9
	a.poll(t0.Add(5 * time.Second))
	if a.State() != StateShed {
		t.Fatal("expected shed")
	}
	a.Drain()
	cpu = 500e9 // the cooldown
	a.cred.credited[sessKey{1, 1}] = &creditedSess{}
	a.poll(t0.Add(2 * time.Minute))
	if a.State() != StateActive {
		t.Fatal("expected resume")
	}
	for _, c := range a.Drain().Clusters {
		if c.Host.MysqldCPUNs > 10e9 {
			t.Fatalf("cluster %d booked the cooldown's CPU into one poll: %d", c.PostmasterPID, c.Host.MysqldCPUNs)
		}
	}
	if len(a.cred.credited) != 0 {
		t.Fatal("credit must be reset on resume")
	}
}

type fakeSQL struct {
	s    pgstat.Settings
	mu   sync.Mutex
	rows []pgstat.Row
}

func (f *fakeSQL) Settings(context.Context) (pgstat.Settings, error) { return f.s, nil }
func (f *fakeSQL) Statements(context.Context, []int64, string) ([]pgstat.Row, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pgstat.Row(nil), f.rows...), nil
}
func (f *fakeSQL) Close() {}

func (f *fakeSQL) set(r ...pgstat.Row) { f.mu.Lock(); f.rows = r; f.mu.Unlock() }

func twoClusterProcs() *fakeProc {
	p := hostProcs()
	p.comm[150], p.ppid[150] = "postgres", 1
	p.cmdline[150] = "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/alt"
	p.exe[150] = p.exe[100]
	p.files["/proc/150/cwd/postmaster.pid"] = "150\n/var/lib/postgresql/16/alt\n1760000000\n5434\n"
	p.cgroup[150] = "0::/system.slice/docker-x.scope\n"
	return p
}

// Finding 3: one binary, two clusters, only one with sync standbys: the
// optional hook decision is the OR, not the last map-iteration winner.
func TestSyncRepSharedBinaryDoesNotFlap(t *testing.T) {
	a, tr := testAnalyzer(t, twoClusterProcs())
	a.d.Enricher = pgstat.NewEnricher(func(_ context.Context, port int) (pgstat.Conn, error) {
		s := pgstat.Settings{VersionNum: 160002, BlockSize: 8192, ComputeQueryID: "on"}
		if port == 5434 {
			s.SyncStandbys = "standby1"
		}
		return &fakeSQL{s: s}, nil
	})
	for _, port := range []int{5432, 5434} {
		a.d.Enricher.Poll(context.Background(), port, nil, t0)
	}
	a.discover(time.Unix(0, 0))
	first := tr.attaches
	for i := 0; i < 40; i++ {
		a.discover(time.Unix(int64(30*(i+1)), 0))
	}
	if tr.attaches != first || tr.detaches != 0 {
		t.Fatalf("hooks flapped: attaches %d (first %d) detaches %d", tr.attaches, first, tr.detaches)
	}
	if b := a.binaries[pgtrace.BinaryKey{Dev: 1, Ino: 16}]; !b.syncRep {
		t.Fatal("sync rep hook must be on while any cluster of the binary needs it")
	}
}

// Finding 4: discover, the enrichment poll and the drain run concurrently.
func TestDiscoverDrainEnrichRace(t *testing.T) {
	a, tr := testAnalyzer(t, twoClusterProcs())
	sql := &fakeSQL{s: pgstat.Settings{VersionNum: 170002, BlockSize: 8192, ComputeQueryID: "on"}}
	a.d.Enricher = pgstat.NewEnricher(func(context.Context, int) (pgstat.Conn, error) { return sql, nil })
	a.EnableDrain(100, 10)
	a.discover(time.Unix(0, 0))
	h := learn(a, "select * from t where id = 1")
	tr.qids = map[uint64]int64{h: 5}
	sql.set(pgstat.Row{QueryID: 5, Calls: 1})
	a.poll(t0)
	var wg sync.WaitGroup
	run := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				f(i)
			}
		}()
	}
	run(func(i int) { a.discover(time.Unix(int64(i), 0)) })
	run(func(int) { a.Drain() })
	run(func(i int) { a.enrich(context.Background(), t0.Add(time.Duration(i)*time.Second)) })
	run(func(int) { a.Views(); a.Latest() })
	wg.Wait()
}

// Finding 5: an interval closed by a command event is not double counted.
func TestCmdEventSettlesCredit(t *testing.T) {
	for _, noticed := range []bool{false, true} {
		a, tr := testAnalyzer(t, hostProcs())
		a.EnableDrain(100, 10)
		a.discover(time.Unix(0, 0))
		h := learn(a, "select * from big where x > 1")
		a.cred.readProc = func(uint32) (procCounters, error) { return procCounters{CPU: 5e9}, nil }
		tr.sessions = []pgtrace.Session{{TID: 7, Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, OpenTS: 1}}
		a.poll(t0)
		tr.sessions = nil
		if noticed {
			a.poll(t0.Add(5 * time.Second))
		}
		a.recordCmd(pgtrace.CmdEvent{Postmaster: 100, PID: 7, Kind: pgtrace.KindClient, Hash: h, Calls: 1, WallNs: 9e9, CPUNs: 9e9}, t0.Add(6*time.Second))
		a.poll(t0.Add(10 * time.Second))
		var got uint64
		for _, c := range a.Drain().Clusters {
			if c.PostmasterPID == 100 {
				got = sumCPU(c.Digests)
			}
		}
		if got != 9e9 {
			t.Fatalf("noticed=%v: cpu total %d, want exactly one execution (9e9)", noticed, got)
		}
	}
}

// Finding 6: a parallel worker's delta must not name the leader's digest.
func TestParallelDoesNotNameDigest(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	h := learn(a, "select count(*) from big where x > 1")
	tr.entries = [][]pgtrace.AggEntry{{
		{Postmaster: 100, Kind: pgtrace.KindParallel, Hash: h, CPUNs: 9e9},
		{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, CPUNs: 1e9},
	}}
	a.poll(t0)
	v := cluster100(t, a)
	if len(v.Overload.TopDigests) != 1 || v.Snapshot.TopByCPU[0].Command != CommandClient {
		t.Fatalf("snapshot %+v overload %+v", v.Snapshot.TopByCPU, v.Overload.TopDigests)
	}
}

// Finding 8: an unreadable session map is not "no sessions".
func TestSessionsErrorSkipsCredit(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	h := learn(a, "select * from big where x > 1")
	a.cred.readProc = func(uint32) (procCounters, error) { return procCounters{CPU: 5e9}, nil }
	tr.sessions = []pgtrace.Session{{TID: 7, Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, OpenTS: 1}}
	a.poll(t0)
	tr.sessions, tr.sessErr = nil, errors.New("map read")
	a.poll(t0.Add(5 * time.Second))
	if len(a.cred.credited) != 1 || len(a.cred.owed) != 0 {
		t.Fatalf("credited %d owed %d: the failed read must change nothing", len(a.cred.credited), len(a.cred.owed))
	}
}

// Finding 9: the SQL poll is single-flight.
func TestStartEnrichSingleFlight(t *testing.T) {
	a, _ := testAnalyzer(t, hostProcs())
	a.d.Enricher = pgstat.NewEnricher(func(context.Context, int) (pgstat.Conn, error) { return &fakeSQL{}, nil })
	a.enriching.Store(true)
	if a.startEnrich(context.Background(), t0) {
		t.Fatal("must skip while the previous poll runs")
	}
	a.enriching.Store(false)
	if !a.startEnrich(context.Background(), t0) {
		t.Fatal("must start when idle")
	}
	a.wg.Wait()
}

// Finding 10: Views() hands out copies.
func TestViewsAreCopies(t *testing.T) {
	a, _ := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	a.poll(t0)
	v := a.Views()
	v[0].Accounting["x"], v[0].Overload.Accounting["x"] = "y", "y"
	v = a.Views()
	if _, ok := v[0].Accounting["x"]; ok {
		t.Fatal("ClusterView.Accounting is shared")
	}
	if _, ok := v[0].Overload.Accounting["x"]; ok {
		t.Fatal("Overload.Accounting is shared")
	}
	for _, c := range a.Latest().Clusters {
		if _, ok := c.Accounting["x"]; ok {
			t.Fatal("the report shares the view's map")
		}
	}
}

// Finding 12: a command event whose text has not arrived waits for it.
func TestCmdEventWaitsForText(t *testing.T) {
	a, _ := testAnalyzer(t, hostProcs())
	a.EnableDrain(100, 10)
	a.discover(time.Unix(0, 0))
	text := "select * from t where id = 1"
	h := pghash.KernelHash([]byte(text))
	a.recordCmd(pgtrace.CmdEvent{Postmaster: 100, PID: 7, Kind: pgtrace.KindClient, Hash: h, Calls: 1, WallNs: 1e9, CPUNs: 1e9}, t0)
	a.poll(t0)
	learn(a, text)
	a.poll(t0.Add(5 * time.Second))
	var texts []string
	for _, c := range a.Drain().Clusters {
		for _, d := range c.Digests {
			texts = append(texts, d.Text)
		}
	}
	if len(texts) != 1 || texts[0] != "select * from t where id = ?" {
		t.Fatalf("digest texts %q", texts)
	}
}

// Drain: windows do not overlap, slow queries are capped and counted, enrichment
// is exported once per SQL poll.
func TestDrainWindowsSlowCapAndEnrich(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	sql := &fakeSQL{s: pgstat.Settings{VersionNum: 170002, BlockSize: 8192, ComputeQueryID: "on"}}
	a.d.Enricher = pgstat.NewEnricher(func(context.Context, int) (pgstat.Conn, error) { return sql, nil })
	a.EnableDrain(0, 2)         // the clamp makes 0 a cap of 1, not "off"
	a.discover(time.Unix(0, 0)) // clusters created after EnableDrain drain too
	h := learn(a, "select * from orders where id = 1")
	tr.qids = map[uint64]int64{h: 77}
	tr.entries = [][]pgtrace.AggEntry{{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 1, WallNs: 1e9, CPUNs: 1e9}}}
	a.poll(t0)
	for i := 0; i < 3; i++ {
		a.recordSlow(pgtrace.SlowEvent{Postmaster: 100, PID: 7, Hash: h, WallNs: 5e8, At: t0})
	}
	sql.set(pgstat.Row{QueryID: 77, Calls: 1, SharedRead: 10})
	a.d.Enricher.Poll(context.Background(), 5432, []int64{77}, t0)
	sql.set(pgstat.Row{QueryID: 77, Calls: 5, SharedRead: 110})
	a.d.Enricher.Poll(context.Background(), 5432, []int64{77}, t0.Add(time.Minute))

	find := func(d []pgdrain.Cluster) pgdrain.Cluster {
		for _, c := range d {
			if c.PostmasterPID == 100 {
				return c
			}
		}
		t.Fatal("no cluster 100")
		return pgdrain.Cluster{}
	}
	d1 := find(a.Drain().Clusters)
	if len(d1.Digests) != 1 || d1.Host.Samples == 0 {
		t.Fatalf("first drain %+v", d1)
	}
	if len(d1.Slow) != 2 || d1.SlowDropped != 1 {
		t.Fatalf("slow %d dropped %d", len(d1.Slow), d1.SlowDropped)
	}
	if len(d1.Enrich) != 1 {
		t.Fatalf("enrich %+v", d1.Enrich)
	}
	for _, e := range d1.Enrich {
		if e.SharedRead != 100 {
			t.Fatalf("enrich %+v", e)
		}
	}
	d2 := find(a.Drain().Clusters)
	if len(d2.Digests) != 0 || d2.Host.Samples != 0 || len(d2.Slow) != 0 || d2.Enrich != nil {
		t.Fatalf("windows overlap: %+v", d2)
	}
	sql.set(pgstat.Row{QueryID: 77, Calls: 6, SharedRead: 130})
	a.d.Enricher.Poll(context.Background(), 5432, []int64{77}, t0.Add(2*time.Minute))
	if d3 := find(a.Drain().Clusters); len(d3.Enrich) != 1 {
		t.Fatalf("a newer SQL poll must be exported: %+v", d3.Enrich)
	}
}
