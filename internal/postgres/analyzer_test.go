package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/overload"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pghash"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgsym"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

type fakeTracer struct {
	clusters  map[uint32]pgtrace.ClusterConst
	attached  map[pgtrace.BinaryKey]pgtrace.Binary
	detachAll int
	cleared   int
	entries   [][]pgtrace.AggEntry
	sessions  []pgtrace.Session
	texts     chan pgtrace.TextEvent
	cmds      chan pgtrace.CmdEvent
	slows     chan pgtrace.SlowEvent
	unsafe    []uint64
}

func newFakeTracer() *fakeTracer {
	return &fakeTracer{attached: map[pgtrace.BinaryKey]pgtrace.Binary{}, texts: make(chan pgtrace.TextEvent, 8),
		cmds: make(chan pgtrace.CmdEvent, 8), slows: make(chan pgtrace.SlowEvent, 8)}
}

func (f *fakeTracer) Start(context.Context) error { return nil }
func (f *fakeTracer) Stop()                       {}
func (f *fakeTracer) SetClusters(m map[uint32]pgtrace.ClusterConst) error {
	f.clusters = m
	return nil
}
func (f *fakeTracer) Attach(b pgtrace.Binary) (pgtrace.Attached, error) {
	f.attached[b.Key] = b
	return pgtrace.Attached{WAL: true, Parallel: true, SyncRep: b.SyncRep, QueryID: b.QueryID}, nil
}
func (f *fakeTracer) Detach(k pgtrace.BinaryKey) { delete(f.attached, k) }
func (f *fakeTracer) DetachAll() {
	f.detachAll++
	f.attached = map[pgtrace.BinaryKey]pgtrace.Binary{}
}
func (f *fakeTracer) ClearSessions() error { f.cleared++; return nil }
func (f *fakeTracer) DrainAgg() ([]pgtrace.AggEntry, error) {
	if len(f.entries) == 0 {
		return nil, nil
	}
	e := f.entries[0]
	f.entries = f.entries[1:]
	return e, nil
}
func (f *fakeTracer) OpenSessions() ([]pgtrace.Session, error) { return f.sessions, nil }
func (f *fakeTracer) QueryIDs() (map[uint64]int64, error)      { return nil, nil }
func (f *fakeTracer) ForgetText(uint64)                        {}
func (f *fakeTracer) MarkUnsafe(h uint64)                      { f.unsafe = append(f.unsafe, h) }
func (f *fakeTracer) Texts() <-chan pgtrace.TextEvent          { return f.texts }
func (f *fakeTracer) Cmds() <-chan pgtrace.CmdEvent            { return f.cmds }
func (f *fakeTracer) Slows() <-chan pgtrace.SlowEvent          { return f.slows }
func (f *fakeTracer) Dropped() uint64                          { return 0 }
func (f *fakeTracer) TextDropped() uint64                      { return 0 }
func (f *fakeTracer) AggOverflow() uint64                      { return 0 }
func (f *fakeTracer) LiteralSkip() bool                        { return true }
func (f *fakeTracer) Accounting() pgtrace.Accounting {
	return pgtrace.Accounting{DiskBytes: true, BlkioDelay: true}
}

var allSyms = []string{pgsym.SymActivity, pgsym.SymPortalRun, pgsym.SymQueryID, pgsym.SymXLogFlush, pgsym.SymSyncRep, pgsym.SymParallel}

func fakeELF(path string) (pgsym.Version, []string, error) {
	major := map[string]int{"/proc/100/exe": 16, "/proc/150/exe": 16, "/proc/200/exe": 18}[path]
	return pgsym.Version{Major: major, Minor: 1}, allSyms, nil
}

// testAnalyzer: node of 8 CPUs, 90 % busy (36 of 40 CPU-seconds per 5 s poll).
func testAnalyzer(t *testing.T, proc *fakeProc) (*Analyzer, *fakeTracer) {
	t.Helper()
	tr := newFakeTracer()
	var used, total uint64
	a := NewAnalyzer(Options{SlowQueryThresholdMs: 100, PollInterval: 5 * time.Second, DigestWindow: 60 * time.Second,
		DiscoverInterval: 30 * time.Second, ShedCooldown: time.Minute, TopDigests: 20, StickyDigestsMax: 50,
		StickyDigestTTL: time.Hour, CPUCulpritPercentOfNodeCPUUsed: 20, CPUCulpritMinNodeCPUUsedPct: 50,
		VictimWaitPercent: 50, IOCulpritPercentOfDiskRead: 20, IOCulpritMinNodeDiskReadMBPerSec: 5,
		BackgroundDominantPercent: 50, MaxStatementsPerSec: 30000, FoldSystemCatalogs: true, SampleQueries: true,
		IncludeIO: true, SyncRepWait: "auto"},
		Deps{Tracer: tr, Proc: proc, ReadELF: fakeELF,
			NodeCPU: func() (collector.NodeCPUTimes, error) {
				used, total = used+36e9, total+40e9
				return collector.NodeCPUTimes{UsedNs: used, TotalNs: total, NumCPU: 8}, nil
			},
			NodeDisk:   func() (collector.NodeDiskBytes, error) { return collector.NodeDiskBytes{Disks: 1}, nil },
			ReadThread: func(uint32) (procCounters, error) { return procCounters{}, nil },
			DelayAcct:  func() (bool, error) { return true, nil },
			Mono:       func() uint64 { return 1e12 },
			SysFS:      t.TempDir(),
			PIDCPU:     func(uint32) (uint64, error) { return 0, nil },
			Children:   func(pid uint32) []uint32 { return []uint32{pid} },
			NumCPU:     8})
	a.primeNode()
	return a, tr
}

func learn(a *Analyzer, text string) uint64 {
	h := pghash.KernelHash([]byte(text))
	a.learnText(pgtrace.TextEvent{Hash: h, Len: uint32(len(text)), Text: text})
	return h
}

func TestPollAttributesDigestsAndParallelShares(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	h := learn(a, "SELECT status, count(*) FROM orders WHERE created_at > '2026-01-01' GROUP BY status")
	tr.entries = [][]pgtrace.AggEntry{{
		{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 10, WallNs: 20e9, WallMaxNs: 4e9, CPUNs: 15e9},
		{Postmaster: 100, Kind: pgtrace.KindParallel, Hash: h, WallNs: 9e9, CPUNs: 9e9},
	}}
	now := time.Unix(1_800_000_000, 0)
	a.poll(now)
	r := a.Latest()
	if r == nil || len(r.Clusters) != 2 {
		t.Fatalf("report %+v", r)
	}
	var c model.PostgresCluster
	for _, x := range r.Clusters {
		if x.PostmasterPID == 100 {
			c = x
		}
	}
	if len(c.TopDigests) != 1 {
		t.Fatalf("digests %+v", c.TopDigests)
	}
	d := c.TopDigests[0]
	if d.Command != CommandClient || d.Calls != 10 || d.CPUCores != 24.0/60 || d.LatencyMsAvg != 2000 {
		t.Fatalf("digest %+v", d)
	}
	if c.Accounting["wal_wait"] != "ok" || c.Accounting["syncrep_wait"] != reasonNotAttached || c.Accounting["commit_wait"] != "" {
		t.Fatalf("accounting %v", c.Accounting)
	}
	if r.Accounting["state"] != StateActive || r.Accounting["enrichment"] != "not_configured" {
		t.Fatalf("report accounting %v", r.Accounting)
	}
}

func TestAutovacuumDigestIsNotAQueryCandidate(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	h := learn(a, "autovacuum: VACUUM ANALYZE public.orders")
	tr.entries = [][]pgtrace.AggEntry{{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 1, WallNs: 5e9, CPUNs: 4e9}}}
	a.poll(time.Unix(1_800_000_000, 0))
	for _, v := range a.Views() {
		if v.PostmasterPID != 100 {
			continue
		}
		if len(v.Overload.TopDigests) != 0 {
			t.Fatalf("autovacuum digests must not be query candidates: %+v", v.Overload.TopDigests)
		}
		if v.Snapshot.TopByCPU[0].Command != CommandAutovacuum {
			t.Fatalf("command %q", v.Snapshot.TopByCPU[0].Command)
		}
	}
}

// Review Focus 3.
func TestClusterConstsPerVersion(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	if tr.clusters[100] != (pgtrace.ClusterConst{Running: 2, Fastpath: 4}) || tr.clusters[200] != (pgtrace.ClusterConst{Running: 3, Fastpath: 5}) {
		t.Fatalf("clusters map %+v", tr.clusters)
	}
	if len(tr.attached) != 2 {
		t.Fatalf("both binaries attached once each: %+v", tr.attached)
	}
}

// Review Focus 1.
func TestClusterRestartReplacesState(t *testing.T) {
	p := hostProcs()
	a, tr := testAnalyzer(t, p)
	a.discover(time.Unix(0, 0))
	old := a.cluster(100)
	// The postmaster restarts: PID 150, same unit, same binary.
	delete(p.comm, 100)
	p.comm[150], p.ppid[150] = "postgres", 1
	p.cmdline[150] = p.cmdline[100]
	p.exe[150] = p.exe[100]
	p.files["/proc/150/cwd/postmaster.pid"] = p.files["/proc/100/cwd/postmaster.pid"]
	p.cgroup[150] = p.cgroup[100]
	a.discover(time.Unix(30, 0))
	if a.cluster(100) != nil {
		t.Fatal("the dead postmaster's cluster must be dropped")
	}
	c := a.cluster(150)
	if c == nil || c.name != "postgresql@16-main.service" || c == old || c.agg == old.agg {
		t.Fatalf("restarted cluster %+v", c)
	}
	if _, ok := tr.clusters[100]; ok || tr.clusters[150].Running != 2 {
		t.Fatalf("clusters map %+v", tr.clusters)
	}
}

func TestShedDetachesThenResumes(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.opts.MaxStatementsPerSec = 100
	a.brk.max = 100
	a.discover(time.Unix(0, 0))
	h := learn(a, "select 1")
	big := []pgtrace.AggEntry{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 10_000, WallNs: 1e9, CPUNs: 1e8}}
	tr.entries = [][]pgtrace.AggEntry{big, big}
	t0 := time.Unix(1_800_000_000, 0)
	a.poll(t0)
	if a.State() != StateActive {
		t.Fatal("one over-limit poll must not shed")
	}
	a.poll(t0.Add(5 * time.Second))
	if a.State() != StateShed || tr.detachAll != 1 || tr.cleared != 1 || len(tr.attached) != 0 || a.ShedTotal() != 1 {
		t.Fatalf("state %s detachAll %d cleared %d attached %d", a.State(), tr.detachAll, tr.cleared, len(tr.attached))
	}
	if a.Latest().Accounting["state"] != StateShed {
		t.Fatal("report must say shed")
	}
	a.poll(t0.Add(30 * time.Second))
	if len(tr.attached) != 0 {
		t.Fatal("no re-attach during cooldown")
	}
	a.poll(t0.Add(2 * time.Minute))
	if a.State() != StateActive || len(tr.attached) != 2 {
		t.Fatalf("resume must re-attach: state %s attached %d", a.State(), len(tr.attached))
	}
}

func TestPG18WithoutSQLIsAsync(t *testing.T) {
	a, _ := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	a.poll(time.Unix(1_800_000_000, 0))
	for _, c := range a.Latest().Clusters {
		want := "ok"
		if c.PostmasterPID == 200 {
			want = reasonAsyncIO
		}
		if c.Accounting["disk_bytes"] != want {
			t.Errorf("cluster %d disk_bytes %q, want %q", c.PostmasterPID, c.Accounting["disk_bytes"], want)
		}
	}
}

func TestHashDriftMarksUnsafe(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.learnText(pgtrace.TextEvent{Hash: 12345, Text: "select 1"})
	if len(tr.unsafe) != 1 || tr.unsafe[0] != 12345 || a.HashMismatches() != 1 {
		t.Fatalf("unsafe %v mismatches %d", tr.unsafe, a.HashMismatches())
	}
}

func TestSlowEventsKeepClientOnly(t *testing.T) {
	a, _ := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	q := learn(a, "select * from orders where id = 1")
	v := learn(a, "autovacuum: VACUUM public.orders")
	a.recordSlow(pgtrace.SlowEvent{Postmaster: 100, PID: 7, Hash: q, WallNs: 5e8, At: time.Unix(1, 0)})
	a.recordSlow(pgtrace.SlowEvent{Postmaster: 100, PID: 8, Hash: v, WallNs: 9e9, At: time.Unix(1, 0)})
	c := a.cluster(100)
	if len(c.recent) != 1 || c.recent[0].LatencyMs != 500 || c.recent[0].DigestText != "select * from orders where id = ?" {
		t.Fatalf("recent %+v", c.recent)
	}
}

func TestAssessPicksCluster(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.discover(time.Unix(0, 0))
	h := learn(a, "select * from big where x > 1")
	tr.entries = [][]pgtrace.AggEntry{{{Postmaster: 100, Kind: pgtrace.KindClient, Hash: h, Calls: 1, WallNs: 5e9, CPUNs: 5e9}}}
	a.poll(time.Unix(1_800_000_000, 0))
	in := overload.Inputs{Families: []model.FamilyStats{{Family: "postgresql@16-main.service", CPUPercent: 80}},
		PIDFamilies: map[uint32]string{100: "postgresql@16-main.service"}}
	in.Metrics.LoadAvg.NumCPU = 8
	r := a.WithOverload(in, overload.Thresholds{}, time.Unix(1_800_000_000, 0))
	if r.OverloadCause == nil || r.OverloadCause.Cluster == "" || len(r.OverloadCause.OtherClusters) != 1 {
		t.Fatalf("overload %+v", r.OverloadCause)
	}
	if a.Latest().OverloadCause != nil {
		t.Fatal("the cached report must not be mutated")
	}
}

func TestBinaryPathsAllowList(t *testing.T) {
	a, tr := testAnalyzer(t, hostProcs())
	a.opts.BinaryPaths = []string{"/usr/lib/postgresql/18/bin/postgres"}
	a.d.StatKey = func(string) (pgtrace.BinaryKey, error) { return pgtrace.BinaryKey{Dev: 1, Ino: 18}, nil }
	a.discover(time.Unix(0, 0))
	if a.cluster(100) != nil || a.cluster(200) == nil || len(tr.attached) != 1 {
		t.Fatalf("only the listed binary is traced: attached %v", tr.attached)
	}
}
