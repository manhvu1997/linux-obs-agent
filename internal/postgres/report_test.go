package postgres

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

func TestCommandFor(t *testing.T) {
	cases := []struct {
		kind uint32
		text string
		want string
	}{
		{pgtrace.KindClient, "select * from t", CommandClient},
		{pgtrace.KindParallel, "select * from t", CommandParallel},
		{pgtrace.KindFastpath, "<FASTPATH function call>", CommandFastpath},
		{pgtrace.KindClient, "autovacuum : vacuum analyze public . orders", CommandAutovacuum},
		{pgtrace.KindClient, "start_replication slot ? physical ? / ?", CommandReplication},
		{pgtrace.KindClient, "identify_system", CommandReplication},
	}
	for _, c := range cases {
		if got := commandFor(c.kind, c.text); got != c.want {
			t.Errorf("commandFor(%d, %q) = %q, want %q", c.kind, c.text, got, c.want)
		}
	}
}

func TestToPGDigestRenamesWaits(t *testing.T) {
	w, r := 30.0, 10.0
	d := toPGDigest(model.QueryDigestStats{DigestID: "a", VictimOf: "commit",
		TimeBreakdown: &model.TimeBreakdown{CPU: 60, CommitWait: &w, ReplicaWait: &r}})
	if d.VictimOf != "wal" || d.TimeBreakdown.WALWait != &w || d.TimeBreakdown.SyncRepWait != &r {
		t.Fatalf("%+v %+v", d, d.TimeBreakdown)
	}
	acct := pgAccounting(map[string]string{"commit_wait": "ok", "replica_wait": "not_attached", "cpu_wait": "ok"})
	if acct["wal_wait"] != "ok" || acct["syncrep_wait"] != "not_attached" || acct["cpu_wait"] != "ok" || len(acct) != 3 {
		t.Fatalf("%v", acct)
	}
}

func TestEstimateDisk(t *testing.T) {
	node := 100.0
	th := model.QueryRoleThresholds{IOCulpritPercentOfDiskRead: 20, IOCulpritMinNodeDiskReadMBPerSec: 5}
	stats := []model.QueryDigestStats{{DigestID: "a", Calls: 60}, {DigestID: "b", Calls: 60}, {DigestID: "c"}}
	top := estimateDisk(stats, map[string]uint64{"a": 750, "b": 250}, 80, &node, th, time.Minute, 10)
	if len(top) != 2 || top[0].DigestID != "a" || *top[0].DiskReadMBPerSec != 60 || *top[0].PercentOfDiskRead != 60 || top[0].IORole != "culprit" {
		t.Fatalf("top %+v", top)
	}
	if *stats[1].DiskReadMBPerSec != 20 || stats[1].IORole != "culprit" || stats[2].DiskReadMBPerSec != nil {
		t.Fatalf("stats %+v", stats)
	}
	if estimateDisk(stats, nil, 80, &node, th, time.Minute, 10) != nil {
		t.Fatal("no shared reads → no estimate")
	}
}

func TestMergeAccounting(t *testing.T) {
	got := mergeAccounting([]model.PostgresCluster{
		{Accounting: map[string]string{"disk_bytes": "ok", "wal_wait": "ok"}},
		{Accounting: map[string]string{"disk_bytes": "io_method_async", "wal_wait": "ok"}},
	})
	if got["disk_bytes"] != "io_method_async" || got["wal_wait"] != "ok" {
		t.Fatalf("%v", got)
	}
}

func TestApplyEnrichment(t *testing.T) {
	var d model.PGDigestStats
	applyEnrichment(&d, enrichment{queryID: -5, Calls: 10, SharedHit: 30, SharedRead: 10, TempWrite: 128,
		ReadTimeMs: 50, Window: time.Second, BlockSize: 8192, TrackIOTiming: true})
	if *d.QueryID != -5 || *d.SharedHitPercent != 75 || *d.TempWriteMBPerSec != 1 || *d.ReadTimeMsPerCall != 5 {
		t.Fatalf("%+v", d)
	}
}
