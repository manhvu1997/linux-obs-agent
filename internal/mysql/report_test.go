package mysql

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/sqlhash"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

// allAvailable makes every per-statement signal available, independent of
// the loader and of the host's delay-accounting state.
func allAvailable(a *Analyzer) {
	a.acct = func() mysqlq.Accounting { return mysqlq.Accounting{DiskBytes: true, BlkioDelay: true, Redo: true} }
	a.delayAcct = func() (bool, error) { return true, nil }
}

// A busy node where one statement does a third of the CPU work: the report
// carries the node block, coverage, the culprit role and the thresholds.
func TestTickBuildsReport(t *testing.T) {
	cfg := config.Defaults().MySQL
	a := NewAnalyzer(&cfg, nil)
	allAvailable(a)
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	f := &fakeHost{
		node:    []collector.NodeCPUTimes{nodeTimes(0, 0), nodeTimes(36e9, 40e9)}, // 90 % of 8 CPUs over 5 s
		nodeErr: []bool{false, false},
		pid:     map[uint32]uint64{42: 20e9}, // mysqld read at this poll: 20 s
	}
	a.host = f.sampler()
	a.host.prime()
	a.host.prevPID[42] = 0 // mysqld baselined at 0 → 20 s of mysqld CPU this poll

	const q = "SELECT * FROM orders WHERE id = 1"
	h := sqlhash.KernelHash([]byte(q))
	a.learnText(mysqlq.TextEvent{Command: cmdmap.ComQuery, Hash: h, Query: q, QueryLen: uint32(len(q))}, true, true)
	now := time.Unix(1_800_000_000, 0)
	a.tick(now, []mysqlq.AggEntry{{PID: 42, Command: cmdmap.ComQuery, Hash: h, Calls: 100, CPUNs: 12e9, WallNs: 15e9, WallMaxNs: 3e8}}, true)

	r := a.Latest()
	if r == nil || r.Node == nil || r.Node.NumCPU != 8 || r.Node.CPUUsedPercent != 90 {
		t.Fatalf("node = %+v", r)
	}
	if r.QueryCPUCoveragePercent == nil || *r.QueryCPUCoveragePercent != 60 {
		t.Fatalf("coverage = %v, want 60 (12 s of 20 s)", r.QueryCPUCoveragePercent)
	}
	d := r.TopDigests[0]
	if d.PercentOfNodeCPUUsed == nil || *d.PercentOfNodeCPUUsed < 33.3 || *d.PercentOfNodeCPUUsed > 33.4 || d.CPURole != "culprit" {
		t.Fatalf("digest = %+v", d)
	}
	if r.Accounting["cpu_wait"] != "ok" || r.Victims == nil || r.Thresholds.CPUCulpritPercentOfNodeCPUUsed != 20 {
		t.Fatalf("accounting %v victims %v thresholds %+v", r.Accounting, r.Victims, r.Thresholds)
	}
	for _, k := range []string{querystats.AccountingKeyDiskBytes, querystats.AccountingKeyDiskWait, querystats.AccountingKeyCommitWait} {
		if r.Accounting[k] != "ok" {
			t.Errorf("accounting[%s] = %q, want ok", k, r.Accounting[k])
		}
	}
	// The fake host has no disk data: node disk and disk coverage are absent, never 0.
	if r.Node.DiskReadMBPerSec != nil || r.Node.DiskWriteMBPerSec != nil || r.QueryDiskReadCoveragePercent != nil {
		t.Fatalf("node disk %v/%v coverage %v without disk data", r.Node.DiskReadMBPerSec, r.Node.DiskWriteMBPerSec, r.QueryDiskReadCoveragePercent)
	}
}

// No digests and no slow queries: nothing is published.
func TestTickWithoutDataPublishesNothing(t *testing.T) {
	cfg := config.Defaults().MySQL
	a := NewAnalyzer(&cfg, nil)
	allAvailable(a)
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	f := &fakeHost{node: []collector.NodeCPUTimes{nodeTimes(0, 0), nodeTimes(1, 2)}, nodeErr: []bool{false, false}}
	a.host = f.sampler()
	a.host.prime()
	a.tick(time.Unix(1_800_000_000, 0), nil, true)
	if a.Latest() != nil {
		t.Fatalf("published %+v", a.Latest())
	}
}

func TestAccountingReasons(t *testing.T) {
	for _, c := range []struct {
		name               string
		acct               mysqlq.Accounting
		delayOn            bool
		disk, wait, commit string
	}{
		{"all available", mysqlq.Accounting{DiskBytes: true, BlkioDelay: true, Redo: true}, true, "", "", ""},
		{"delayacct off", mysqlq.Accounting{DiskBytes: true, BlkioDelay: true, Redo: true}, false, "", reasonDelayAcctOff, ""},
		{"no delays field", mysqlq.Accounting{DiskBytes: true, Redo: true}, true, "", reasonNoBlkioDelay, ""},
		{"no ioac, no redo probe", mysqlq.Accounting{BlkioDelay: true}, true, reasonNoIOAccounting, "", reasonNoRedoProbe},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Defaults().MySQL
			a := NewAnalyzer(&cfg, nil)
			a.acct = func() mysqlq.Accounting { return c.acct }
			a.delayAcct = func() (bool, error) { return c.delayOn, nil }
			var h querystats.HostDelta
			a.setReasons(&h)
			if h.QueryDiskReason != c.disk || h.IOWaitReason != c.wait || h.RedoWaitReason != c.commit {
				t.Fatalf("reasons = %q / %q / %q", h.QueryDiskReason, h.IOWaitReason, h.RedoWaitReason)
			}
		})
	}
}
