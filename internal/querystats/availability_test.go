package querystats

import (
	"testing"
	"time"
)

func fullHost(rd, wr uint64) HostDelta {
	h := okHost(30e9, 40e9, 4e9)
	h.DiskOK, h.DiskReadBytes, h.DiskWriteBytes = true, rd, wr
	return h
}

func TestNodeDiskAndCoverage(t *testing.T) {
	a := New(cfg())
	d := digestDelta(1, "SELECT 1", 10, 1e9)
	d.DiskReadBytes = 30 << 20
	a.AddDeltas([]Delta{d}, t0)
	a.AddHost(fullHost(60<<20, 120<<20), t0) // 60 MiB read, 120 MiB written in the window
	s := a.Snapshot(t0)
	if s.Node == nil || s.Node.DiskReadMBPerSec == nil || !near(*s.Node.DiskReadMBPerSec, 1) || !near(*s.Node.DiskWriteMBPerSec, 2) {
		t.Fatalf("node = %+v", s.Node) // 60 MiB / 60 s = 1 MB/s
	}
	if s.QueryDiskReadCoveragePercent == nil || !near(*s.QueryDiskReadCoveragePercent, 50) {
		t.Fatalf("disk coverage = %v, want 50", s.QueryDiskReadCoveragePercent)
	}
	for k, want := range map[string]string{AccountingKeyDiskBytes: AccountingOK, AccountingKeyDiskWait: AccountingOK, AccountingKeyCommitWait: AccountingOK} {
		if s.Accounting[k] != want {
			t.Errorf("accounting[%s] = %q, want %q", k, s.Accounting[k], want)
		}
	}
}

func TestDiskWaitOmittedWhenDelayAcctOff(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{digestDelta(1, "SELECT 1", 10, 1e9)}, t0)
	h := fullHost(1, 1)
	h.IOWaitReason = "delayacct_disabled"
	a.AddHost(h, t0)
	a.AddHost(fullHost(1, 1), t0.Add(5*time.Second)) // switched on later in the window
	s := a.Snapshot(t0.Add(5 * time.Second))
	if s.Accounting[AccountingKeyDiskWait] != "delayacct_disabled" {
		t.Fatalf("accounting = %v: a poll without delay accounting is in the window", s.Accounting)
	}
	if s := a.Snapshot(t0.Add(60 * time.Second)); s.Accounting[AccountingKeyDiskWait] != AccountingOK {
		t.Fatalf("accounting = %v once that poll left the window", s.Accounting)
	}
}

func TestNodeDiskOmittedWhenAPollMissedIt(t *testing.T) {
	a := New(cfg())
	h := okHost(30e9, 40e9, 4e9) // DiskOK false
	a.AddHost(h, t0)
	a.AddHost(fullHost(1, 1), t0.Add(5*time.Second))
	s := a.Snapshot(t0.Add(5 * time.Second))
	if s.Node == nil || s.Node.DiskReadMBPerSec != nil || s.QueryDiskReadCoveragePercent != nil {
		t.Fatalf("node %+v coverage %v: node disk must be omitted while the bad poll is in the window", s.Node, s.QueryDiskReadCoveragePercent)
	}
}

func TestNoHostSampleNoAccountingClaims(t *testing.T) {
	a := New(cfg())
	a.AddDeltas([]Delta{digestDelta(1, "SELECT 1", 10, 1e9)}, t0)
	s := a.Snapshot(t0)
	for _, k := range []string{AccountingKeyDiskBytes, AccountingKeyDiskWait, AccountingKeyCommitWait} {
		if s.Accounting[k] == AccountingOK {
			t.Errorf("accounting[%s] = ok without any host sample", k)
		}
	}
}
