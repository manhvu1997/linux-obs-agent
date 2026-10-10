package querystats

import (
	"testing"
	"time"
)

func TestDrainHostSumsSinceLastDrain(t *testing.T) {
	a := New(cfg())
	if (a.DrainHost() != HostWindow{}) {
		t.Fatal("drain off must return the zero value")
	}
	a.EnableHostDrain()
	h := okHost(30e9, 40e9, 4e9)
	h.DiskOK, h.DiskReadBytes, h.DiskWriteBytes = true, 100, 50
	a.AddHost(h, t0)
	a.AddHost(h, t0.Add(5*time.Second))
	w := a.DrainHost()
	if w.Samples != 2 || w.NumCPU != 8 || w.NodeCPUUsedNs != 60e9 || w.MysqldCPUNs != 8e9 || w.DiskReadBytes != 200 || w.DiskWriteBytes != 100 ||
		!w.NodeOK || !w.MysqldOK || !w.DiskOK || !w.IOWaitOK || !w.RedoWaitOK {
		t.Fatalf("window = %+v", w)
	}
	if got := a.DrainHost(); got.Samples != 0 {
		t.Fatalf("second drain = %+v, want empty", got)
	}
}

func TestDrainHostAvailabilityIsAllPolls(t *testing.T) {
	a := New(cfg())
	a.EnableHostDrain()
	bad := okHost(1, 2, 1)
	bad.NodeOK, bad.MysqldPartial, bad.IOWaitReason = false, true, "delayacct_disabled"
	a.AddHost(okHost(1, 2, 1), t0)
	a.AddHost(bad, t0.Add(time.Second))
	w := a.DrainHost()
	if w.NodeOK || w.MysqldOK || w.DiskOK || w.IOWaitOK || !w.RedoWaitOK {
		t.Fatalf("window = %+v: one bad poll must clear the matching flags", w)
	}
}
