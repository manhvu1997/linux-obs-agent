package mysql

import (
	"errors"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
)

type fakeHost struct {
	node    []collector.NodeCPUTimes // consumed one per call
	nodeErr []bool
	disk    []collector.NodeDiskBytes // consumed one per call; nil → reader errors
	pid     map[uint32]uint64
	pidErr  map[uint32]bool
}

func (f *fakeHost) sampler() *hostSampler {
	h := newHostSampler()
	h.nodeCPU = func() (collector.NodeCPUTimes, error) {
		n, bad := f.node[0], f.nodeErr[0]
		f.node, f.nodeErr = f.node[1:], f.nodeErr[1:]
		if bad {
			return collector.NodeCPUTimes{}, errors.New("unreadable")
		}
		return n, nil
	}
	h.pidCPU = func(pid uint32) (uint64, error) {
		if f.pidErr[pid] {
			return 0, errors.New("gone")
		}
		return f.pid[pid], nil
	}
	h.nodeDisk = func() (collector.NodeDiskBytes, error) {
		if len(f.disk) == 0 {
			return collector.NodeDiskBytes{}, errors.New("no disk data")
		}
		d := f.disk[0]
		f.disk = f.disk[1:]
		return d, nil
	}
	return h
}

func nodeTimes(used, total uint64) collector.NodeCPUTimes {
	return collector.NodeCPUTimes{UsedNs: used, TotalNs: total, NumCPU: 8}
}

func TestHostSamplerNodeDeltaAfterPrime(t *testing.T) {
	f := &fakeHost{node: []collector.NodeCPUTimes{nodeTimes(100, 1000), nodeTimes(400, 2000)}, nodeErr: []bool{false, false}}
	h := f.sampler()
	h.prime()
	d := h.sample(nil)
	if !d.NodeOK || d.NodeCPUUsedNs != 300 || d.NodeCPUTotalNs != 1000 || d.NumCPU != 8 {
		t.Fatalf("got %+v", d)
	}
}

func TestHostSamplerNodeErrorAndBackwards(t *testing.T) {
	f := &fakeHost{
		node:    []collector.NodeCPUTimes{nodeTimes(100, 1000), {}, nodeTimes(500, 3000), nodeTimes(400, 3500), nodeTimes(600, 4000)},
		nodeErr: []bool{false, true, false, false, false},
	}
	h := f.sampler()
	h.prime()
	if d := h.sample(nil); d.NodeOK {
		t.Fatalf("read error: NodeOK must be false, got %+v", d)
	}
	if d := h.sample(nil); d.NodeOK {
		t.Fatalf("first read after an error has no baseline: NodeOK must be false, got %+v", d)
	}
	if d := h.sample(nil); d.NodeOK {
		t.Fatalf("used went backwards: NodeOK must be false, got %+v", d)
	}
	if d := h.sample(nil); !d.NodeOK || d.NodeCPUUsedNs != 200 || d.NodeCPUTotalNs != 500 {
		t.Fatalf("after rebaseline: got %+v", d)
	}
}

func TestHostSamplerNewPIDIsPartial(t *testing.T) {
	f := &fakeHost{node: []collector.NodeCPUTimes{nodeTimes(0, 0), nodeTimes(1, 1), nodeTimes(2, 2)}, nodeErr: []bool{false, false, false},
		pid: map[uint32]uint64{7: 5_000}}
	h := f.sampler()
	h.prime()
	if d := h.sample([]uint32{7}); !d.MysqldPartial || d.MysqldCPUNs != 0 {
		t.Fatalf("first sight of pid: want partial and 0, got %+v", d)
	}
	f.pid[7] = 9_000
	if d := h.sample([]uint32{7}); d.MysqldPartial || d.MysqldCPUNs != 4_000 {
		t.Fatalf("second sight: want 4000 and not partial, got %+v", d)
	}
}

func TestHostSamplerVanishedOrRestartedPIDIsPartial(t *testing.T) {
	f := &fakeHost{node: []collector.NodeCPUTimes{nodeTimes(0, 0), nodeTimes(1, 1), nodeTimes(2, 2), nodeTimes(3, 3)}, nodeErr: []bool{false, false, false, false},
		pid: map[uint32]uint64{7: 5_000}, pidErr: map[uint32]bool{}}
	h := f.sampler()
	h.prime()
	h.sample([]uint32{7})
	f.pid[7] = 1_000 // pid reused / restarted: counter went backwards
	if d := h.sample([]uint32{7}); !d.MysqldPartial || d.MysqldCPUNs != 0 {
		t.Fatalf("restart: got %+v", d)
	}
	f.pidErr[7] = true
	if d := h.sample([]uint32{7}); !d.MysqldPartial {
		t.Fatalf("vanished: got %+v", d)
	}
}

func TestHostSamplerDiskDelta(t *testing.T) {
	f := &fakeHost{
		node:    []collector.NodeCPUTimes{nodeTimes(0, 0), nodeTimes(1, 2), nodeTimes(2, 4)},
		nodeErr: []bool{false, false, false},
		disk:    []collector.NodeDiskBytes{{ReadBytes: 1000, WriteBytes: 50, Disks: 1}, {ReadBytes: 5000, WriteBytes: 150, Disks: 1}, {ReadBytes: 4000, WriteBytes: 200, Disks: 1}},
	}
	h := f.sampler()
	h.prime()
	if d := h.sample(nil); !d.DiskOK || d.DiskReadBytes != 4000 || d.DiskWriteBytes != 100 {
		t.Fatalf("got %+v", d)
	}
	if d := h.sample(nil); d.DiskOK {
		t.Fatalf("read counter went backwards (device removed): DiskOK must be false, got %+v", d)
	}
}

// A disk appearing (hot-plug, a new volume attached) adds its whole
// cumulative count to the sum: rebaseline instead of reporting it as one
// poll's reads, then resume deltas from the new set.
func TestHostSamplerDiskSetChangeRebaselines(t *testing.T) {
	f := &fakeHost{
		node:    []collector.NodeCPUTimes{nodeTimes(0, 0), nodeTimes(1, 2), nodeTimes(2, 4), nodeTimes(3, 6)},
		nodeErr: []bool{false, false, false, false},
		disk: []collector.NodeDiskBytes{
			{ReadBytes: 1000, WriteBytes: 50, Disks: 1},
			{ReadBytes: 900_000, WriteBytes: 90_000, Disks: 2}, // second disk appears with its history
			{ReadBytes: 901_000, WriteBytes: 90_100, Disks: 2},
		},
	}
	h := f.sampler()
	h.prime()
	if d := h.sample(nil); d.DiskOK {
		t.Fatalf("disk set changed: DiskOK must be false, got %+v", d)
	}
	if d := h.sample(nil); !d.DiskOK || d.DiskReadBytes != 1000 || d.DiskWriteBytes != 100 {
		t.Fatalf("after rebaseline got %+v", d)
	}
}
