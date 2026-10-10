package querystats

// HostWindow is what the host did since the previous DrainHost: the
// ClickHouse host_stats denominators and which per-statement signals every
// poll measured. The zero value (Samples 0) means nothing to write.
type HostWindow struct {
	Samples        int
	NumCPU         int
	NodeCPUUsedNs  uint64
	MysqldCPUNs    uint64
	DiskReadBytes  uint64
	DiskWriteBytes uint64
	NodeOK         bool // every poll had a valid /proc/stat delta
	MysqldOK       bool // no poll lacked a mysqld baseline
	DiskOK         bool // every poll had a valid /proc/diskstats delta
	IOWaitOK       bool // every poll measured block-I/O wait
	RedoWaitOK     bool // every poll measured commit wait
}

// hostDrain accumulates HostDelta between drains; nil until EnableHostDrain.
type hostDrain struct {
	w                                           HostWindow
	nodeBad, mysqldBad, diskBad, ioBad, redoBad bool
}

// EnableHostDrain starts accumulating host deltas for DrainHost.
func (a *Aggregator) EnableHostDrain() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hdrain == nil {
		a.hdrain = &hostDrain{}
	}
}

// DrainHost returns the host deltas since the previous call and resets them.
func (a *Aggregator) DrainHost() HostWindow {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.hdrain
	if d == nil || d.w.Samples == 0 {
		return HostWindow{}
	}
	w := d.w
	w.NodeOK, w.MysqldOK, w.DiskOK = !d.nodeBad, !d.mysqldBad, !d.diskBad
	w.IOWaitOK, w.RedoWaitOK = !d.ioBad, !d.redoBad
	*d = hostDrain{}
	return w
}

// add folds one poll; called from AddHost with a.mu held.
func (d *hostDrain) add(h HostDelta) {
	d.w.Samples++
	if h.NodeOK {
		d.w.NodeCPUUsedNs += h.NodeCPUUsedNs
		d.w.NumCPU = h.NumCPU
	} else {
		d.nodeBad = true
	}
	d.w.MysqldCPUNs += h.MysqldCPUNs
	d.mysqldBad = d.mysqldBad || h.MysqldPartial
	if h.DiskOK {
		d.w.DiskReadBytes += h.DiskReadBytes
		d.w.DiskWriteBytes += h.DiskWriteBytes
	} else {
		d.diskBad = true
	}
	d.ioBad = d.ioBad || h.IOWaitReason != ""
	d.redoBad = d.redoBad || h.RedoWaitReason != ""
}
