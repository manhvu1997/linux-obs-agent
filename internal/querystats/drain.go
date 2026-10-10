package querystats

import "sort"

// DigestDelta is one (pid, digest) aggregate accumulated since the previous
// DrainDigests call. Consecutive drains are disjoint, so summing them gives
// exact totals — what a ClickHouse delta row needs.
type DigestDelta struct {
	PID       uint32
	DigestID  string
	Command   string
	Text      string
	Sample    string
	Calls     uint64
	CPUNs     uint64
	RunqNs    uint64
	WallNs    uint64
	WallMaxNs uint64
	BytesOut  uint64
	// Disk bytes and waits over the interval (see Event).
	DiskReadBytes  uint64
	DiskWriteBytes uint64
	IOWaitNs       uint64
	RedoWaitNs     uint64
}

// EnableDrain starts accumulating per-(pid, digest) deltas for DrainDigests.
// maxKeys bounds the keys per interval; later digests fold into that pid's
// OtherDigestID entry. Until it is called, Add does no drain work.
func (a *Aggregator) EnableDrain(maxKeys int) {
	if maxKeys < 1 {
		maxKeys = 1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.drainMax = maxKeys
	if a.drain == nil {
		a.drain = make(map[key]*acc)
	}
}

// DrainDigests returns everything accumulated since the previous call and
// resets the accumulator. folded counts events that went to OtherDigestID
// because the key cap was reached. It returns nil, 0 when the drain is off.
func (a *Aggregator) DrainDigests() (out []DigestDelta, folded uint64) {
	a.mu.Lock()
	m := a.drain
	folded = a.drainFolded
	if m != nil {
		a.drain = make(map[key]*acc, len(m))
		a.drainFolded = 0
	}
	a.mu.Unlock()
	if len(m) == 0 {
		return nil, folded
	}
	out = make([]DigestDelta, 0, len(m))
	for k, x := range m {
		out = append(out, DigestDelta{
			PID: k.pid, DigestID: k.id, Command: x.command, Text: x.text, Sample: x.sample,
			Calls: x.calls, CPUNs: x.cpu, RunqNs: x.runq, WallNs: x.wall, WallMaxNs: x.wallMax,
			BytesOut: x.out, DiskReadBytes: x.diskRead, DiskWriteBytes: x.diskWrite, IOWaitNs: x.ioWait, RedoWaitNs: x.redoWait,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].DigestID < out[j].DigestID
	})
	return out, folded
}

// addDrain is called from addDeltaLocked with a.mu held. It keys by the delta's own
// digest: the bucket map's MaxDigests fold is a Prometheus/report concern.
func (a *Aggregator) addDrain(d Delta) {
	k := key{d.PID, d.Digest.ID}
	x, ok := a.drain[k]
	if !ok {
		if len(a.drain) >= a.drainMax {
			a.drainFolded += d.Calls
			k = key{d.PID, OtherDigestID}
			x = a.drain[k]
			if x == nil {
				x = &acc{command: "other", text: OtherDigestText, normalized: true}
				a.drain[k] = x
			}
		} else {
			x = &acc{command: d.Command, text: d.Digest.Text, normalized: d.Digest.Normalized}
			a.drain[k] = x
		}
	}
	x.add(d)
	if k.id == OtherDigestID {
		// The overflow bucket mixes unrelated statements; a sample of the
		// first one would be arbitrary and misleading.
		x.sample = ""
	}
}
