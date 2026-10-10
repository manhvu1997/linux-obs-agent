package chsink

import "github.com/manhvu1997/linux-obs-agent/internal/querystats"

const (
	MinorDigestID   = "<minor>"
	MinorDigestText = "<minor digests: each under clickhouse.min_digest_share_percent of the interval's query CPU and disk reads, never slow>"
)

// foldMinor merges, per (pid, command), every digest whose CPU is under
// sharePct % of the interval's query CPU AND whose disk reads are under
// sharePct % of the interval's query disk reads AND that had no execution
// slower than slowNs, into one MinorDigestID row. Sums stay exact; one-off
// cheap statements stop producing rows. sharePct <= 0 disables folding.
//
// When an interval's total of a signal is 0 (no query CPU, or no disk reads
// at all), every digest's 0 counts as "under the share" for that signal, so
// an interval where only disk-reading statements ran still folds on CPU.
func foldMinor(d []querystats.DigestDelta, sharePct float64, slowNs uint64) []querystats.DigestDelta {
	if sharePct <= 0 || len(d) == 0 {
		return d
	}
	var cpuAll, diskAll uint64
	for _, x := range d {
		cpuAll += x.CPUNs
		diskAll += x.DiskReadBytes
	}
	minor := func(v, all uint64) bool { return float64(v)*100 < sharePct*float64(all) || (all == 0 && v == 0) }
	type key struct {
		pid uint32
		cmd string
	}
	out := make([]querystats.DigestDelta, 0, len(d))
	folded := map[key]int{} // index into out
	for _, x := range d {
		if x.DigestID == MinorDigestID || !minor(x.CPUNs, cpuAll) || !minor(x.DiskReadBytes, diskAll) || x.WallMaxNs >= slowNs {
			out = append(out, x)
			continue
		}
		k := key{x.PID, x.Command}
		i, ok := folded[k]
		if !ok {
			out = append(out, querystats.DigestDelta{PID: x.PID, DigestID: MinorDigestID, Command: x.Command, Text: MinorDigestText})
			i = len(out) - 1
			folded[k] = i
		}
		m := &out[i]
		m.Calls += x.Calls
		m.CPUNs += x.CPUNs
		m.RunqNs += x.RunqNs
		m.WallNs += x.WallNs
		m.WallMaxNs = max(m.WallMaxNs, x.WallMaxNs)
		m.BytesOut += x.BytesOut
		m.DiskReadBytes += x.DiskReadBytes
		m.DiskWriteBytes += x.DiskWriteBytes
		m.IOWaitNs += x.IOWaitNs
		m.RedoWaitNs += x.RedoWaitNs
	}
	return out
}
