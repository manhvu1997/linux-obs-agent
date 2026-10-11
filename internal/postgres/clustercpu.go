package postgres

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// clusterCPU turns a cluster's cumulative CPU into per-poll deltas. With a
// systemd unit of its own (Ubuntu: postgresql@16-main.service) the unit's
// cgroup counter is used: it includes backends that exited between polls.
// Otherwise the postmaster's and its children's /proc CPU are summed, and a
// poll in which a PID appeared or vanished is partial.
type clusterCPU struct {
	cgroupRead func() (uint64, error) // nil: per-PID mode
	pids       func() []uint32
	pidCPU     func(pid uint32) (uint64, error)
	prev       uint64
	have       bool
	prevPID    map[uint32]uint64
}

// sample returns the CPU ns since the previous call; partial means the value
// misses CPU (a first sample, a PID without baseline, a read error).
func (c *clusterCPU) sample() (delta uint64, partial bool) {
	if c.cgroupRead != nil {
		v, err := c.cgroupRead()
		if err != nil || !c.have || v < c.prev {
			c.prev, c.have = v, err == nil
			return 0, true
		}
		d := v - c.prev
		c.prev = v
		return d, false
	}
	next := map[uint32]uint64{}
	for _, pid := range c.pids() {
		v, err := c.pidCPU(pid)
		if err != nil {
			partial = true
			continue
		}
		if p, ok := c.prevPID[pid]; ok && v >= p {
			delta += v - p
		} else {
			partial = true
		}
		next[pid] = v
	}
	if len(c.prevPID) > 0 {
		for pid := range c.prevPID {
			if _, ok := next[pid]; !ok {
				partial = true // exited since the last poll: its last CPU is lost
				break
			}
		}
	}
	c.prevPID = next
	return delta, partial
}

// cgroupCPUReader returns a reader of the cumulative CPU ns of the cgroup in
// cgroupFile (/proc/<pid>/cgroup content) when the postmaster runs in its own
// systemd service: cgroup v2 cpu.stat usage_usec, else v1 cpuacct.usage.
func cgroupCPUReader(sysfs, cgroupFile, unit string) func() (uint64, error) {
	if unit == "" {
		return nil
	}
	for _, line := range strings.Split(strings.TrimSpace(cgroupFile), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 || !strings.HasSuffix(f[2], unit) {
			continue
		}
		switch {
		case f[0] == "0" && f[1] == "":
			p := sysfs + "/fs/cgroup" + f[2] + "/cpu.stat"
			return func() (uint64, error) { return readUsageUsec(p) }
		case strings.Contains(","+f[1]+",", ",cpuacct,"):
			p := sysfs + "/fs/cgroup/" + f[1] + f[2] + "/cpuacct.usage"
			return func() (uint64, error) { return readUint(p) }
		}
	}
	return nil
}

func readUsageUsec(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "usage_usec "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n * 1000, err
		}
	}
	return 0, fmt.Errorf("%s: no usage_usec", path)
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// childrenOf lists pid and its children from /proc/<pid>/task/<pid>/children
// (CONFIG_PROC_CHILDREN, enabled on Ubuntu kernels).
func childrenOf(pid uint32) []uint32 {
	out := []uint32{pid}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return out
	}
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.ParseUint(f, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out
}
