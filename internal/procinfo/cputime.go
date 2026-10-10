package procinfo

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
)

const clkTckNs = 10_000_000 // USER_HZ 100

// ReadCPUTimeNs returns the process's cumulative user+system CPU time (all
// threads) from /proc/<pid>/stat.
func ReadCPUTimeNs(pid uint32) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	t, err := parseCPUTicks(b)
	return t * clkTckNs, err
}

// parseCPUTicks returns utime+stime (fields 14 and 15). comm (field 2) may
// contain spaces and parentheses, so fields are counted after its last ')'.
func parseCPUTicks(stat []byte) (uint64, error) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, fmt.Errorf("no comm in stat")
	}
	f := bytes.Fields(stat[i+1:]) // f[0] is field 3 (state)
	if len(f) < 13 {
		return 0, fmt.Errorf("short stat: %d fields after comm", len(f))
	}
	u, err1 := strconv.ParseUint(string(f[11]), 10, 64)
	s, err2 := strconv.ParseUint(string(f[12]), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("bad utime/stime")
	}
	return u + s, nil
}
