package procinfo

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadThreadOwner returns a thread's thread group (process) id and its own
// name (comm), from the Tgid and Name lines of /proc/<tid>/status. A TID is
// reachable as /proc/<tid> although it is not listed there.
func ReadThreadOwner(tid uint32) (tgid uint32, name string, err error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, "", err
	}
	return parseThreadOwner(string(b))
}

func parseThreadOwner(status string) (tgid uint32, name string, err error) {
	haveTgid := false
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "Name:"); ok {
			name = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			if err != nil {
				return 0, "", err
			}
			tgid, haveTgid = uint32(n), true
		}
	}
	if !haveTgid {
		return 0, "", fmt.Errorf("no Tgid in status")
	}
	return tgid, name, nil
}
