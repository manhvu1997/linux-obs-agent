// Package procinfo holds small best-effort /proc readers shared by the
// analyzers and report builders.
//
// Equivalent private copies currently live in the fsync, mongo_query and
// mysql_query eBPF loaders; those can migrate here when they are next touched.
package procinfo

import (
	"fmt"
	"os"
	"strings"
)

// ReadCmdline returns the full command line of a PID, with the NUL separators
// replaced by spaces. Returns "" when the process is gone or unreadable.
func ReadCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
}

// ReadCgroup returns the cgroup path from the first line of /proc/<pid>/cgroup.
// Works for both cgroup v1 and v2 layouts. Returns "" when unreadable.
func ReadCgroup(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	parts := strings.SplitN(line, ":", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return ""
}
