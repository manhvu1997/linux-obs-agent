package procinfo

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

const (
	delayAcctSysctl = "/proc/sys/kernel/task_delayacct"
	procCmdline     = "/proc/cmdline"
)

// DelayAcctEnabled reports whether the kernel accounts per-task delays
// (block-I/O wait among them). Since 5.14 it is off by default and switched
// with the task_delayacct sysctl; older kernels have no sysctl and account
// unless booted with nodelayacct.
func DelayAcctEnabled() (bool, error) { return delayAcctEnabledAt(delayAcctSysctl, procCmdline) }

// EnableDelayAcct turns delay accounting on (needs CAP_SYS_ADMIN).
func EnableDelayAcct() error { return enableDelayAcctAt(delayAcctSysctl) }

func delayAcctEnabledAt(sysctl, cmdline string) (bool, error) {
	b, err := os.ReadFile(sysctl)
	if err == nil {
		return strings.TrimSpace(string(b)) == "1", nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	c, err := os.ReadFile(cmdline)
	if err != nil {
		return false, err
	}
	for _, f := range strings.Fields(string(c)) {
		if f == "nodelayacct" {
			return false, nil
		}
	}
	return true, nil
}

func enableDelayAcctAt(sysctl string) error { return os.WriteFile(sysctl, []byte("1\n"), 0o644) }
