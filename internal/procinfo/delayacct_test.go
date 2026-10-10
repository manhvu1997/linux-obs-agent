package procinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDelayAcctEnabledAt(t *testing.T) {
	d := t.TempDir()
	cmdOK := write(t, d, "cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet\n")
	cmdOff := write(t, d, "cmdline-off", "BOOT_IMAGE=/vmlinuz nodelayacct quiet\n")
	on := write(t, d, "on", "1\n")
	off := write(t, d, "off", "0\n")
	missing := filepath.Join(d, "missing")
	for _, c := range []struct {
		name, sysctl, cmdline string
		want                  bool
	}{
		{"sysctl 1", on, cmdOK, true},
		{"sysctl 0", off, cmdOK, false},
		{"no sysctl (kernel < 5.14), default on", missing, cmdOK, true},
		{"no sysctl, booted with nodelayacct", missing, cmdOff, false},
	} {
		got, err := delayAcctEnabledAt(c.sysctl, c.cmdline)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v; want %v", c.name, got, err, c.want)
		}
	}
}

func TestEnableDelayAcctAt(t *testing.T) {
	p := write(t, t.TempDir(), "task_delayacct", "0\n")
	if err := enableDelayAcctAt(p); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "1\n" {
		t.Fatalf("sysctl = %q, want \"1\\n\"", b)
	}
}
