package procinfo

import "testing"

func TestParseThreadOwner(t *testing.T) {
	tgid, name, err := parseThreadOwner("Name:\tconnection\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t2578\nNgid:\t0\nPid:\t2375502\n")
	if err != nil || tgid != 2578 || name != "connection" {
		t.Fatalf("got %d %q, %v", tgid, name, err)
	}
	if _, _, err := parseThreadOwner("Name:\tx\n"); err == nil {
		t.Fatal("missing Tgid must be an error")
	}
}
