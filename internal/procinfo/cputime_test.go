package procinfo

import "testing"

func TestParseCPUTicks(t *testing.T) {
	// comm may contain spaces and parentheses; utime/stime are fields 14/15.
	stat := []byte("4821 (my (odd) proc) S 1 4821 4821 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 8 0 12345 1000 200 18446744073709551615")
	got, err := parseCPUTicks(stat)
	if err != nil || got != 300 {
		t.Fatalf("ticks = %d, %v; want 300", got, err)
	}
	if _, err := parseCPUTicks([]byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}
