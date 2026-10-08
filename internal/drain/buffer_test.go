package drain

import "testing"

func TestBufferDisabledByDefault(t *testing.T) {
	var b Buffer[int]
	b.Add(1)
	if got, dropped := b.Drain(); got != nil || dropped != 0 {
		t.Fatalf("disabled buffer returned %v, %d", got, dropped)
	}
}

func TestBufferCapAndReset(t *testing.T) {
	var b Buffer[int]
	b.Enable(2)
	b.Add(1)
	b.Add(2)
	b.Add(3)
	got, dropped := b.Drain()
	if len(got) != 2 || got[0] != 1 || got[1] != 2 || dropped != 1 {
		t.Fatalf("got %v dropped %d, want [1 2] and 1", got, dropped)
	}
	if got, dropped := b.Drain(); got != nil || dropped != 0 {
		t.Fatalf("second drain = %v, %d, want empty", got, dropped)
	}
}
