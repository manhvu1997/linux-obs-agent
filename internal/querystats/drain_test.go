package querystats

import (
	"sync"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func dEv(pid uint32, id string, cpu uint64) Event {
	return Event{
		PID: pid, Command: "query",
		Digest: sqldigest.Digest{ID: id, Text: "select " + id, Normalized: true},
		CPUNs:  cpu, WallNs: 2 * cpu, RunqNs: cpu / 2, BytesIn: 10, BytesOut: 100,
		At: time.Unix(1_800_000_000, 0),
	}
}

func TestDrainDisabledByDefault(t *testing.T) {
	a := New(Config{})
	a.Add(dEv(1, "d1", 1000))
	if out, folded := a.DrainDigests(); out != nil || folded != 0 {
		t.Fatalf("disabled drain returned %v, %d", out, folded)
	}
}

func TestDrainConsecutiveDisjoint(t *testing.T) {
	a := New(Config{})
	a.EnableDrain(100)
	for i := 0; i < 3; i++ {
		a.Add(dEv(1, "d1", 1000))
	}
	first, _ := a.DrainDigests()
	a.Add(dEv(1, "d1", 1000))
	a.Add(dEv(1, "d1", 5000))
	second, _ := a.DrainDigests()
	third, _ := a.DrainDigests()

	if len(first) != 1 || first[0].Calls != 3 || first[0].CPUNs != 3000 || first[0].Text != "select d1" {
		t.Fatalf("first = %+v", first)
	}
	if len(second) != 1 || second[0].Calls != 2 || second[0].CPUNs != 6000 || second[0].WallMaxNs != 10000 {
		t.Fatalf("second = %+v", second)
	}
	if third != nil {
		t.Fatalf("third drain should be empty, got %+v", third)
	}
	if got := a.life["d1"].c.Calls; got != first[0].Calls+second[0].Calls {
		t.Fatalf("drains sum to %d calls, lifetime has %d", first[0].Calls+second[0].Calls, got)
	}
}

func TestDrainCapFoldsIntoOther(t *testing.T) {
	a := New(Config{})
	a.EnableDrain(1)
	a.Add(dEv(1, "d1", 1))
	a.Add(dEv(1, "d2", 2))
	a.Add(dEv(1, "d3", 3))
	out, folded := a.DrainDigests()
	if folded != 2 {
		t.Fatalf("folded = %d, want 2", folded)
	}
	var total uint64
	var other *DigestDelta
	for i := range out {
		total += out[i].CPUNs
		if out[i].DigestID == OtherDigestID {
			other = &out[i]
		}
	}
	if total != 6 {
		t.Fatalf("total cpu = %d, want 6 (overflow must keep the data)", total)
	}
	if other == nil || other.Calls != 2 || other.Text != OtherDigestText || other.PID != 1 {
		t.Fatalf("other = %+v", other)
	}
}

func TestDrainConcurrent(t *testing.T) {
	a := New(Config{})
	a.EnableDrain(1000)
	const writers, perWriter = 4, 500
	var drained uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			out, _ := a.DrainDigests()
			for _, d := range out {
				drained += d.Calls
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				a.Add(dEv(uint32(w), "d", 1))
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-done
	out, _ := a.DrainDigests()
	for _, d := range out {
		drained += d.Calls
	}
	if drained != writers*perWriter {
		t.Fatalf("drained %d calls, want %d", drained, writers*perWriter)
	}
}
