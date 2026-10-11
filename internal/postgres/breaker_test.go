package postgres

import (
	"testing"
	"time"
)

func TestBreakerShedsAfterTwoPolls(t *testing.T) {
	b := &breaker{max: 1000, cooldown: 10 * time.Minute}
	t0 := time.Unix(0, 0)
	if b.observe(5000, t0) != actNone {
		t.Fatal("one over-limit poll must not shed")
	}
	if b.observe(5000, t0.Add(5*time.Second)) != actShed || b.total != 1 {
		t.Fatal("second over-limit poll must shed")
	}
	if b.observe(0, t0.Add(time.Minute)) != actNone {
		t.Fatal("cooldown")
	}
	if b.observe(0, t0.Add(11*time.Minute)) != actResume {
		t.Fatal("resume after cooldown")
	}
}

// Review Focus 5.
func TestBreakerReshedsAfterTwoPolls(t *testing.T) {
	b := &breaker{max: 1000, cooldown: time.Minute}
	t0 := time.Unix(0, 0)
	b.observe(5000, t0)
	b.observe(5000, t0.Add(5*time.Second)) // shed
	if b.observe(5000, t0.Add(2*time.Minute)) != actResume {
		t.Fatal("resume expected")
	}
	if b.observe(5000, t0.Add(2*time.Minute+5*time.Second)) != actNone {
		t.Fatal("the first over-limit poll after a resume must not shed")
	}
	if b.observe(5000, t0.Add(2*time.Minute+10*time.Second)) != actShed || b.total != 2 {
		t.Fatal("re-shed after two polls")
	}
}

func TestBreakerResetsOnNormalPoll(t *testing.T) {
	b := &breaker{max: 1000, cooldown: time.Minute}
	t0 := time.Unix(0, 0)
	b.observe(5000, t0)
	b.observe(10, t0.Add(5*time.Second))
	if b.observe(5000, t0.Add(10*time.Second)) != actNone {
		t.Fatal("non-consecutive over-limit polls must not shed")
	}
}

func TestBreakerOffWhenMaxNotPositive(t *testing.T) {
	b := &breaker{max: 0, cooldown: time.Minute}
	t0 := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		if b.observe(1e9, t0.Add(time.Duration(i)*5*time.Second)) != actNone || b.shed {
			t.Fatal("max <= 0 disables the breaker")
		}
	}
}
