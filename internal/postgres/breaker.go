package postgres

import "time"

type breakerAction int

const (
	actNone breakerAction = iota
	actShed
	actResume
)

// breaker detaches the probes when the traced statement rate stays above max
// for two consecutive polls, for cooldown; then it re-attaches. The first
// poll after a resume covers only part of an interval, so it can never shed
// on its own: two over-limit polls are always needed.
type breaker struct {
	max      float64
	cooldown time.Duration
	over     int
	shed     bool
	until    time.Time
	total    uint64
}

func (b *breaker) observe(rate float64, now time.Time) breakerAction {
	if b.shed {
		if now.Before(b.until) {
			return actNone
		}
		b.shed, b.over = false, 0
		return actResume
	}
	if b.max <= 0 || rate <= b.max { // max <= 0: breaker off
		b.over = 0
		return actNone
	}
	if b.over++; b.over < 2 {
		return actNone
	}
	b.shed, b.until, b.over = true, now.Add(b.cooldown), 0
	b.total++
	return actShed
}
