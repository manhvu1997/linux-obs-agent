// Package drain holds helpers for producers that hand accumulated data to the
// ClickHouse sink once per flush interval.
package drain

import "sync"

// Buffer collects up to max items between Drain calls; further items are
// counted and discarded. Safe for concurrent use. The zero value is disabled:
// Add is a no-op until Enable is called.
type Buffer[T any] struct {
	mu      sync.Mutex
	max     int
	items   []T
	dropped uint64
}

func (b *Buffer[T]) Enable(max int) {
	if max < 1 {
		max = 1
	}
	b.mu.Lock()
	b.max = max
	b.mu.Unlock()
}

func (b *Buffer[T]) Add(v T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.max == 0 {
		return
	}
	if len(b.items) >= b.max {
		b.dropped++
		return
	}
	b.items = append(b.items, v)
}

// Drain returns the items collected since the previous call and how many
// were discarded over the cap, and resets both.
func (b *Buffer[T]) Drain() ([]T, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	items, dropped := b.items, b.dropped
	b.items, b.dropped = nil, 0
	return items, dropped
}
