package mysql

import (
	"container/list"
	"sync"
	"sync/atomic"

	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// textKey identifies one statement text as the kernel aggregates it. The
// command is part of the key: the same text is a different digest as a
// COM_STMT_PREPARE ("prepare: …") than as a COM_QUERY.
type textKey struct {
	command uint32
	hash    uint64
}

// textEntry is a statement text classified once (cmdmap + system-schema
// folding + sample privacy).
type textEntry struct {
	class     string
	digest    sqldigest.Digest
	sample    string
	truncated bool
}

// aggSums are one kernel aggregation entry's sums.
type aggSums struct {
	PID                                                                  uint32
	Calls, WallNs, WallMaxNs, CPUNs, CPUMaxNs, RunqNs, BytesIn, BytesOut uint64
}

// textCacheHooks call back into the kernel maps. They are never invoked with
// the cache lock held, so they may safely call back into the cache.
type textCacheHooks struct {
	forget     func(command uint32, hash uint64)
	markUnsafe func(command uint32, hash uint64)
}

type parked struct {
	key  textKey
	sums aggSums
}

// textCache maps kernel text hashes to classified statements. learn/verify
// run on the text-event goroutine, resolve/endTick on the poll goroutine.
type textCache struct {
	mu       sync.Mutex
	max      int
	ll       *list.List // front = most recently used; values are textKey
	m        map[textKey]*list.Element
	entries  map[textKey]textEntry
	hooks    textCacheHooks
	pending  []parked // parked during the current tick
	previous []parked // parked during the previous tick
	mismatch atomic.Uint64
}

func newTextCache(max int, hooks textCacheHooks) *textCache {
	return &textCache{max: max, ll: list.New(), m: map[textKey]*list.Element{}, entries: map[textKey]textEntry{}, hooks: hooks}
}

// learn records the text of a first-sight hash.
func (c *textCache) learn(k textKey, e textEntry) {
	c.mu.Lock()
	evicted := c.putLocked(k, e)
	c.mu.Unlock()
	c.forgetAll(evicted)
}

// verify checks a sampled resend against the cached classification. On a
// different digest the hash is marked unsafe in the kernel: its statements go
// back to exact per-event processing.
func (c *textCache) verify(k textKey, e textEntry) bool {
	c.mu.Lock()
	old, ok := c.entries[k]
	if !ok {
		evicted := c.putLocked(k, e)
		c.mu.Unlock()
		c.forgetAll(evicted)
		return false
	}
	c.mu.Unlock()
	if old.digest.ID == e.digest.ID {
		return false
	}
	c.mismatch.Add(1)
	c.hooks.markUnsafe(k.command, k.hash)
	return true
}

func (c *textCache) mismatches() uint64 { return c.mismatch.Load() }

// putLocked stores the entry and returns the keys evicted to stay within max.
// The caller must forget them in the kernel after releasing c.mu.
func (c *textCache) putLocked(k textKey, e textEntry) (evicted []textKey) {
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		c.entries[k] = e
		return nil
	}
	c.m[k] = c.ll.PushFront(k)
	c.entries[k] = e
	for c.ll.Len() > c.max {
		el := c.ll.Back()
		old := el.Value.(textKey)
		c.ll.Remove(el)
		delete(c.m, old)
		delete(c.entries, old)
		evicted = append(evicted, old) // the kernel must resend it
	}
	return evicted
}

func (c *textCache) forgetAll(keys []textKey) {
	for _, k := range keys {
		c.hooks.forget(k.command, k.hash)
	}
}

func toDelta(e textEntry, s aggSums) querystats.Delta {
	return querystats.Delta{
		PID: s.PID, Command: e.class, Digest: e.digest, SampleQuery: e.sample, Truncated: e.truncated,
		Calls: s.Calls, WallNs: s.WallNs, WallMaxNs: s.WallMaxNs, CPUNs: s.CPUNs, CPUMaxNs: s.CPUMaxNs,
		RunqNs: s.RunqNs, BytesIn: s.BytesIn, BytesOut: s.BytesOut,
	}
}

// resolve classifies one drained entry. Hash 0 (no text) is classified by
// command. An unknown hash is parked until its text event arrives.
func (c *textCache) resolve(k textKey, s aggSums, byCommand func(uint32) textEntry) (querystats.Delta, bool) {
	if k.hash == 0 {
		return toDelta(byCommand(k.command), s), true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		return toDelta(c.entries[k], s), true
	}
	c.pending = append(c.pending, parked{k, s})
	return querystats.Delta{}, false
}

// endTick returns the parked entries whose text arrived, and — for entries
// parked a full tick ago that are still unknown — deltas classified as
// unavailable(command), asking the kernel to resend those texts.
func (c *textCache) endTick(unavailable func(command uint32) textEntry) []querystats.Delta {
	c.mu.Lock()
	var out []querystats.Delta
	var forget []textKey
	var still []parked
	for _, p := range c.previous {
		if e, ok := c.entries[p.key]; ok {
			out = append(out, toDelta(e, p.sums))
			continue
		}
		out = append(out, toDelta(unavailable(p.key.command), p.sums))
		forget = append(forget, p.key)
	}
	for _, p := range c.pending {
		if e, ok := c.entries[p.key]; ok {
			out = append(out, toDelta(e, p.sums))
			continue
		}
		still = append(still, p)
	}
	c.previous, c.pending = still, nil
	c.mu.Unlock()
	c.forgetAll(forget)
	return out
}
