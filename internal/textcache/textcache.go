// Package textcache maps kernel statement-text hashes to classified digests
// for the in-kernel aggregation of the MySQL and PostgreSQL tracers. Learn /
// Verify run on the text-event goroutine, Resolve / EndTick on the poll
// goroutine.
//
// Memory: at most max nodes (~150 B each with list element and map slot,
// measured; ~5 MB at 32 768) plus one digestRec per distinct digest among
// them (id, normalised text ≤ ~512 B, and with sample queries one sample
// ≤ 511 B).
package textcache

import (
	"container/list"
	"sync"
	"sync/atomic"

	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// Key identifies one statement text as the kernel aggregates it. MySQL keys
// by command too (the same text is a different digest as a prepare);
// PostgreSQL uses Command 0 (the text does not depend on the backend kind).
type Key struct {
	Command uint32
	Hash    uint64
}

// Entry is a statement text classified once.
type Entry struct {
	Class     string
	Digest    sqldigest.Digest
	Sample    string
	Truncated bool
}

// Sums are one kernel aggregation entry's sums. Kind is the PostgreSQL
// backend kind (unused by MySQL).
type Sums struct {
	PID                                                 uint32
	Kind                                                uint32
	Calls, WallNs, WallMaxNs, CPUNs, RunqNs, BytesOut   uint64
	DiskReadBytes, DiskWriteBytes, IOWaitNs, RedoWaitNs uint64
	ReplicaWaitNs                                       uint64
}

// Hooks call back into the kernel maps. Forget and MarkUnsafe are never
// invoked with the cache lock held. Command, when set, names a delta's
// command from its entry and sums (PostgreSQL: kind + text); nil uses
// Entry.Class.
type Hooks struct {
	Forget     func(command uint32, hash uint64)
	MarkUnsafe func(command uint32, hash uint64)
	Command    func(e Entry, s Sums) string
}

type parked struct {
	key  Key
	sums Sums
}

// digestRec is one digest shared by every cached hash that maps to it.
type digestRec struct {
	digest sqldigest.Digest
	sample string
	refs   int
}

type node struct {
	key       Key
	class     string
	truncated bool
	rec       *digestRec
}

// Cache maps kernel text hashes to classified statements.
type Cache struct {
	mu       sync.Mutex
	max      int
	ll       *list.List // front = most recently used; values are *node
	m        map[Key]*list.Element
	digests  map[string]*digestRec // by digest id
	hooks    Hooks
	pending  []parked // parked during the current tick
	previous []parked // parked during the previous tick
	mismatch atomic.Uint64
}

// New returns a cache holding at most max hashes.
func New(max int, hooks Hooks) *Cache {
	return &Cache{max: max, ll: list.New(), m: map[Key]*list.Element{}, digests: map[string]*digestRec{}, hooks: hooks}
}

// Learn records the text of a first-sight hash. A hash already cached with a
// different digest means one kernel hash covers two digests: the hash is
// marked unsafe and counted; the latest text is kept. It reports whether
// that happened.
func (c *Cache) Learn(k Key, e Entry) bool {
	c.mu.Lock()
	evicted, changed := c.putLocked(k, e)
	c.mu.Unlock()
	c.forgetAll(evicted)
	if changed {
		c.FlagMismatch(k)
	}
	return changed
}

// Verify checks a sampled resend against the cached classification and
// reports a mismatch (the hash is then marked unsafe).
func (c *Cache) Verify(k Key, e Entry) bool {
	c.mu.Lock()
	old, ok := c.getLocked(k)
	if !ok {
		evicted, _ := c.putLocked(k, e)
		c.mu.Unlock()
		c.forgetAll(evicted)
		return false
	}
	c.mu.Unlock()
	if old.Digest.ID == e.Digest.ID {
		return false
	}
	c.FlagMismatch(k)
	return true
}

// FlagMismatch counts one hash/digest inconsistency and sends every later
// statement of k through the exact per-event path. Must not be called with
// c.mu held.
func (c *Cache) FlagMismatch(k Key) {
	c.mismatch.Add(1)
	c.hooks.MarkUnsafe(k.Command, k.Hash)
}

// Mismatches returns the number of FlagMismatch calls.
func (c *Cache) Mismatches() uint64 { return c.mismatch.Load() }

// Lookup returns the cached entry of k without touching its LRU position.
func (c *Cache) Lookup(k Key) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(k)
}

func (c *Cache) getLocked(k Key) (Entry, bool) {
	el, ok := c.m[k]
	if !ok {
		return Entry{}, false
	}
	n := el.Value.(*node)
	return Entry{Class: n.class, Digest: n.rec.digest, Sample: n.rec.sample, Truncated: n.truncated}, true
}

func (c *Cache) internLocked(e Entry) *digestRec {
	r := c.digests[e.Digest.ID]
	if r == nil {
		r = &digestRec{digest: e.Digest, sample: e.Sample}
		c.digests[e.Digest.ID] = r
	} else if r.sample == "" {
		r.sample = e.Sample
	}
	r.refs++
	return r
}

func (c *Cache) releaseLocked(r *digestRec) {
	if r.refs--; r.refs <= 0 {
		delete(c.digests, r.digest.ID)
	}
}

// putLocked stores the entry and returns the keys evicted to stay within max,
// and whether an existing entry for k had a different digest.
func (c *Cache) putLocked(k Key, e Entry) (evicted []Key, changed bool) {
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		n := el.Value.(*node)
		changed = n.rec.digest.ID != e.Digest.ID
		rec := c.internLocked(e) // before release: the same record may be reused
		c.releaseLocked(n.rec)
		n.class, n.truncated, n.rec = e.Class, e.Truncated, rec
		return nil, changed
	}
	c.m[k] = c.ll.PushFront(&node{key: k, class: e.Class, truncated: e.Truncated, rec: c.internLocked(e)})
	for c.ll.Len() > c.max {
		el := c.ll.Back()
		old := el.Value.(*node)
		c.ll.Remove(el)
		delete(c.m, old.key)
		c.releaseLocked(old.rec)
		evicted = append(evicted, old.key) // the kernel must resend it
	}
	return evicted, false
}

func (c *Cache) forgetAll(keys []Key) {
	for _, k := range keys {
		c.hooks.Forget(k.Command, k.Hash)
	}
}

func (c *Cache) toDelta(e Entry, s Sums) querystats.Delta {
	cmd := e.Class
	if c.hooks.Command != nil {
		cmd = c.hooks.Command(e, s)
	}
	return querystats.Delta{
		PID: s.PID, Command: cmd, Digest: e.Digest, SampleQuery: e.Sample, Truncated: e.Truncated,
		Calls: s.Calls, WallNs: s.WallNs, WallMaxNs: s.WallMaxNs, CPUNs: s.CPUNs,
		RunqNs: s.RunqNs, BytesOut: s.BytesOut,
		DiskReadBytes: s.DiskReadBytes, DiskWriteBytes: s.DiskWriteBytes, IOWaitNs: s.IOWaitNs, RedoWaitNs: s.RedoWaitNs,
		ReplicaWaitNs: s.ReplicaWaitNs,
	}
}

// Resolve classifies one drained entry. Hash 0 (no text) is classified by
// command. An unknown hash is parked until its text event arrives.
func (c *Cache) Resolve(k Key, s Sums, byCommand func(uint32) Entry) (querystats.Delta, bool) {
	if k.Hash == 0 {
		return c.toDelta(byCommand(k.Command), s), true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		e, _ := c.getLocked(k)
		return c.toDelta(e, s), true
	}
	c.pending = append(c.pending, parked{k, s})
	return querystats.Delta{}, false
}

// EndTick returns the parked entries whose text arrived, and — for entries
// parked a full tick ago that are still unknown — deltas classified as
// unavailable(command), asking the kernel to resend those texts.
func (c *Cache) EndTick(unavailable func(command uint32) Entry) []querystats.Delta {
	c.mu.Lock()
	var out []querystats.Delta
	var forget []Key
	var still []parked
	for _, p := range c.previous {
		if e, ok := c.getLocked(p.key); ok {
			out = append(out, c.toDelta(e, p.sums))
			continue
		}
		out = append(out, c.toDelta(unavailable(p.key.Command), p.sums))
		forget = append(forget, p.key)
	}
	for _, p := range c.pending {
		if e, ok := c.getLocked(p.key); ok {
			out = append(out, c.toDelta(e, p.sums))
			continue
		}
		still = append(still, p)
	}
	c.previous, c.pending = still, nil
	c.mu.Unlock()
	c.forgetAll(forget)
	return out
}
