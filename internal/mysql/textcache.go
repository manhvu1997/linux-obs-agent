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
	PID                                                 uint32
	Calls, WallNs, WallMaxNs, CPUNs, RunqNs, BytesOut   uint64
	DiskReadBytes, DiskWriteBytes, IOWaitNs, RedoWaitNs uint64
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

// digestRec is one digest shared by every cached hash that maps to it (many
// hashes — whitespace, comment or literal-shape variants — normalise to one
// digest): its text and id are stored once, plus the digest's first sample
// (only with mysql.sample_queries; classify drops samples otherwise). refs
// counts the hashes referencing it; the record is released at zero.
type digestRec struct {
	digest sqldigest.Digest
	sample string
	refs   int
}

// node is one cached hash: per-text fields plus the shared digest record.
type node struct {
	key       textKey
	class     string // a cmdmap constant, no allocation
	truncated bool
	rec       *digestRec
}

// textCache maps kernel text hashes to classified statements. learn/verify
// run on the text-event goroutine, resolve/endTick on the poll goroutine.
//
// Memory: at most max nodes (~150 B each with list element and map slot,
// measured; ~5 MB at 32 768) plus one digestRec per distinct digest among them (id,
// normalised text ≤ ~512 B, and with mysql.sample_queries one sample
// ≤ 511 B).
type textCache struct {
	mu       sync.Mutex
	max      int
	ll       *list.List // front = most recently used; values are *node
	m        map[textKey]*list.Element
	digests  map[string]*digestRec // by digest id
	hooks    textCacheHooks
	pending  []parked // parked during the current tick
	previous []parked // parked during the previous tick
	mismatch atomic.Uint64
}

func newTextCache(max int, hooks textCacheHooks) *textCache {
	return &textCache{max: max, ll: list.New(), m: map[textKey]*list.Element{}, digests: map[string]*digestRec{}, hooks: hooks}
}

// learn records the text of a first-sight hash. A hash already cached with a
// different digest (a resend after ForgetText or a kernel text_seen
// eviction) means one kernel hash covers two digests: like a verify
// mismatch, the hash is marked unsafe and counted; the latest text is kept.
// It reports whether that happened.
func (c *textCache) learn(k textKey, e textEntry) bool {
	c.mu.Lock()
	evicted, changed := c.putLocked(k, e)
	c.mu.Unlock()
	c.forgetAll(evicted)
	if changed {
		c.flagMismatch(k)
	}
	return changed
}

// verify checks a sampled resend against the cached classification. On a
// different digest the hash is marked unsafe in the kernel: its statements go
// back to exact per-event processing.
func (c *textCache) verify(k textKey, e textEntry) bool {
	c.mu.Lock()
	old, ok := c.getLocked(k)
	if !ok {
		evicted, _ := c.putLocked(k, e)
		c.mu.Unlock()
		c.forgetAll(evicted)
		return false
	}
	c.mu.Unlock()
	if old.digest.ID == e.digest.ID {
		return false
	}
	c.flagMismatch(k)
	return true
}

// flagMismatch counts one hash/digest inconsistency and sends every later
// command of k through the exact per-event path. Must not be called with
// c.mu held.
func (c *textCache) flagMismatch(k textKey) {
	c.mismatch.Add(1)
	c.hooks.markUnsafe(k.command, k.hash)
}

func (c *textCache) mismatches() uint64 { return c.mismatch.Load() }

func (c *textCache) getLocked(k textKey) (textEntry, bool) {
	el, ok := c.m[k]
	if !ok {
		return textEntry{}, false
	}
	n := el.Value.(*node)
	return textEntry{class: n.class, digest: n.rec.digest, sample: n.rec.sample, truncated: n.truncated}, true
}

func (c *textCache) internLocked(e textEntry) *digestRec {
	r := c.digests[e.digest.ID]
	if r == nil {
		r = &digestRec{digest: e.digest, sample: e.sample}
		c.digests[e.digest.ID] = r
	} else if r.sample == "" {
		r.sample = e.sample
	}
	r.refs++
	return r
}

func (c *textCache) releaseLocked(r *digestRec) {
	if r.refs--; r.refs <= 0 {
		delete(c.digests, r.digest.ID)
	}
}

// putLocked stores the entry and returns the keys evicted to stay within max,
// and whether an existing entry for k had a different digest. The caller must
// forget the evicted keys in the kernel after releasing c.mu.
func (c *textCache) putLocked(k textKey, e textEntry) (evicted []textKey, changed bool) {
	if el, ok := c.m[k]; ok {
		c.ll.MoveToFront(el)
		n := el.Value.(*node)
		changed = n.rec.digest.ID != e.digest.ID
		rec := c.internLocked(e) // before release: the same record may be reused
		c.releaseLocked(n.rec)
		n.class, n.truncated, n.rec = e.class, e.truncated, rec
		return nil, changed
	}
	c.m[k] = c.ll.PushFront(&node{key: k, class: e.class, truncated: e.truncated, rec: c.internLocked(e)})
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

func (c *textCache) forgetAll(keys []textKey) {
	for _, k := range keys {
		c.hooks.forget(k.command, k.hash)
	}
}

func toDelta(e textEntry, s aggSums) querystats.Delta {
	return querystats.Delta{
		PID: s.PID, Command: e.class, Digest: e.digest, SampleQuery: e.sample, Truncated: e.truncated,
		Calls: s.Calls, WallNs: s.WallNs, WallMaxNs: s.WallMaxNs, CPUNs: s.CPUNs,
		RunqNs: s.RunqNs, BytesOut: s.BytesOut,
		DiskReadBytes: s.DiskReadBytes, DiskWriteBytes: s.DiskWriteBytes, IOWaitNs: s.IOWaitNs, RedoWaitNs: s.RedoWaitNs,
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
		e, _ := c.getLocked(k)
		return toDelta(e, s), true
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
		if e, ok := c.getLocked(p.key); ok {
			out = append(out, toDelta(e, p.sums))
			continue
		}
		out = append(out, toDelta(unavailable(p.key.command), p.sums))
		forget = append(forget, p.key)
	}
	for _, p := range c.pending {
		if e, ok := c.getLocked(p.key); ok {
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
