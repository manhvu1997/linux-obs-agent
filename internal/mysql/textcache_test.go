package mysql

import (
	"testing"
	"unsafe"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

type hookLog struct{ forgot, unsafe []textKey }

func newTestCache(max int) (*textCache, *hookLog) {
	l := &hookLog{}
	return newTextCache(max, textCacheHooks{
		forget:     func(c uint32, h uint64) { l.forgot = append(l.forgot, textKey{c, h}) },
		markUnsafe: func(c uint32, h uint64) { l.unsafe = append(l.unsafe, textKey{c, h}) },
	}), l
}

func entry(sql, class string) textEntry {
	return textEntry{class: class, digest: sqldigest.Normalize(sql), sample: sql}
}

func noCmd(uint32) textEntry { panic("byCommand must not be called for a non-zero hash") }

func TestResolveKnownHash(t *testing.T) {
	c, _ := newTestCache(8)
	k := textKey{3, 42}
	c.learn(k, entry("SELECT 1", "query"))
	d, ok := c.resolve(k, aggSums{PID: 7, Calls: 5, CPUNs: 10}, noCmd)
	if !ok || d.Calls != 5 || d.PID != 7 || d.Digest.Text != "select ?" || d.Command != "query" {
		t.Fatalf("got %+v, %v", d, ok)
	}
}

func TestHashZeroUsesCommandPlaceholder(t *testing.T) {
	c, _ := newTestCache(8)
	d, ok := c.resolve(textKey{25, 0}, aggSums{Calls: 2}, func(cmd uint32) textEntry {
		return textEntry{class: "other", digest: sqldigest.Digest{ID: "p", Text: "<COM_STMT_CLOSE>"}}
	})
	if !ok || d.Digest.Text != "<COM_STMT_CLOSE>" {
		t.Fatalf("got %+v, %v", d, ok)
	}
}

func TestCacheKeyIncludesCommand(t *testing.T) {
	c, _ := newTestCache(8)
	c.learn(textKey{22, 9}, entry("SELECT ?", "stmt_prepare"))
	if _, ok := c.resolve(textKey{23, 9}, aggSums{Calls: 1}, noCmd); ok {
		t.Fatal("an execute must not reuse the prepare's cache entry")
	}
}

func TestUnknownHashForgottenAfterOneTick(t *testing.T) {
	c, log := newTestCache(8)
	k := textKey{3, 77}
	if _, ok := c.resolve(k, aggSums{Calls: 4}, noCmd); ok {
		t.Fatal("unknown hash resolved")
	}
	unavailable := func(uint32) textEntry {
		return textEntry{class: "query", digest: sqldigest.Digest{ID: "u", Text: "<text unavailable>"}}
	}
	// The text may still arrive during this tick: nothing is flushed yet.
	if got := c.endTick(unavailable); len(got) != 0 {
		t.Fatalf("flushed %d deltas in the tick they were parked", len(got))
	}
	got := c.endTick(unavailable)
	if len(got) != 1 || got[0].Calls != 4 || got[0].Digest.Text != "<text unavailable>" {
		t.Fatalf("got %+v", got)
	}
	if len(log.forgot) != 1 || log.forgot[0] != k {
		t.Fatalf("forget calls = %v", log.forgot)
	}
}

func TestPendingResolvedWhenTextArrives(t *testing.T) {
	c, log := newTestCache(8)
	k := textKey{3, 5}
	c.resolve(k, aggSums{Calls: 2}, noCmd)
	c.endTick(nil)
	c.learn(k, entry("SELECT 2", "query"))
	got := c.endTick(nil)
	if len(got) != 1 || got[0].Digest.Text != "select ?" || got[0].Calls != 2 {
		t.Fatalf("got %+v", got)
	}
	if len(log.forgot) != 0 {
		t.Fatalf("forgot %v although the text arrived", log.forgot)
	}
}

func TestEvictionForgetsInKernel(t *testing.T) {
	c, log := newTestCache(2)
	c.learn(textKey{3, 1}, entry("SELECT 1", "query"))
	c.learn(textKey{3, 2}, entry("SELECT a", "query"))
	c.learn(textKey{3, 3}, entry("SELECT b", "query"))
	if len(log.forgot) != 1 || log.forgot[0] != (textKey{3, 1}) {
		t.Fatalf("forgot %v, want the least recently used key", log.forgot)
	}
}

func TestVerifyMismatchMarksUnsafe(t *testing.T) {
	c, log := newTestCache(8)
	k := textKey{3, 11}
	c.learn(k, entry("SELECT a FROM t", "query"))
	if c.verify(k, entry("SELECT a FROM t", "query")) {
		t.Fatal("same digest reported as mismatch")
	}
	if !c.verify(k, entry("SELECT b FROM t", "query")) {
		t.Fatal("different digest not reported")
	}
	if len(log.unsafe) != 1 || log.unsafe[0] != k || c.mismatches() != 1 {
		t.Fatalf("unsafe = %v, mismatches = %d", log.unsafe, c.mismatches())
	}
}

// A resend that yields the same digest just refreshes the entry.
func TestLearnSameDigestIsNotMismatch(t *testing.T) {
	c, log := newTestCache(8)
	k := textKey{3, 21}
	c.learn(k, entry("SELECT a FROM t WHERE x = 1", "query"))
	c.learn(k, entry("SELECT a FROM t WHERE x = 2", "query"))
	if len(log.unsafe) != 0 || c.mismatches() != 0 {
		t.Fatalf("unsafe = %v, mismatches = %d", log.unsafe, c.mismatches())
	}
}

// A resend whose text yields a different digest for the same kernel hash is
// the same inconsistency verify detects: mark unsafe and count it.
func TestLearnDifferentDigestIsMismatch(t *testing.T) {
	c, log := newTestCache(8)
	k := textKey{3, 22}
	c.learn(k, entry("SELECT a FROM t", "query"))
	c.learn(k, entry("SELECT b FROM t", "query"))
	if len(log.unsafe) != 1 || log.unsafe[0] != k || c.mismatches() != 1 {
		t.Fatalf("unsafe = %v, mismatches = %d", log.unsafe, c.mismatches())
	}
	d, ok := c.resolve(k, aggSums{Calls: 1}, noCmd)
	if !ok || d.Digest.Text != "select b from t" {
		t.Fatalf("got %+v, %v; want the latest text", d, ok)
	}
}

// flagMismatch is the hook the analyzer's kernel-hash drift check uses.
func TestFlagMismatch(t *testing.T) {
	c, log := newTestCache(8)
	c.flagMismatch(textKey{22, 5})
	if len(log.unsafe) != 1 || log.unsafe[0] != (textKey{22, 5}) || c.mismatches() != 1 {
		t.Fatalf("unsafe = %v, mismatches = %d", log.unsafe, c.mismatches())
	}
}

// Many hashes map to one digest: the digest text, id and sample are stored
// once and shared, and released when the last hash referencing them goes.
func TestDigestsAreInterned(t *testing.T) {
	c, _ := newTestCache(2)
	c.learn(textKey{3, 1}, entry("SELECT * FROM t WHERE id = 1", "query"))
	c.learn(textKey{3, 2}, entry("SELECT * FROM t WHERE id =   2", "query"))
	d1, _ := c.resolve(textKey{3, 1}, aggSums{Calls: 1}, noCmd)
	d2, _ := c.resolve(textKey{3, 2}, aggSums{Calls: 1}, noCmd)
	if d1.Digest.ID != d2.Digest.ID {
		t.Fatalf("test texts must share a digest: %q vs %q", d1.Digest.Text, d2.Digest.Text)
	}
	if unsafe.StringData(d1.Digest.Text) != unsafe.StringData(d2.Digest.Text) {
		t.Error("digest text is not shared between hashes of one digest")
	}
	if d2.SampleQuery != "SELECT * FROM t WHERE id = 1" {
		t.Errorf("sample = %q, want the digest's first sample", d2.SampleQuery)
	}
	if len(c.digests) != 1 {
		t.Fatalf("%d digest records, want 1", len(c.digests))
	}
	// Two other digests evict both hashes: the shared record is released.
	c.learn(textKey{3, 3}, entry("SELECT a FROM u", "query"))
	c.learn(textKey{3, 4}, entry("SELECT b FROM u", "query"))
	if _, ok := c.digests[d1.Digest.ID]; ok || len(c.digests) != 2 {
		t.Fatalf("digest records = %d (released: %v)", len(c.digests), !ok)
	}
	// Overwriting a hash with another digest releases the old record too.
	c.learn(textKey{3, 4}, entry("SELECT a FROM u", "query"))
	if len(c.digests) != 1 {
		t.Fatalf("digest records after overwrite = %d, want 1", len(c.digests))
	}
}
