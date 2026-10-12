// Package inflight credits long statements while they run.
//
// The kernel tracers (MySQL dispatch_command, PostgreSQL activity intervals)
// sum a statement's CPU, run-queue wait, disk bytes and block-I/O wait when
// it ends, so a statement that runs for an hour would land in one poll: its
// share of the node in that poll reads thousands of percent and the hour
// before shows nothing. Every poll, a Creditor reads the /proc counters of
// each thread whose statement has been open longer than a minimum age and
// attributes the progress since the previous poll now; when the statement's
// full sums arrive (an aggregation-map drain, or a command event) it
// subtracts what it credited, so window sums stay exact.
//
// Wall time and calls are never credited: they describe completed statements.
package inflight

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Counters are a thread's cumulative counters, in the units the kernel
// baselines use (ns, bytes).
type Counters struct{ CPU, Runq, Read, Write, Blkio uint64 }

// Sub returns a − b per field, floored at 0.
func (a Counters) Sub(b Counters) Counters {
	s := func(x, y uint64) uint64 {
		if x > y {
			return x - y
		}
		return 0
	}
	return Counters{s(a.CPU, b.CPU), s(a.Runq, b.Runq), s(a.Read, b.Read), s(a.Write, b.Write), s(a.Blkio, b.Blkio)}
}

// Zero reports whether every counter is 0.
func (a Counters) Zero() bool { return a == Counters{} }

func (a Counters) add(b Counters) Counters {
	return Counters{a.CPU + b.CPU, a.Runq + b.Runq, a.Read + b.Read, a.Write + b.Write, a.Blkio + b.Blkio}
}

func maxOf(a, b Counters) Counters {
	return Counters{max(a.CPU, b.CPU), max(a.Runq, b.Runq), max(a.Read, b.Read), max(a.Write, b.Write), max(a.Blkio, b.Blkio)}
}

// take moves min(*v, *o) out of both, per field: the part of an amount that
// was already credited.
func take(v, o *Counters) {
	t := func(x, y *uint64) {
		n := min(*x, *y)
		*x -= n
		*y -= n
	}
	t(&v.CPU, &o.CPU)
	t(&v.Runq, &o.Runq)
	t(&v.Read, &o.Read)
	t(&v.Write, &o.Write)
	t(&v.Blkio, &o.Blkio)
}

// Session is one statement still running on thread TID: the aggregation key
// its full sums will arrive under, when it started (CLOCK_MONOTONIC ns, the
// bpf_ktime_get_ns clock) and the thread's counters at that moment.
type Session[K comparable] struct {
	TID    uint32
	OpenTS uint64
	Key    K
	Base   Counters
}

// Credit is progress of a still-running statement, attributed now.
type Credit[K comparable] struct {
	Key K
	Counters
}

type sessKey struct {
	TID    uint32
	OpenTS uint64
}

type creditedSess[K comparable] struct {
	key   K
	total Counters
}

type owed struct {
	c   Counters
	age int
}

// Creditor credits long statements while they run and subtracts what it
// credited once their full sums arrive, so window sums stay exact and a
// running culprit is visible after one poll.
type Creditor[K comparable] struct {
	mu       sync.Mutex // Credit/Pay/Age run on the poll goroutine, SettleCmd on an event consumer
	read     func(tid uint32) (Counters, error)
	minAgeNs uint64
	credited map[sessKey]*creditedSess[K]
	owed     map[K]*owed
	tomb     map[sessKey]bool // sessions settled by SettleCmd; a stale session list must not re-credit them
	dropped  uint64           // owed amounts never matched (counted, then forgotten)
}

// New returns a Creditor that credits statements open at least minAgeNs,
// reading thread counters with read (ReadThread outside tests).
func New[K comparable](minAgeNs uint64, read func(tid uint32) (Counters, error)) *Creditor[K] {
	return &Creditor[K]{read: read, minAgeNs: minAgeNs, credited: map[sessKey]*creditedSess[K]{},
		owed: map[K]*owed{}, tomb: map[sessKey]bool{}}
}

// Credit returns the progress of every session open longer than minAge whose
// key is known (known(key): its statement text has been classified), and
// moves the credit of sessions that ended since the last call to the owed
// ledger, to be paid by Pay or SettleCmd. sessions must be the complete list
// of running statements: one missing from it is treated as ended.
func (c *Creditor[K]) Credit(sessions []Session[K], nowMono uint64, known func(K) bool) []Credit[K] {
	c.mu.Lock()
	defer c.mu.Unlock()
	open := make(map[sessKey]bool, len(sessions))
	var out []Credit[K]
	for _, s := range sessions {
		k := sessKey{s.TID, s.OpenTS}
		open[k] = true
		if c.tomb[k] {
			continue
		}
		if nowMono < s.OpenTS || nowMono-s.OpenTS < c.minAgeNs || !known(s.Key) {
			continue
		}
		cur, err := c.read(s.TID)
		if err != nil {
			continue
		}
		total := cur.Sub(s.Base)
		cs := c.credited[k]
		if cs == nil {
			cs = &creditedSess[K]{key: s.Key}
			c.credited[k] = cs
		}
		if inc := total.Sub(cs.total); !inc.Zero() {
			out = append(out, Credit[K]{cs.key, inc})
			cs.total = maxOf(cs.total, total)
		}
	}
	for k := range c.tomb {
		if !open[k] {
			delete(c.tomb, k) // gone from a fresh list: no stale list can resurrect it
		}
	}
	for k, cs := range c.credited {
		if open[k] {
			continue
		}
		o := c.owed[cs.key]
		if o == nil {
			o = &owed{}
			c.owed[cs.key] = o
		}
		o.c = o.c.add(cs.total)
		delete(c.credited, k)
	}
	return out
}

// Pay subtracts what is owed for k from p, in place: p holds the full sums of
// statements that ended under k, part of which was already credited. Call it
// once per drained entry, then Age once per drain.
func (c *Creditor[K]) Pay(k K, p *Counters) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if o := c.owed[k]; o != nil {
		take(p, &o.c)
	}
}

// Age ends a drain: an owed amount that no drain matched for two more drains
// is dropped and counted (its statement's sums never arrived, or arrived
// under another key).
func (c *Creditor[K]) Age() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, o := range c.owed {
		if o.c.Zero() {
			delete(c.owed, k)
			continue
		}
		if o.age++; o.age > 2 {
			c.dropped++
			delete(c.owed, k)
		}
	}
}

// SettleCmd subtracts what was already credited for a statement of thread
// tid that ended as a command event (an unsafe hash or a full aggregation
// map) instead of through the aggregation map: the event carries the full
// sums, so crediting them again would double count. The still-open credit of
// tid is consumed first, then the owed ledger (the session was already
// noticed as ended). p is modified in place.
func (c *Creditor[K]) SettleCmd(k K, tid uint32, p *Counters) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for sk, cs := range c.credited {
		if sk.TID == tid && cs.key == k {
			take(p, &cs.total)
			delete(c.credited, sk)
			// Limit: a session never credited has no tombstone (the event has no
			// open timestamp), so a stale list can still credit it once.
			c.tomb[sk] = true
			return
		}
	}
	if o := c.owed[k]; o != nil {
		take(p, &o.c)
	}
}

// Reset forgets every credit and owed amount (the probes were detached: the
// sessions they describe can no longer end through the kernel map).
func (c *Creditor[K]) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credited = map[sessKey]*creditedSess[K]{}
	c.owed = map[K]*owed{}
	c.tomb = map[sessKey]bool{}
}

// Dropped is the number of owed amounts that were never matched.
func (c *Creditor[K]) Dropped() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// Tracked returns how many running sessions carry credit and how many keys
// still owe credit.
func (c *Creditor[K]) Tracked() (credited, owed int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.credited), len(c.owed)
}

// ReadThread reads a thread's counters: /proc/<tid>/schedstat (on-CPU and
// run-queue ns), /proc/<tid>/io (storage bytes) and /proc/<tid>/stat field 42
// (block-I/O delay in clock ticks of 10 ms). A TID is reachable as
// /proc/<tid> although it is not listed there.
func ReadThread(tid uint32) (Counters, error) {
	var c Counters
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/schedstat", tid))
	if err != nil {
		return c, err
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return c, fmt.Errorf("short schedstat")
	}
	c.CPU, _ = strconv.ParseUint(f[0], 10, 64)
	c.Runq, _ = strconv.ParseUint(f[1], 10, 64)
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", tid)); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "read_bytes: "); ok {
				c.Read, _ = strconv.ParseUint(v, 10, 64)
			}
			if v, ok := strings.CutPrefix(sc.Text(), "write_bytes: "); ok {
				c.Write, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", tid)); err == nil {
		if i := bytes.LastIndexByte(b, ')'); i >= 0 {
			if f := bytes.Fields(b[i+1:]); len(f) >= 40 { // f[0] is field 3; field 42 is f[39]
				t, _ := strconv.ParseUint(string(f[39]), 10, 64)
				c.Blkio = t * 10_000_000
			}
		}
	}
	return c, nil
}

// MonoNow returns CLOCK_MONOTONIC in ns, the clock of bpf_ktime_get_ns.
func MonoNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
