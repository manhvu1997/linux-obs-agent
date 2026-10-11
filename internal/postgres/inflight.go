package postgres

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// procCounters are a thread's cumulative counters, in the units the kernel
// session baselines use (ns, bytes).
type procCounters struct{ CPU, Runq, Read, Write, Blkio uint64 }

func (a procCounters) sub(b procCounters) procCounters {
	s := func(x, y uint64) uint64 {
		if x > y {
			return x - y
		}
		return 0
	}
	return procCounters{s(a.CPU, b.CPU), s(a.Runq, b.Runq), s(a.Read, b.Read), s(a.Write, b.Write), s(a.Blkio, b.Blkio)}
}

func (a procCounters) zero() bool { return a == procCounters{} }

type aggKey struct {
	Postmaster, Kind uint32
	Hash             uint64
}

type sessKey struct {
	TID    uint32
	OpenTS uint64
}

type creditedSess struct {
	key   aggKey
	total procCounters
}

type owed struct {
	c   procCounters
	age int
}

// credit is progress of a still-open interval, attributed now.
type credit struct {
	aggKey
	procCounters
}

// creditor credits long intervals while they run and subtracts what it
// credited once their full sums arrive through the aggregation map, so
// window sums stay exact and a running culprit is visible after one poll.
type creditor struct {
	mu       sync.Mutex // Credit/Settle run on the poll goroutine, SettleCmd on the consumer
	readProc func(tid uint32) (procCounters, error)
	minAgeNs uint64
	credited map[sessKey]*creditedSess
	owed     map[aggKey]*owed
	tomb     map[sessKey]bool // sessions settled by SettleCmd; a stale session list must not re-credit them
	dropped  uint64           // owed amounts never matched (counted, then forgotten)
}

func newCreditor(minAgeNs uint64, read func(uint32) (procCounters, error)) *creditor {
	return &creditor{readProc: read, minAgeNs: minAgeNs, credited: map[sessKey]*creditedSess{}, owed: map[aggKey]*owed{}, tomb: map[sessKey]bool{}}
}

// Credit returns the progress of every interval open longer than minAge whose
// text is known (known(hash); hash 0 is always known), and moves the credit
// of intervals that closed since the last call to the owed ledger.
func (c *creditor) Credit(sessions []pgtrace.Session, nowMono uint64, known func(uint64) bool) []credit {
	c.mu.Lock()
	defer c.mu.Unlock()
	open := make(map[sessKey]bool, len(sessions))
	var out []credit
	for _, s := range sessions {
		k := sessKey{s.TID, s.OpenTS}
		open[k] = true
		if c.tomb[k] {
			continue
		}
		if nowMono < s.OpenTS || nowMono-s.OpenTS < c.minAgeNs || (s.Hash != 0 && !known(s.Hash)) {
			continue
		}
		cur, err := c.readProc(s.TID)
		if err != nil {
			continue
		}
		total := cur.sub(procCounters{s.CPU, s.Runq, s.ReadBytes, s.WriteBytes, s.Blkio})
		cs := c.credited[k]
		if cs == nil {
			cs = &creditedSess{key: aggKey{s.Postmaster, s.Kind, s.Hash}}
			c.credited[k] = cs
		}
		inc := total.sub(cs.total)
		if !inc.zero() {
			out = append(out, credit{cs.key, inc})
			cs.total = procCounters{max(cs.total.CPU, total.CPU), max(cs.total.Runq, total.Runq),
				max(cs.total.Read, total.Read), max(cs.total.Write, total.Write), max(cs.total.Blkio, total.Blkio)}
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
		o.c = procCounters{o.c.CPU + cs.total.CPU, o.c.Runq + cs.total.Runq, o.c.Read + cs.total.Read,
			o.c.Write + cs.total.Write, o.c.Blkio + cs.total.Blkio}
		delete(c.credited, k)
	}
	return out
}

// Settle subtracts owed credit from the drained entries (in place) and ages
// what is still owed: an amount unmatched after two more drains is dropped
// and counted.
func (c *creditor) Settle(entries []pgtrace.AggEntry) []pgtrace.AggEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	take := func(v *uint64, o *uint64) {
		n := min(*v, *o)
		*v -= n
		*o -= n
	}
	for i := range entries {
		e := &entries[i]
		o := c.owed[aggKey{e.Postmaster, e.Kind, e.Hash}]
		if o == nil {
			continue
		}
		take(&e.CPUNs, &o.c.CPU)
		take(&e.RunqNs, &o.c.Runq)
		take(&e.DiskReadBytes, &o.c.Read)
		take(&e.DiskWriteBytes, &o.c.Write)
		take(&e.IOWaitNs, &o.c.Blkio)
	}
	for k, o := range c.owed {
		if o.c.zero() {
			delete(c.owed, k)
			continue
		}
		if o.age++; o.age > 2 {
			c.dropped++
			delete(c.owed, k)
		}
	}
	return entries
}

// readThread reads a thread's counters: /proc/<tid>/schedstat (on-CPU and
// run-queue ns), /proc/<tid>/io (storage bytes) and /proc/<tid>/stat field 42
// (block-I/O delay in clock ticks of 10 ms).
func readThread(tid uint32) (procCounters, error) {
	var c procCounters
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

// SettleCmd subtracts what was already credited for an interval that closed
// as a command event (unsafe hash or full aggregation map) instead of through
// the aggregation map: the event carries the full sums, so crediting them
// again would double count. The still-open credit of the backend tid is
// consumed first, then the owed ledger (the session was already noticed as
// closed). *cpu, ... are modified in place.
func (c *creditor) SettleCmd(k aggKey, tid uint32, p *procCounters) {
	c.mu.Lock()
	defer c.mu.Unlock()
	take := func(v, o *uint64) {
		n := min(*v, *o)
		*v -= n
		*o -= n
	}
	pay := func(o *procCounters) {
		take(&p.CPU, &o.CPU)
		take(&p.Runq, &o.Runq)
		take(&p.Read, &o.Read)
		take(&p.Write, &o.Write)
		take(&p.Blkio, &o.Blkio)
	}
	for sk, cs := range c.credited {
		if sk.TID == tid && cs.key == k {
			pay(&cs.total)
			delete(c.credited, sk)
			// Limit: a session never credited has no tombstone (the event has no
			// open timestamp), so a stale list can still credit it once.
			c.tomb[sk] = true
			return
		}
	}
	if o := c.owed[k]; o != nil {
		pay(&o.c)
	}
}

// Reset forgets every credit and owed amount (the probes were detached: the
// sessions they describe can no longer close through the kernel map).
func (c *creditor) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credited = map[sessKey]*creditedSess{}
	c.owed = map[aggKey]*owed{}
	c.tomb = map[sessKey]bool{}
}

// Dropped is the number of owed amounts that were never matched.
func (c *creditor) Dropped() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}
