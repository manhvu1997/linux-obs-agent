package postgres

import (
	"github.com/manhvu1997/linux-obs-agent/internal/inflight"
	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgtrace"
)

// procCounters are a thread's cumulative counters, in the units the kernel
// session baselines use (ns, bytes).
type procCounters = inflight.Counters

type aggKey struct {
	Postmaster, Kind uint32
	Hash             uint64
}

// credit is progress of a still-open interval, attributed now.
type credit = inflight.Credit[aggKey]

// creditor adapts inflight.Creditor to pg_query's open intervals and
// aggregation entries: long intervals are credited while they run and the
// credit is subtracted once their full sums arrive.
type creditor struct {
	readProc func(tid uint32) (procCounters, error) // read at every Credit, so tests can swap it
	c        *inflight.Creditor[aggKey]
}

func newCreditor(minAgeNs uint64, read func(uint32) (procCounters, error)) *creditor {
	cr := &creditor{readProc: read}
	cr.c = inflight.New[aggKey](minAgeNs, func(tid uint32) (procCounters, error) { return cr.readProc(tid) })
	return cr
}

// Credit returns the progress of every interval open longer than minAge whose
// text is known (known(hash); hash 0 is always known), and moves the credit
// of intervals that closed since the last call to the owed ledger.
func (c *creditor) Credit(sessions []pgtrace.Session, nowMono uint64, known func(uint64) bool) []credit {
	ss := make([]inflight.Session[aggKey], len(sessions))
	for i, s := range sessions {
		ss[i] = inflight.Session[aggKey]{TID: s.TID, OpenTS: s.OpenTS, Key: aggKey{s.Postmaster, s.Kind, s.Hash},
			Base: procCounters{CPU: s.CPU, Runq: s.Runq, Read: s.ReadBytes, Write: s.WriteBytes, Blkio: s.Blkio}}
	}
	return c.c.Credit(ss, nowMono, func(k aggKey) bool { return k.Hash == 0 || known(k.Hash) })
}

// Settle subtracts owed credit from the drained entries (in place) and ages
// what is still owed: an amount unmatched after two more drains is dropped
// and counted.
func (c *creditor) Settle(entries []pgtrace.AggEntry) []pgtrace.AggEntry {
	for i := range entries {
		e := &entries[i]
		p := procCounters{CPU: e.CPUNs, Runq: e.RunqNs, Read: e.DiskReadBytes, Write: e.DiskWriteBytes, Blkio: e.IOWaitNs}
		c.c.Pay(aggKey{e.Postmaster, e.Kind, e.Hash}, &p)
		e.CPUNs, e.RunqNs, e.DiskReadBytes, e.DiskWriteBytes, e.IOWaitNs = p.CPU, p.Runq, p.Read, p.Write, p.Blkio
	}
	c.c.Age()
	return entries
}

// SettleCmd subtracts what was already credited for an interval that closed
// as a command event (unsafe hash or full aggregation map) instead of through
// the aggregation map; p is modified in place.
func (c *creditor) SettleCmd(k aggKey, tid uint32, p *procCounters) { c.c.SettleCmd(k, tid, p) }

// Reset forgets every credit and owed amount (the probes were detached: the
// sessions they describe can no longer close through the kernel map).
func (c *creditor) Reset() { c.c.Reset() }

// Dropped is the number of owed amounts that were never matched.
func (c *creditor) Dropped() uint64 { return c.c.Dropped() }

// readThread reads a backend thread's counters from /proc.
func readThread(tid uint32) (procCounters, error) { return inflight.ReadThread(tid) }
