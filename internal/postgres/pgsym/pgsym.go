// Package pgsym decides which postgres functions the pg_query tracer hooks
// and which BackendState values mean "running", from the binary alone.
// Pure (no eBPF; I/O only in ReadELF), so it is tested on any OS against
// fixtures taken from real PGDG builds (testdata/*.syms). A major version
// without a known BackendState layout is refused: a wrong enum value would
// record garbage silently.
package pgsym

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// Hook symbols (all exported in PGDG 16–19, .dynsym).
const (
	SymActivity  = "pgstat_report_activity" // (BackendState state, const char *cmd_str)
	SymPortalRun = "PortalRun"              // (Portal, long count, bool isTopLevel, …)
	SymQueryID   = "pgstat_report_query_id" // (uint64/int64 query_id, bool force)
	SymXLogFlush = "XLogFlush"              // (XLogRecPtr record)
	SymSyncRep   = "SyncRepWaitForLSN"      // (XLogRecPtr lsn, bool commit)
	SymParallel  = "ParallelQueryMain"      // (dsm_segment *seg, shm_toc *toc)
)

var versionRE = regexp.MustCompile(`PostgreSQL ([0-9]+)(?:\.([0-9]+)|(beta[0-9]+|rc[0-9]+|devel))?(?: \([^)\x00]*\))? on [^,\x00]+, compiled by`)

// Version is the server version from the binary's banner.
type Version struct {
	Major, Minor int
	Pre          string // "beta4", "rc1", "devel" or ""
	Full         string // the matched banner
}

func (v Version) String() string {
	if v.Pre != "" {
		return fmt.Sprintf("%d%s", v.Major, v.Pre)
	}
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// ParseVersion finds the "PostgreSQL <ver> … on <host>, compiled by" banner.
func ParseVersion(b []byte) (Version, error) {
	m := versionRE.FindSubmatch(b)
	if m == nil {
		return Version{}, errors.New("no PostgreSQL version banner found")
	}
	v := Version{Full: string(m[0]), Pre: string(m[3])}
	v.Major, _ = strconv.Atoi(string(m[1]))
	if len(m[2]) > 0 {
		v.Minor, _ = strconv.Atoi(string(m[2]))
	}
	return v, nil
}

// States are the BackendState values pgstat_report_activity receives.
type States struct{ Running, Fastpath uint32 }

// StatesFor: PG 16/17 enum UNDEFINED, IDLE, RUNNING, IDLEINTRANSACTION,
// FASTPATH, …; PG 18 inserted STATE_STARTING after UNDEFINED.
func StatesFor(major int) (States, error) {
	switch major {
	case 16, 17:
		return States{Running: 2, Fastpath: 4}, nil
	case 18, 19:
		return States{Running: 3, Fastpath: 5}, nil
	}
	return States{}, fmt.Errorf("PostgreSQL %d is not supported (16–19); add its BackendState layout to pgsym.StatesFor and a fixture", major)
}

// Hooks are the resolved uprobe symbols. Activity and PortalRun are always
// set when Resolve succeeds; optional hooks carry their own error.
type Hooks struct {
	Version                               Version
	States                                States
	Activity, PortalRun                   string
	QueryID, XLogFlush, SyncRep, Parallel string
	QueryIDErr, XLogFlushErr              error
	SyncRepErr, ParallelErr               error
}

// Resolve picks the hooks. Symbols are matched exactly (C names, no mangling).
func Resolve(v Version, symbols []string) (Hooks, error) {
	st, err := StatesFor(v.Major)
	if err != nil {
		return Hooks{}, err
	}
	have := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		have[s] = true
	}
	h := Hooks{Version: v, States: st}
	for _, req := range []struct {
		name string
		dst  *string
	}{{SymActivity, &h.Activity}, {SymPortalRun, &h.PortalRun}} {
		if !have[req.name] {
			return Hooks{}, fmt.Errorf("postgres %s: required symbol %s not found (stripped or unsupported build)", v, req.name)
		}
		*req.dst = req.name
	}
	opt := func(name string, dst *string, errp *error) {
		if have[name] {
			*dst = name
		} else {
			*errp = fmt.Errorf("symbol %s not found", name)
		}
	}
	opt(SymQueryID, &h.QueryID, &h.QueryIDErr)
	opt(SymXLogFlush, &h.XLogFlush, &h.XLogFlushErr)
	opt(SymSyncRep, &h.SyncRep, &h.SyncRepErr)
	opt(SymParallel, &h.Parallel, &h.ParallelErr)
	return h, nil
}

// Summary is the one-line hook status logged at attach. queryID / syncRep say
// whether those optional hooks are wanted (enrichment / sync replication).
func (h Hooks) Summary(queryID, syncRep bool) string {
	state := func(err error, wanted bool) string {
		switch {
		case !wanted:
			return "off"
		case err != nil:
			return "unavailable"
		}
		return "ok"
	}
	return fmt.Sprintf("activity=ok portalrun=ok queryid=%s xlogflush=%s syncrep=%s parallel=%s",
		state(h.QueryIDErr, queryID), state(h.XLogFlushErr, true), state(h.SyncRepErr, syncRep), state(h.ParallelErr, true))
}
