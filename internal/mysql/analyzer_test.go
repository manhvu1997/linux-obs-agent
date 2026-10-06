package mysql

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func TestSampleQueriesOptOut(t *testing.T) {
	ev := mysqlq.CmdEvent{PID: 1, Command: cmdmap.ComQuery, Query: "CREATE USER u IDENTIFIED BY 'secret'", QueryLen: 36}
	for _, keep := range []bool{true, false} {
		cfg := config.Defaults().MySQL
		cfg.SampleQueries = keep
		a := NewAnalyzer(&cfg, nil)
		e := a.toEvent(ev, time.Unix(0, 0), true)
		if keep && e.SampleQuery == "" {
			t.Fatal("sample_queries=true: SampleQuery must be kept")
		}
		if !keep && e.SampleQuery != "" {
			t.Fatalf("sample_queries=false: SampleQuery = %q, want empty", e.SampleQuery)
		}
		if e.Digest.ID == "" {
			t.Fatal("digest must be computed regardless of sample_queries")
		}
	}
}

func TestSampleQueriesOptOutPreparedText(t *testing.T) {
	cfg := config.Defaults().MySQL
	cfg.SampleQueries = false
	a := NewAnalyzer(&cfg, nil)
	q := "SELECT c FROM sbtest1 WHERE id = ?"
	e := a.toEvent(mysqlq.CmdEvent{Command: cmdmap.ComStmtExecute, Query: q, QueryLen: uint32(len(q))}, time.Unix(0, 0), true)
	if e.SampleQuery != "" || e.Command != "stmt_execute" || e.Digest.Text != "select c from sbtest1 where id = ?" {
		t.Fatalf("got %+v", e)
	}
}

func TestFoldSystemSchemas(t *testing.T) {
	q := "SELECT * FROM performance_schema.events_statements_summary_by_digest WHERE schema_name = 'x'"
	ev := mysqlq.CmdEvent{Command: cmdmap.ComQuery, Query: q, QueryLen: uint32(len(q))}
	const folded = "<system schemas: information_schema, performance_schema, sys, mysql>"

	cfg := config.Defaults().MySQL
	cfg.FoldSystemSchemas = true
	e := NewAnalyzer(&cfg, nil).toEvent(ev, time.Unix(0, 0), true)
	if e.Digest.Text != folded || e.Digest.ID != sqldigest.HashID(folded) || e.SampleQuery != "" || e.Command != "query" {
		t.Fatalf("fold on: %+v", e)
	}

	// A prepared execute against a system schema folds too; class unchanged.
	ex := mysqlq.CmdEvent{Command: cmdmap.ComStmtExecute, Query: "SELECT * FROM sys.statement_analysis", QueryLen: 36}
	e = NewAnalyzer(&cfg, nil).toEvent(ex, time.Unix(0, 0), true)
	if e.Digest.Text != folded || e.Command != "stmt_execute" {
		t.Fatalf("fold on (execute): %+v", e)
	}

	// Ordinary application queries are never folded.
	app := mysqlq.CmdEvent{Command: cmdmap.ComQuery, Query: "SELECT mysql_version FROM t", QueryLen: 27}
	if e = NewAnalyzer(&cfg, nil).toEvent(app, time.Unix(0, 0), true); e.Digest.Text == folded {
		t.Fatalf("application query folded: %+v", e)
	}

	cfg.FoldSystemSchemas = false
	e = NewAnalyzer(&cfg, nil).toEvent(ev, time.Unix(0, 0), true)
	if e.Digest.Text == folded || e.SampleQuery != q {
		t.Fatalf("fold off: %+v", e)
	}
}

func TestPreparedTrackingFlagPropagates(t *testing.T) {
	cfg := config.Defaults().MySQL
	a := NewAnalyzer(&cfg, nil)
	ev := mysqlq.CmdEvent{Command: cmdmap.ComStmtExecute}
	on := a.toEvent(ev, time.Unix(0, 0), true)
	off := a.toEvent(ev, time.Unix(0, 0), false)
	if on.Digest.Text != "<COM_STMT_EXECUTE: prepared before agent start, text unavailable>" ||
		off.Digest.Text != "<COM_STMT_EXECUTE: prepared, text unavailable>" {
		t.Fatalf("on=%q off=%q", on.Digest.Text, off.Digest.Text)
	}
}
