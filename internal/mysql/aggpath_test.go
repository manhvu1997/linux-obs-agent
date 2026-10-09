package mysql

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	mysqlq "github.com/manhvu1997/linux-obs-agent/internal/ebpf/mysql_query"
)

func testAnalyzer() *Analyzer {
	return NewAnalyzer(&config.MySQLConfig{SampleQueries: true, FoldSystemSchemas: true, DigestWindow: time.Minute, TopDigests: 20}, nil)
}

// A drained entry whose text was learned becomes one digest with its sums.
func TestAggEntriesBecomeDigests(t *testing.T) {
	a := testAnalyzer()
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	a.learnText(mysqlq.TextEvent{Command: 3, Hash: 99, Query: "SELECT * FROM t WHERE id = 5", QueryLen: 28}, true)
	now := time.Unix(1_800_000_000, 0)
	a.applyAgg([]mysqlq.AggEntry{{PID: 1, Command: 3, Hash: 99, Calls: 40, CPUNs: 40e6, WallNs: 80e6, WallMaxNs: 3e6, CPUMaxNs: 2e6}}, now, true)
	s := a.agg.Snapshot(now.Add(time.Second))
	if len(s.TopByCPU) != 1 || s.TopByCPU[0].Calls != 40 || s.TopByCPU[0].DigestText != "select * from t where id = ?" {
		t.Fatalf("got %+v", s.TopByCPU)
	}
}

// Review focus 3: commands delivered as fallback events are counted too.
func TestFallbackEventsBecomeDeltas(t *testing.T) {
	a := testAnalyzer()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		a.agg.Add(a.toEvent(mysqlq.CmdEvent{PID: 1, Command: 3, Query: "SELECT 1", QueryLen: 8, WallNs: 1e6, CPUNs: 1e6}, now, true))
	}
	if s := a.agg.Snapshot(now.Add(time.Second)); s.TopByCPU[0].Calls != 3 {
		t.Fatalf("calls = %d", s.TopByCPU[0].Calls)
	}
}

// Prepare texts classify as "prepare: …", execute texts as the query digest.
func TestLearnTextClassifiesByCommand(t *testing.T) {
	a := testAnalyzer()
	a.text = newTextCache(16, textCacheHooks{forget: func(uint32, uint64) {}, markUnsafe: func(uint32, uint64) {}})
	a.learnText(mysqlq.TextEvent{Command: 22, Hash: 5, Query: "SELECT ?", QueryLen: 8}, true)
	a.learnText(mysqlq.TextEvent{Command: 23, Hash: 5, Query: "SELECT ?", QueryLen: 8}, true)
	p, _ := a.text.resolve(textKey{22, 5}, aggSums{Calls: 1}, nil)
	e, _ := a.text.resolve(textKey{23, 5}, aggSums{Calls: 1}, nil)
	if p.Command != "stmt_prepare" || p.Digest.Text != "prepare: select ?" || e.Command != "stmt_execute" || e.Digest.Text != "select ?" {
		t.Fatalf("prepare %+v / execute %+v", p, e)
	}
}
