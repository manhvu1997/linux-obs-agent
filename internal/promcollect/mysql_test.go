package promcollect

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func snap(text string) *querystats.Snapshot {
	return &querystats.Snapshot{
		Commands: map[string]model.QueryCounters{"query": {Calls: 2, CPUNs: 1_500_000_000, RunqNs: 500_000_000, WallNs: 3_000_000_000, BytesOut: 9000}},
		Exported: []querystats.ExportedDigest{{ID: "aaa", Text: text, Counters: model.QueryCounters{Calls: 2, CPUNs: 1_500_000_000, BytesOut: 9000}}},
	}
}

func TestMySQLCollector(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap("select * from t") }, MySQLHealth{Dropped: func() uint64 { return 7 }}, config.DigestsFull, 20)
	want := `
# HELP obs_agent_mysql_digest_cpu_seconds_total On-CPU seconds spent executing statements of this digest.
# TYPE obs_agent_mysql_digest_cpu_seconds_total counter
obs_agent_mysql_digest_cpu_seconds_total{digest_id="aaa"} 1.5
# HELP obs_agent_mysql_events_dropped_total Commands lost before reaching the digest aggregator (fallback ring buffer full or consumer behind); digest totals undercount when this rises. Text events are counted separately.
# TYPE obs_agent_mysql_events_dropped_total counter
obs_agent_mysql_events_dropped_total 7
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_digest_cpu_seconds_total", "obs_agent_mysql_events_dropped_total"); err != nil {
		t.Fatal(err)
	}
}

// Result bytes are only sent bytes: no flow="in" series (bytes_in is gone).
func TestMySQLQueryBytesOutOnly(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap("select * from t") }, MySQLHealth{}, config.DigestsFull, 20)
	flows := gatherOne(t, c, "obs_agent_mysql_query_bytes_total", "flow")
	if len(flows) != 1 || flows[0] != "out" {
		t.Fatalf("obs_agent_mysql_query_bytes_total flows = %v, want [out]", flows)
	}
}

func TestMySQLCollectorNilSnapshot(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return nil }, MySQLHealth{}, config.DigestsFull, 20)
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_queries_total"); n != 0 {
		t.Fatalf("got %d series before any snapshot", n)
	}
}

// gatherOne gathers c through a pedantic registry (a failure there is what
// breaks a real /metrics scrape) and returns the values of label on every
// series of metric name.
func gatherOne(t *testing.T, c prometheus.Collector, name, label string) []string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed — one bad label must not break /metrics: %v", err)
	}
	var vals []string
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == label {
					vals = append(vals, lp.GetValue())
				}
			}
		}
	}
	return vals
}

func TestMySQLCollectorInvalidUTF8Label(t *testing.T) {
	cases := map[string]string{
		// invalid byte well inside the 120-byte label budget
		"early": "selec\xfft * from t where id = ?" + strings.Repeat(" and x = ?", 30),
		// a 3-byte rune cut after 2 bytes, straddling the 120-byte boundary
		"cut-boundary": strings.Repeat("a", 119) + "\xe1\xbb" + strings.Repeat("z", 50),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			c := NewMySQLCollector(func() *querystats.Snapshot { return snap(text) }, MySQLHealth{}, config.DigestsFull, 20)
			vals := gatherOne(t, c, "obs_agent_mysql_digest_info", "digest_text")
			if len(vals) != 1 {
				t.Fatalf("digest_info series = %d, want exactly 1", len(vals))
			}
			if v := vals[0]; !utf8.ValidString(v) || len(v) > 120 {
				t.Fatalf("digest_text label invalid or too long (%d bytes): %q", len(v), v)
			}
		})
	}
}

// A label value that is not valid UTF-8 makes NewConstMetric fail; emit must
// skip that series instead of panicking (a panic inside Registry.Gather's
// collector goroutine kills the agent).
func TestEmitSkipsInvalidSeries(t *testing.T) {
	ch := make(chan prometheus.Metric, 1)
	emit(ch, myDigestInfoDesc, prometheus.GaugeValue, 1, "id", "bad\xff")
	if len(ch) != 0 {
		t.Fatal("invalid series must be skipped")
	}
	emit(ch, myDigestInfoDesc, prometheus.GaugeValue, 1, "id", "good")
	if len(ch) != 1 {
		t.Fatal("valid series must be emitted")
	}
}

func TestSanitizeLabel(t *testing.T) {
	if got := SanitizeLabel("abcdef", 4); got != "abcd" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeLabel("ễễ", 4); got != "ễ" { // 3-byte rune; never split it
		t.Fatalf("got %q", got)
	}
	for _, tc := range []struct {
		in   string
		max  int
		want string
	}{
		{"ab\xffcd", 10, "ab?cd"},
		{"\xff\xfe", 10, "?"},       // a run of invalid bytes becomes one "?"
		{"abc\xe1\xbb", 10, "abc?"}, // truncated multi-byte rune at the end
		{"abc\xe1\xbbz", 4, "abc?"}, // ... cut at the boundary
	} {
		got := SanitizeLabel(tc.in, tc.max)
		if got != tc.want || !utf8.ValidString(got) || len(got) > tc.max {
			t.Fatalf("SanitizeLabel(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

func modeSnap() *querystats.Snapshot {
	return &querystats.Snapshot{
		QueryCPUMsTotal: 1000, // 1 s of query CPU in the window
		Commands:        map[string]model.QueryCounters{"query": {Calls: 100, CPUNs: 10_000_000_000, DiskReadBytes: 1000}},
		Exported: []querystats.ExportedDigest{
			{ID: "aaa", Text: "select a", Counters: model.QueryCounters{Calls: 10, CPUNs: 6_000_000_000, BytesOut: 5, DiskReadBytes: 300, IOWaitNs: 2_000_000_000}, WindowCPUNs: 600_000_000},
			{ID: "bbb", Text: "select b", Counters: model.QueryCounters{Calls: 20, CPUNs: 3_000_000_000}, WindowCPUNs: 300_000_000},
			{ID: "ccc", Text: "select c", Counters: model.QueryCounters{Calls: 30, CPUNs: 500_000_000}, WindowCPUNs: 50_000_000},
		},
	}
}

func TestMySQLCollectorMinimal(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return modeSnap() }, MySQLHealth{}, config.DigestsMinimal, 2)
	want := `
# HELP obs_agent_mysql_digest_cpu_seconds_total On-CPU seconds spent executing statements of this digest.
# TYPE obs_agent_mysql_digest_cpu_seconds_total counter
obs_agent_mysql_digest_cpu_seconds_total{digest_id="aaa"} 6
obs_agent_mysql_digest_cpu_seconds_total{digest_id="bbb"} 3
obs_agent_mysql_digest_cpu_seconds_total{digest_id="other"} 1
# HELP obs_agent_mysql_digest_calls_total Executions of statements of this digest.
# TYPE obs_agent_mysql_digest_calls_total counter
obs_agent_mysql_digest_calls_total{digest_id="aaa"} 10
obs_agent_mysql_digest_calls_total{digest_id="bbb"} 20
obs_agent_mysql_digest_calls_total{digest_id="other"} 70
# HELP obs_agent_mysql_digest_disk_read_bytes_total Bytes statements of this digest caused to be read from storage.
# TYPE obs_agent_mysql_digest_disk_read_bytes_total counter
obs_agent_mysql_digest_disk_read_bytes_total{digest_id="aaa"} 300
obs_agent_mysql_digest_disk_read_bytes_total{digest_id="bbb"} 0
obs_agent_mysql_digest_disk_read_bytes_total{digest_id="other"} 700
# HELP obs_agent_mysql_digest_coverage_ratio Share (0-1) of the window's query CPU explained by the per-digest series exported in the current mode.
# TYPE obs_agent_mysql_digest_coverage_ratio gauge
obs_agent_mysql_digest_coverage_ratio 0.9
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_digest_cpu_seconds_total", "obs_agent_mysql_digest_calls_total",
		"obs_agent_mysql_digest_disk_read_bytes_total", "obs_agent_mysql_digest_coverage_ratio"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"obs_agent_mysql_digest_bytes_out_total", "obs_agent_mysql_digest_runq_wait_seconds_total",
		"obs_agent_mysql_digest_io_wait_seconds_total"} {
		if n := testutil.CollectAndCount(c, name); n != 0 {
			t.Errorf("%s has %d series in minimal mode, want 0", name, n)
		}
	}
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_digest_info"); n != 2 {
		t.Errorf("digest_info series = %d, want 2 (no info for other)", n)
	}
}

func TestMySQLCollectorOff(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return modeSnap() }, MySQLHealth{}, config.DigestsOff, 20)
	for _, name := range []string{"obs_agent_mysql_digest_cpu_seconds_total", "obs_agent_mysql_digest_info"} {
		if n := testutil.CollectAndCount(c, name); n != 0 {
			t.Errorf("%s has %d series in off mode", name, n)
		}
	}
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_queries_total"); n != 1 {
		t.Errorf("per-command metrics must stay in off mode")
	}
	assertCoverage(t, c, "0")
}

func TestMySQLCollectorFullCoverage(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return modeSnap() }, MySQLHealth{}, config.DigestsFull, 20)
	assertCoverage(t, c, "0.95")
	idle := func() *querystats.Snapshot { s := modeSnap(); s.QueryCPUMsTotal = 0; return s }
	assertCoverage(t, NewMySQLCollector(idle, MySQLHealth{}, config.DigestsFull, 20), "1")
}

// Full mode: every sticky digest gets disk_read; io_wait only while block-I/O
// wait is measured over the whole window (never a misleading 0).
func TestMySQLCollectorFullDiskSeries(t *testing.T) {
	measured := func() *querystats.Snapshot {
		s := modeSnap()
		s.Accounting = map[string]string{querystats.AccountingKeyDiskWait: querystats.AccountingOK}
		return s
	}
	c := NewMySQLCollector(measured, MySQLHealth{}, config.DigestsFull, 20)
	want := `
# HELP obs_agent_mysql_digest_io_wait_seconds_total Seconds statements of this digest waited for block I/O (full mode).
# TYPE obs_agent_mysql_digest_io_wait_seconds_total counter
obs_agent_mysql_digest_io_wait_seconds_total{digest_id="aaa"} 2
obs_agent_mysql_digest_io_wait_seconds_total{digest_id="bbb"} 0
obs_agent_mysql_digest_io_wait_seconds_total{digest_id="ccc"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_mysql_digest_io_wait_seconds_total"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_digest_disk_read_bytes_total"); n != 3 {
		t.Fatalf("digest disk read series = %d, want 3 (no other in full)", n)
	}
	unmeasured := NewMySQLCollector(func() *querystats.Snapshot { return modeSnap() }, MySQLHealth{}, config.DigestsFull, 20)
	if n := testutil.CollectAndCount(unmeasured, "obs_agent_mysql_digest_io_wait_seconds_total"); n != 0 {
		t.Fatalf("digest io wait series = %d while not measured, want 0", n)
	}
	if n := testutil.CollectAndCount(unmeasured, "obs_agent_mysql_digest_disk_read_bytes_total"); n != 3 {
		t.Fatalf("digest disk read series = %d, want 3", n)
	}
}

func TestCommandDiskAndWaitSeries(t *testing.T) {
	s := &querystats.Snapshot{
		Commands:   map[string]model.QueryCounters{"query": {Calls: 1, DiskReadBytes: 4096, DiskWriteBytes: 512, IOWaitNs: 2e9, RedoWaitNs: 1e9}},
		Accounting: map[string]string{querystats.AccountingKeyDiskWait: querystats.AccountingOK, querystats.AccountingKeyCommitWait: querystats.AccountingOK},
	}
	c := NewMySQLCollector(func() *querystats.Snapshot { return s }, MySQLHealth{}, config.DigestsOff, 20)
	want := `
# HELP obs_agent_mysql_query_disk_read_bytes_total Bytes MySQL statements caused to be read from storage (task I/O accounting), by command class.
# TYPE obs_agent_mysql_query_disk_read_bytes_total counter
obs_agent_mysql_query_disk_read_bytes_total{command="query"} 4096
# HELP obs_agent_mysql_query_io_wait_seconds_total Seconds MySQL statements waited for block I/O (kernel delay accounting), by command class. Absent while not measured.
# TYPE obs_agent_mysql_query_io_wait_seconds_total counter
obs_agent_mysql_query_io_wait_seconds_total{command="query"} 2
# HELP obs_agent_mysql_io_wait_available 1 when per-statement block-I/O wait is measured over the whole digest window (delay accounting on), else 0.
# TYPE obs_agent_mysql_io_wait_available gauge
obs_agent_mysql_io_wait_available 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_query_disk_read_bytes_total", "obs_agent_mysql_query_io_wait_seconds_total", "obs_agent_mysql_io_wait_available"); err != nil {
		t.Fatal(err)
	}
	want = `
# HELP obs_agent_mysql_query_disk_write_bytes_total Bytes MySQL statements caused to be written (dirtied or O_DIRECT), by command class.
# TYPE obs_agent_mysql_query_disk_write_bytes_total counter
obs_agent_mysql_query_disk_write_bytes_total{command="query"} 512
# HELP obs_agent_mysql_query_redo_wait_seconds_total Seconds MySQL statements waited for the redo log inside log_write_up_to (commit wait), by command class. Absent while not measured.
# TYPE obs_agent_mysql_query_redo_wait_seconds_total counter
obs_agent_mysql_query_redo_wait_seconds_total{command="query"} 1
# HELP obs_agent_mysql_redo_wait_available 1 when per-statement commit wait is measured over the whole digest window, else 0.
# TYPE obs_agent_mysql_redo_wait_available gauge
obs_agent_mysql_redo_wait_available 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_query_disk_write_bytes_total", "obs_agent_mysql_query_redo_wait_seconds_total", "obs_agent_mysql_redo_wait_available"); err != nil {
		t.Fatal(err)
	}
}

func TestWaitCountersOnlyWhenMeasured(t *testing.T) {
	s := &querystats.Snapshot{
		Commands:   map[string]model.QueryCounters{"query": {Calls: 1, IOWaitNs: 2e9, RedoWaitNs: 1e9}},
		Accounting: map[string]string{querystats.AccountingKeyDiskWait: "delayacct_disabled", querystats.AccountingKeyCommitWait: querystats.AccountingOK},
	}
	c := NewMySQLCollector(func() *querystats.Snapshot { return s }, MySQLHealth{}, config.DigestsOff, 20)
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_query_io_wait_seconds_total"); n != 0 {
		t.Fatalf("io wait series = %d, want none while not measured", n)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_query_redo_wait_seconds_total"); n != 1 {
		t.Fatalf("redo wait series = %d", n)
	}
	if v := testutil.ToFloat64(gaugeOf(t, c, "obs_agent_mysql_io_wait_available")); v != 0 {
		t.Fatalf("io_wait_available = %v", v)
	}
	if v := testutil.ToFloat64(gaugeOf(t, c, "obs_agent_mysql_redo_wait_available")); v != 1 {
		t.Fatalf("redo_wait_available = %v", v)
	}
}

func TestMinimalExportsTopDiskReaders(t *testing.T) {
	exp := []querystats.ExportedDigest{
		{ID: "cpu", Text: "select a", Counters: model.QueryCounters{Calls: 1, CPUNs: 9e9}},
		{ID: "disk", Text: "select * from big", Counters: model.QueryCounters{Calls: 1, CPUNs: 1, DiskReadBytes: 1 << 30}},
		{ID: "neither", Text: "select 1", Counters: model.QueryCounters{Calls: 1, CPUNs: 2}},
	}
	s := &querystats.Snapshot{Exported: exp, Commands: map[string]model.QueryCounters{"query": {Calls: 3, CPUNs: 9e9 + 3, DiskReadBytes: 1 << 30}}}
	c := NewMySQLCollector(func() *querystats.Snapshot { return s }, MySQLHealth{}, config.DigestsMinimal, 1)
	// top 1 by CPU ("cpu") ∪ top 1 by disk read ("disk"), plus "other".
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_digest_disk_read_bytes_total"); n != 3 {
		t.Fatalf("digest disk read series = %d, want cpu, disk and other", n)
	}
	ids := gatherOne(t, c, "obs_agent_mysql_digest_info", "digest_id")
	if strings.Join(ids, ",") != "cpu,disk" {
		t.Fatalf("exported digests = %v, want [cpu disk]", ids)
	}
}

// With no digest reading from disk, the disk ranking adds nothing: minimal
// stays the top n by CPU (no arbitrary zero-read digests fill the slots).
func TestMinimalNoDiskReadersAddsNothing(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot {
		s := modeSnap()
		for i := range s.Exported {
			s.Exported[i].Counters.DiskReadBytes = 0
		}
		s.Exported[2].Counters.CPUNs = 9_000_000_000 // ccc tops CPU; aaa sorts first by ID
		return s
	}, MySQLHealth{}, config.DigestsMinimal, 1)
	ids := gatherOne(t, c, "obs_agent_mysql_digest_info", "digest_id")
	if strings.Join(ids, ",") != "ccc" {
		t.Fatalf("exported digests = %v, want [ccc]", ids)
	}
}

func TestQueryCPUCoverageRatio(t *testing.T) {
	v := 58.0
	s := &querystats.Snapshot{QueryCPUCoveragePercent: &v}
	c := NewMySQLCollector(func() *querystats.Snapshot { return s }, MySQLHealth{}, config.DigestsOff, 20)
	if got := testutil.ToFloat64(gaugeOf(t, c, "obs_agent_mysql_query_cpu_coverage_ratio")); got != 0.58 {
		t.Fatalf("coverage = %v", got)
	}
	s.QueryCPUCoveragePercent = nil
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_query_cpu_coverage_ratio"); n != 0 {
		t.Fatal("unknown coverage must not be exported")
	}
}

// gaugeOf collects the single sample of name from c as a collector usable by testutil.ToFloat64.
func gaugeOf(t *testing.T, c prometheus.Collector, name string) prometheus.Collector {
	t.Helper()
	return collectorFunc(func(ch chan<- prometheus.Metric) {
		mc := make(chan prometheus.Metric, 64)
		c.Collect(mc)
		close(mc)
		for m := range mc {
			if strings.Contains(m.Desc().String(), `"`+name+`"`) {
				ch <- m
			}
		}
	})
}

type collectorFunc func(chan<- prometheus.Metric)

func (f collectorFunc) Describe(ch chan<- *prometheus.Desc) { prometheus.DescribeByCollect(f, ch) }
func (f collectorFunc) Collect(ch chan<- prometheus.Metric) { f(ch) }

func assertCoverage(t *testing.T, c prometheus.Collector, want string) {
	t.Helper()
	exp := `
# HELP obs_agent_mysql_digest_coverage_ratio Share (0-1) of the window's query CPU explained by the per-digest series exported in the current mode.
# TYPE obs_agent_mysql_digest_coverage_ratio gauge
obs_agent_mysql_digest_coverage_ratio ` + want + "\n"
	if err := testutil.CollectAndCompare(c, strings.NewReader(exp), "obs_agent_mysql_digest_coverage_ratio"); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLCollectorHealthCounters(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap("select 1") }, MySQLHealth{
		Dropped:        func() uint64 { return 1 },
		TextDropped:    func() uint64 { return 3 },
		AggOverflow:    func() uint64 { return 7 },
		HashMismatches: func() uint64 { return 2 },
	}, "full", 20)
	want := `
# HELP obs_agent_mysql_events_dropped_total Commands lost before reaching the digest aggregator (fallback ring buffer full or consumer behind); digest totals undercount when this rises. Text events are counted separately.
# TYPE obs_agent_mysql_events_dropped_total counter
obs_agent_mysql_events_dropped_total 1
# HELP obs_agent_mysql_text_events_dropped_total Statement text events dropped because the consumer was behind; first-sight texts are re-requested from the kernel (no command is lost; until the resend the hash's commands may show under a text-unavailable placeholder).
# TYPE obs_agent_mysql_text_events_dropped_total counter
obs_agent_mysql_text_events_dropped_total 3
# HELP obs_agent_mysql_agg_overflow_total Commands that bypassed in-kernel aggregation because the map was full (processed as full events; totals stay exact).
# TYPE obs_agent_mysql_agg_overflow_total counter
obs_agent_mysql_agg_overflow_total 7
# HELP obs_agent_mysql_hash_mismatch_total Kernel text hashes found inconsistent: a verification sample or resend whose digest differed from the cached one, or a first-sight text whose kernel hash differed from the Go reference; the hash is switched to exact per-event processing.
# TYPE obs_agent_mysql_hash_mismatch_total counter
obs_agent_mysql_hash_mismatch_total 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_events_dropped_total", "obs_agent_mysql_text_events_dropped_total",
		"obs_agent_mysql_agg_overflow_total", "obs_agent_mysql_hash_mismatch_total"); err != nil {
		t.Fatal(err)
	}
}
