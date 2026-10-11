package chsink

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

// Verdicts that never trigger a snapshot on their own.
var benignVerdicts = map[string]bool{
	"": true, "healthy": true, "inconclusive": true, "iowait_accounting_artifact": true,
}

// Reason returns the snapshot trigger reason, "" when nothing is interesting:
// "module:<ids sorted, comma-joined>", "io_verdict:<verdict>", or both
// joined by ";".
func Reason(active []string, verdict string) string {
	var parts []string
	if len(active) > 0 {
		a := append([]string(nil), active...)
		sort.Strings(a)
		parts = append(parts, "module:"+strings.Join(a, ","))
	}
	if !benignVerdicts[verdict] {
		parts = append(parts, "io_verdict:"+verdict)
	}
	return strings.Join(parts, ";")
}

// postgresTriggers are the PostgreSQL overload verdicts worth a snapshot.
var postgresTriggers = map[string]bool{"query_cpu_overload": true, "query_disk_overload": true, "background_overload": true}

// reasonKind: module, io_verdict or postgres_verdict; "both" when the reason
// has more than one kind (the label set stays small).
func reasonKind(r string) string {
	var kinds []string
	for _, k := range []string{"module", "io_verdict", "postgres_verdict"} {
		if strings.Contains(r, k+":") {
			kinds = append(kinds, k)
		}
	}
	switch len(kinds) {
	case 0:
		return "io_verdict"
	case 1:
		return kinds[0]
	}
	return "both"
}

// StripPostgres removes raw SQL from postgres_report unless include is true
// (clickhouse.include_sample_queries AND postgres.sample_queries). It copies:
// the report is the analyzer's shared snapshot.
func StripPostgres(r model.DiagnoseReport, include bool) model.DiagnoseReport {
	if include || r.PostgresReport == nil {
		return r
	}
	cp := *r.PostgresReport
	cp.Clusters = make([]model.PostgresCluster, len(r.PostgresReport.Clusters))
	for i, c := range r.PostgresReport.Clusters {
		c.TopDigests = pgWithoutSamples(c.TopDigests)
		c.TopDigestsByDiskRead = pgWithoutSamples(c.TopDigestsByDiskRead)
		c.TopDigestsByWait = pgWithoutSamples(c.TopDigestsByWait)
		if len(c.RecentSlowQueries) > 0 {
			slow := make([]model.PGSlowQuery, len(c.RecentSlowQueries))
			copy(slow, c.RecentSlowQueries)
			for j := range slow {
				slow[j].SampleQuery = ""
			}
			c.RecentSlowQueries = slow
		}
		cp.Clusters[i] = c
	}
	r.PostgresReport = &cp
	return r
}

func pgWithoutSamples(in []model.PGDigestStats) []model.PGDigestStats {
	if len(in) == 0 {
		return in
	}
	out := make([]model.PGDigestStats, len(in))
	copy(out, in)
	for i := range out {
		out[i].SampleQuery = ""
	}
	return out
}

// StripSensitive removes raw SQL literals from the MySQL section unless
// include is true. It copies before editing: r.MySQLReport is the analyzer's
// shared snapshot, also served by /api/diagnose.
func StripSensitive(r model.DiagnoseReport, include bool) model.DiagnoseReport {
	if include || r.MySQLReport == nil {
		return r
	}
	cp := *r.MySQLReport
	cp.TopDigests = withoutSamples(cp.TopDigests)
	cp.TopDigestsByBytesOut = withoutSamples(cp.TopDigestsByBytesOut)
	cp.TopDigestsByWait = withoutSamples(cp.TopDigestsByWait)
	cp.TopDigestsByDiskRead = withoutSamples(cp.TopDigestsByDiskRead)
	if len(cp.RecentSlowQueries) > 0 {
		slow := make([]model.MySQLSlowEvent, len(cp.RecentSlowQueries))
		copy(slow, cp.RecentSlowQueries)
		for i := range slow {
			slow[i].Query = sqldigest.Normalize(slow[i].Query).Text
		}
		cp.RecentSlowQueries = slow
	}
	r.MySQLReport = &cp
	return r
}

func withoutSamples(in []model.QueryDigestStats) []model.QueryDigestStats {
	if len(in) == 0 {
		return in
	}
	out := make([]model.QueryDigestStats, len(in))
	copy(out, in)
	for i := range out {
		out[i].SampleQuery = ""
	}
	return out
}

// Snapshotter captures the full diagnose report into diagnose_snapshots when
// an eBPF module is active or the I/O verdict is bad, at most once per
// MinInterval unless the reason changes.
type Snapshotter struct {
	cfg        *config.ClickHouseConfig
	host       string
	sink       *Sink
	state      func() ([]string, string)
	build      func() model.DiagnoseReport
	lastAt     time.Time
	lastReason string

	pgVerdict func() string // nil: PostgreSQL off
	pgInclude bool
}

// SetPostgres adds the PostgreSQL overload verdict to the trigger
// ("postgres_verdict:<v>" for query_*_overload and background_overload) and
// keeps postgres_report samples only when includeSamples (clickhouse.
// include_sample_queries AND postgres.sample_queries). Call before Run.
func (s *Snapshotter) SetPostgres(verdict func() string, includeSamples bool) {
	s.pgVerdict, s.pgInclude = verdict, includeSamples
}

func NewSnapshotter(cfg *config.ClickHouseConfig, host string, sink *Sink,
	state func() ([]string, string), build func() model.DiagnoseReport) *Snapshotter {
	return &Snapshotter{cfg: cfg, host: host, sink: sink, state: state, build: build}
}

func (s *Snapshotter) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Snapshots.CheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.Check(ctx, now)
		}
	}
}

// Check performs one trigger evaluation; it reports whether a snapshot was
// captured and queued.
func (s *Snapshotter) Check(ctx context.Context, now time.Time) bool {
	reason := Reason(s.state())
	if s.pgVerdict != nil {
		if v := s.pgVerdict(); postgresTriggers[v] {
			if reason != "" {
				reason += ";"
			}
			reason += "postgres_verdict:" + v
		}
	}
	if reason == "" {
		return false
	}
	if !s.lastAt.IsZero() && reason == s.lastReason && now.Sub(s.lastAt) < s.cfg.Snapshots.MinInterval {
		return false
	}
	r, ok := s.safeBuild()
	if !ok {
		return false
	}
	r = StripSensitive(r, s.cfg.IncludeSampleQueries)
	r = StripPostgres(r, s.pgInclude)
	js, err := json.Marshal(r)
	if err != nil {
		slog.Error("clickhouse: encoding diagnose snapshot failed; skipped", "err", err)
		return false
	}
	verdict := ""
	if r.IODiagnosis != nil {
		verdict = string(r.IODiagnosis.Verdict)
	}
	enqueueRows(s.sink, TableSnapshots, []SnapshotRow{{
		TS: chTime(now), Host: s.host, Reason: reason, Verdict: verdict, Report: string(js),
	}})
	s.sink.m.snapshots.WithLabelValues(reasonKind(reason)).Inc()
	s.lastAt, s.lastReason = now, reason
	s.sink.send(ctx)
	return true
}

func (s *Snapshotter) safeBuild() (r model.DiagnoseReport, ok bool) {
	defer func() {
		if v := recover(); v != nil {
			slog.Error("clickhouse: diagnose snapshot build panicked; skipped", "panic", v)
			ok = false
		}
	}()
	return s.build(), true
}
