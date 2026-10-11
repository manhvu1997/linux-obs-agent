package promcollect

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func pgDesc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc("obs_agent_postgres_"+name, help, labels, nil)
}

var (
	pgQueriesDesc   = pgDesc("queries_total", "PostgreSQL statements executed (top-level PortalRun calls), by cluster and command (client | parallel | fastpath | autovacuum | replication).", "cluster", "command")
	pgCPUDesc       = pgDesc("query_cpu_seconds_total", "On-CPU seconds inside statements (parse, plan, execute; parallel workers' CPU under command=parallel).", "cluster", "command")
	pgRunqDesc      = pgDesc("query_runq_wait_seconds_total", "Seconds statements waited for a CPU (run queue).", "cluster", "command")
	pgWallDesc      = pgDesc("query_wall_seconds_total", "Wall-clock seconds inside statements (client intervals).", "cluster", "command")
	pgDiskReadDesc  = pgDesc("query_disk_read_bytes_total", "Bytes statements caused to be read from storage. Absent while not measured (PostgreSQL 18+ async I/O).", "cluster", "command")
	pgDiskWriteDesc = pgDesc("query_disk_write_bytes_total", "Bytes statements caused to be written (dirtied). Absent while not measured.", "cluster", "command")
	pgIOWaitDesc    = pgDesc("query_io_wait_seconds_total", "Seconds statements waited for block I/O (delay accounting). Absent while not measured.", "cluster", "command")
	pgWALWaitDesc   = pgDesc("query_wal_wait_seconds_total", "Seconds statements waited inside XLogFlush beyond their own CPU, run queue and block I/O (commit / WAL flush wait). Absent while not measured.", "cluster", "command")
	pgSyncRepDesc   = pgDesc("query_syncrep_wait_seconds_total", "Seconds statements waited for synchronous standbys (SyncRepWaitForLSN). Absent while not measured.", "cluster", "command")

	pgDigests = digestDescs{
		cpu:     pgDesc("digest_cpu_seconds_total", "On-CPU seconds of statements of this digest.", "cluster", "digest_id"),
		calls:   pgDesc("digest_calls_total", "Executions of statements of this digest.", "cluster", "digest_id"),
		disk:    pgDesc("digest_disk_read_bytes_total", "Bytes statements of this digest caused to be read from storage.", "cluster", "digest_id"),
		runq:    pgDesc("digest_runq_wait_seconds_total", "Seconds statements of this digest waited for a CPU (full mode).", "cluster", "digest_id"),
		ioWait:  pgDesc("digest_io_wait_seconds_total", "Seconds statements of this digest waited for block I/O (full mode, while measured).", "cluster", "digest_id"),
		walWait: pgDesc("digest_wal_wait_seconds_total", "Seconds statements of this digest waited for the WAL flush (full mode, while measured).", "cluster", "digest_id"),
		info:    pgDesc("digest_info", "Normalised SQL text of a digest (value 1); join with * on(instance, cluster, digest_id) group_left(digest_text).", "cluster", "digest_id", "digest_text"),
	}

	pgBackendCPUDesc  = pgDesc("backend_cpu_seconds_total", "CPU seconds of a cluster's backends by type (client, autovacuum, checkpointer, io_worker, …), integrated from process scans.", "cluster", "backend_type")
	pgBackendReadDesc = pgDesc("backend_disk_read_bytes_total", "Storage bytes read by a cluster's backends by type (needs process.include_io).", "cluster", "backend_type")
	pgCoverageDesc    = pgDesc("query_cpu_coverage_ratio", "Statement CPU ÷ the cluster's CPU over the digest window (≈ 0–1, not clamped; absent while unknown).", "cluster")
	pgDigestCovDesc   = pgDesc("digest_coverage_ratio", "Share (0-1) of the window's statement CPU explained by the exported per-digest series.", "cluster")
	pgIOAvailDesc     = pgDesc("io_wait_available", "1 when per-statement block-I/O wait is measured over the whole digest window, else 0.", "cluster")
	pgWALAvailDesc    = pgDesc("wal_wait_available", "1 when per-statement WAL-flush wait is measured over the whole digest window, else 0.", "cluster")
	pgEnrichUpDesc    = pgDesc("enrichment_up", "1 when the pg_stat_statements enrichment's last poll succeeded, else 0.", "cluster")

	pgTracingDesc  = pgDesc("tracing_active", "1 while the statement probes are attached; 0 while the circuit breaker has shed them or tracing is unavailable.")
	pgShedDesc     = pgDesc("shed_total", "Times the circuit breaker detached the probes (statement rate above postgres.max_statements_per_sec).")
	pgDroppedDesc  = pgDesc("events_dropped_total", "Statement intervals lost (fallback ring buffer full or consumer behind).")
	pgTextDropDesc = pgDesc("text_events_dropped_total", "Text events dropped on a full channel (re-requested; no interval lost).")
	pgOverflowDesc = pgDesc("agg_overflow_total", "Intervals that bypassed in-kernel aggregation because the map was full (exact, as full events).")
	pgMismatchDesc = pgDesc("hash_mismatch_total", "Kernel text hashes found inconsistent with the digest; the hash is switched to exact processing.")
	pgCreditDesc   = pgDesc("credit_dropped_total", "In-flight credit never matched by the closing interval (dropped after two drains).")
	pgOverCapDesc  = pgDesc("backends_over_capacity", "1 when live backends exceed the kernel session map (16 384); some intervals are lost.")
)

// PostgresHealth are the analyzer's health readings. A nil func reads 0.
type PostgresHealth struct {
	Dropped, TextDropped, AggOverflow, HashMismatches, ShedTotal, CreditDropped func() uint64
	Active, OverCapacity                                                        func() bool
}

// PostgresCollector exports obs_agent_postgres_*.
type PostgresCollector struct {
	views       func() []postgres.ClusterView
	health      PostgresHealth
	mode        string
	minimalTopN int
	includeIO   bool
}

func NewPostgresCollector(views func() []postgres.ClusterView, health PostgresHealth, mode string, minimalTopN int, includeIO bool) *PostgresCollector {
	if minimalTopN < 1 {
		minimalTopN = 20
	}
	return &PostgresCollector{views: views, health: health, mode: mode, minimalTopN: minimalTopN, includeIO: includeIO}
}

func (c *PostgresCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{pgQueriesDesc, pgCPUDesc, pgRunqDesc, pgWallDesc, pgDiskReadDesc, pgDiskWriteDesc,
		pgIOWaitDesc, pgWALWaitDesc, pgSyncRepDesc, pgDigests.cpu, pgDigests.calls, pgDigests.disk, pgDigests.runq,
		pgDigests.ioWait, pgDigests.walWait, pgDigests.info, pgBackendCPUDesc, pgBackendReadDesc, pgCoverageDesc,
		pgDigestCovDesc, pgIOAvailDesc, pgWALAvailDesc, pgEnrichUpDesc, pgTracingDesc, pgShedDesc, pgDroppedDesc,
		pgTextDropDesc, pgOverflowDesc, pgMismatchDesc, pgCreditDesc, pgOverCapDesc} {
		ch <- d
	}
}

func (c *PostgresCollector) Collect(ch chan<- prometheus.Metric) {
	sec := func(ns uint64) float64 { return float64(ns) / 1e9 }
	ok := func(acct map[string]string, k string) bool { return acct[k] == querystats.AccountingOK }
	for _, v := range c.views() {
		s, cl := v.Snapshot, v.Name
		diskOK, ioOK := ok(v.Accounting, querystats.AccountingKeyDiskBytes), ok(v.Accounting, querystats.AccountingKeyDiskWait)
		walOK, syncOK := ok(v.Accounting, "wal_wait"), ok(v.Accounting, "syncrep_wait")
		for cmd, q := range s.Commands {
			emit(ch, pgQueriesDesc, prometheus.CounterValue, float64(q.Calls), cl, cmd)
			emit(ch, pgCPUDesc, prometheus.CounterValue, sec(q.CPUNs), cl, cmd)
			emit(ch, pgRunqDesc, prometheus.CounterValue, sec(q.RunqNs), cl, cmd)
			emit(ch, pgWallDesc, prometheus.CounterValue, sec(q.WallNs), cl, cmd)
			if diskOK {
				emit(ch, pgDiskReadDesc, prometheus.CounterValue, float64(q.DiskReadBytes), cl, cmd)
				emit(ch, pgDiskWriteDesc, prometheus.CounterValue, float64(q.DiskWriteBytes), cl, cmd)
			}
			if ioOK {
				emit(ch, pgIOWaitDesc, prometheus.CounterValue, sec(q.IOWaitNs), cl, cmd)
			}
			if walOK {
				emit(ch, pgWALWaitDesc, prometheus.CounterValue, sec(q.RedoWaitNs), cl, cmd)
			}
			if syncOK {
				emit(ch, pgSyncRepDesc, prometheus.CounterValue, sec(q.ReplicaWaitNs), cl, cmd)
			}
		}
		exported := emitDigests(ch, pgDigests, s, c.mode, c.minimalTopN, ioOK, walOK, cl)
		emit(ch, pgDigestCovDesc, prometheus.GaugeValue, coverage(c.mode, exported, s.QueryCPUMsTotal), cl)
		if s.QueryCPUCoveragePercent != nil {
			emit(ch, pgCoverageDesc, prometheus.GaugeValue, *s.QueryCPUCoveragePercent/100, cl)
		}
		emit(ch, pgIOAvailDesc, prometheus.GaugeValue, boolGauge(ioOK), cl)
		emit(ch, pgWALAvailDesc, prometheus.GaugeValue, boolGauge(walOK), cl)
		emit(ch, pgEnrichUpDesc, prometheus.GaugeValue, boolGauge(v.EnrichmentUp), cl)
		for typ, l := range v.Backends {
			emit(ch, pgBackendCPUDesc, prometheus.CounterValue, l.CPUSeconds, cl, typ)
			if c.includeIO {
				emit(ch, pgBackendReadDesc, prometheus.CounterValue, l.ReadBytes, cl, typ)
			}
		}
	}
	h := c.health
	readB := func(f func() bool) float64 {
		if f == nil {
			return 0
		}
		return boolGauge(f())
	}
	readU := func(f func() uint64) float64 {
		if f == nil {
			return 0
		}
		return float64(f())
	}
	emit(ch, pgTracingDesc, prometheus.GaugeValue, readB(h.Active))
	emit(ch, pgOverCapDesc, prometheus.GaugeValue, readB(h.OverCapacity))
	emit(ch, pgShedDesc, prometheus.CounterValue, readU(h.ShedTotal))
	emit(ch, pgDroppedDesc, prometheus.CounterValue, readU(h.Dropped))
	emit(ch, pgTextDropDesc, prometheus.CounterValue, readU(h.TextDropped))
	emit(ch, pgOverflowDesc, prometheus.CounterValue, readU(h.AggOverflow))
	emit(ch, pgMismatchDesc, prometheus.CounterValue, readU(h.HashMismatches))
	emit(ch, pgCreditDesc, prometheus.CounterValue, readU(h.CreditDropped))
}
