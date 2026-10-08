package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/chsink"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/exporter"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/mysql"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/procinfo"
)

// startClickHouse enables the producers' drains and starts the sink and
// snapshotter. The returned channel closes when the sink has finished its
// shutdown flush; it is already closed when the export could not start.
func startClickHouse(ctx context.Context, cfg *config.Config, promExp *exporter.PrometheusExporter,
	my *mysql.Analyzer, netAcc *netflow.Accumulator, insp *process.Inspector) <-chan struct{} {
	done := make(chan struct{})
	ch := &cfg.ClickHouse
	client, err := chsink.NewClient(ch)
	if err != nil {
		slog.Error("clickhouse: export disabled", "err", err)
		close(done)
		return done
	}
	pingCtx, cancel := context.WithTimeout(ctx, ch.Timeout)
	if err := client.Ping(pingCtx); err != nil {
		slog.Warn("clickhouse: ping failed; rows are buffered and retried", "err", err)
	}
	cancel()

	host := cfg.Agent.NodeName
	if host == "" {
		host, _ = os.Hostname()
	}
	src := chsink.Sources{Comm: procinfo.ReadComm}
	insp.EnableFamilyDrain()
	src.Families = insp.DrainFamilies
	if netAcc != nil {
		netAcc.EnableDrain(ch.MaxFlowKeys)
		src.Flows = netAcc.DrainFlows
	}
	if cfg.MySQL.Enabled {
		my.EnableDigestDrain(ch.MaxDigestKeys)
		src.Digests = my.DrainDigests
		my.EnableSlowDrain(ch.MaxSlowQueriesPerFlush)
		src.Slow = my.DrainSlowQueries
	}

	// The sink and snapshotter must see the effective flag: raw SQL leaves the
	// host only when both clickhouse.include_sample_queries and
	// mysql.sample_queries are true.
	eff := *ch
	eff.IncludeSampleQueries = ch.EffectiveIncludeSamples(cfg.MySQL.SampleQueries)

	sink := chsink.NewSink(&eff, host, client, src, time.Now())
	go func() {
		defer close(done)
		sink.Run(ctx)
	}()

	switch {
	case promExp != nil:
		promExp.RegisterCollectors(sink.Collectors()...)
		if ch.Snapshots.Enabled {
			build := func() model.DiagnoseReport { return promExp.BuildDiagnoseReport(100, 20) }
			go chsink.NewSnapshotter(&eff, host, sink, promExp.TriggerState, build).Run(ctx)
		}
	case ch.Snapshots.Enabled:
		slog.Warn("clickhouse: snapshots need agent.metrics_addr (the /api/diagnose builder); snapshots disabled")
	}
	slog.Info("clickhouse: export enabled", "config", ch.String(), "host", host)
	return done
}
