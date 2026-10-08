package chsink

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/process"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

const digestTextMemory = 50_000

// Sources are the producers' drain functions. A nil field means that
// producer is disabled or unavailable; its tables are simply not written.
type Sources struct {
	Digests  func() ([]querystats.DigestDelta, uint64)
	Flows    func() ([]netflow.FlowDelta, uint64)
	Slow     func() ([]model.MySQLSlowEvent, uint64)
	Families func() []process.FamilyWindow
	Comm     func(pid uint32) string
}

// Inserter is satisfied by *Client.
type Inserter interface {
	Insert(ctx context.Context, table string, gz []byte) (Outcome, error)
}

type batch struct {
	id    uint64
	table string
	rows  int
	body  []byte
}

type metrics struct {
	sent, dropped, snapshots *prometheus.CounterVec
	bufferBytes, lastSuccess prometheus.Gauge
	hostInfo                 *prometheus.GaugeVec
}

func newMetrics() *metrics {
	ns, sub := "obs_agent", "clickhouse"
	return &metrics{
		sent: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "rows_sent_total",
			Help: "Rows delivered to ClickHouse, by table."}, []string{"table"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "rows_dropped_total",
			Help: "Rows not delivered (buffer_full, rejected, shutdown) or events folded into overflow keys (drain_cap)."},
			[]string{"table", "reason"}),
		snapshots: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "snapshots_total",
			Help: "Diagnose snapshots captured, by trigger kind."}, []string{"reason_kind"}),
		bufferBytes: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: sub, Name: "buffer_bytes",
			Help: "Encoded bytes waiting to be sent."}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: sub, Name: "last_success_timestamp_seconds",
			Help: "Unix time of the last successful insert (0 = never)."}),
		hostInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Subsystem: sub, Name: "host_info",
			Help: "Always 1; host is the value written to ClickHouse's host column (links Prometheus instance to ClickHouse rows)."},
			[]string{"host"}),
	}
}

// Sink drains the producers every flush interval and delivers the rows.
type Sink struct {
	cfg  *config.ClickHouseConfig
	host string
	ins  Inserter
	src  Sources
	m    *metrics

	mu       sync.Mutex // buf, bufBytes, nextID, lastEnd, seen
	buf      []batch
	bufBytes int
	nextID   uint64
	lastEnd  time.Time
	seen     *idSet

	sendMu     sync.Mutex // serialises send; guards failing, lastReject
	failing    bool
	lastReject map[string]time.Time
}

func NewSink(cfg *config.ClickHouseConfig, host string, ins Inserter, src Sources, start time.Time) *Sink {
	s := &Sink{
		cfg: cfg, host: host, ins: ins, src: src, m: newMetrics(),
		lastEnd: start.UTC().Truncate(time.Second), seen: newIDSet(digestTextMemory),
		lastReject: make(map[string]time.Time),
	}
	s.m.hostInfo.WithLabelValues(host).Set(1)
	return s
}

// Collectors returns the self-metrics for registration.
func (s *Sink) Collectors() []prometheus.Collector {
	return []prometheus.Collector{s.m.sent, s.m.dropped, s.m.snapshots, s.m.bufferBytes, s.m.lastSuccess, s.m.hostInfo}
}

// Run flushes every FlushInterval until ctx is done, then performs one last
// flush bounded by Timeout and counts whatever is left as "shutdown".
func (s *Sink) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.shutdown()
			return
		case now := <-t.C:
			s.Flush(ctx, now)
		}
	}
}

func (s *Sink) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	defer cancel()
	s.Flush(ctx, time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.buf {
		s.m.dropped.WithLabelValues(b.table, "shutdown").Add(float64(b.rows))
	}
	s.buf, s.bufBytes = nil, 0
	s.m.bufferBytes.Set(0)
}

// Flush runs one cycle: drain every source into one batch per table for the
// window (previous end, now], then send.
func (s *Sink) Flush(ctx context.Context, now time.Time) {
	end := now.UTC().Truncate(time.Second)
	s.mu.Lock()
	start := s.lastEnd
	if end.Before(start) { // wall clock stepped back: never emit end < start
		start = end
	}
	s.lastEnd = end
	s.mu.Unlock()
	w := flushWindow{start, end}

	if s.src.Digests != nil {
		d, folded := s.src.Digests()
		s.m.dropped.WithLabelValues(TableDigestStats, "drain_cap").Add(float64(folded))
		enqueueRows(s, TableDigestStats, digestRows(s.host, w, d))
		s.mu.Lock()
		texts := textRows(d, s.seen, s.cfg.IncludeSampleQueries, now)
		s.mu.Unlock()
		enqueueRows(s, TableDigestText, texts)
	}
	if s.src.Slow != nil {
		ev, dropped := s.src.Slow()
		s.m.dropped.WithLabelValues(TableSlowQueries, "drain_cap").Add(float64(dropped))
		enqueueRows(s, TableSlowQueries, slowRows(s.host, ev, s.cfg.IncludeSampleQueries))
	}
	if s.src.Flows != nil {
		f, folded := s.src.Flows()
		s.m.dropped.WithLabelValues(TablePeerStats, "drain_cap").Add(float64(folded))
		enqueueRows(s, TablePeerStats, peerRows(s.host, w, f, s.src.Comm))
	}
	if s.src.Families != nil {
		enqueueRows(s, TableFamilyStats, familyRows(s.host, w, s.src.Families()))
	}
	s.send(ctx)
}

func enqueueRows[T any](s *Sink, table string, rows []T) {
	if len(rows) == 0 {
		return
	}
	body, err := encodeRows(rows)
	if err != nil {
		slog.Error("clickhouse: encoding rows failed; dropped", "table", table, "err", err)
		s.m.dropped.WithLabelValues(table, "rejected").Add(float64(len(rows)))
		return
	}
	s.enqueue(batch{table: table, rows: len(rows), body: body})
}

// enqueue appends b and evicts until under MaxBufferBytes: diagnose
// snapshots first (largest, least essential), then the oldest batch.
func (s *Sink) enqueue(b batch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	b.id = s.nextID
	s.buf = append(s.buf, b)
	s.bufBytes += len(b.body)
	for s.bufBytes > s.cfg.MaxBufferBytes && len(s.buf) > 0 {
		i := 0
		for j, x := range s.buf {
			if x.table == TableSnapshots {
				i = j
				break
			}
		}
		ev := s.buf[i]
		s.buf = append(s.buf[:i], s.buf[i+1:]...)
		s.bufBytes -= len(ev.body)
		s.m.dropped.WithLabelValues(ev.table, "buffer_full").Add(float64(ev.rows))
	}
	s.m.bufferBytes.Set(float64(s.bufBytes))
}

// send delivers up to MaxBatchesPerFlush batches oldest first. A retryable
// failure stops the cycle so order is preserved.
func (s *Sink) send(ctx context.Context) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for n := 0; n < s.cfg.MaxBatchesPerFlush; n++ {
		s.mu.Lock()
		if len(s.buf) == 0 {
			s.mu.Unlock()
			return
		}
		b := s.buf[0]
		s.mu.Unlock()

		out, err := s.ins.Insert(ctx, b.table, b.body)
		switch out {
		case OutcomeRetry:
			if !s.failing {
				slog.Warn("clickhouse: export failing; buffering", "table", b.table, "err", err)
				s.failing = true
			}
			return
		case OutcomeReject:
			if time.Since(s.lastReject[b.table]) > 5*time.Minute {
				slog.Error("clickhouse: batch rejected; dropped", "table", b.table, "rows", b.rows, "err", err)
				s.lastReject[b.table] = time.Now()
			}
			s.m.dropped.WithLabelValues(b.table, "rejected").Add(float64(b.rows))
		case OutcomeOK:
			if s.failing {
				slog.Info("clickhouse: export recovered")
				s.failing = false
			}
			s.m.sent.WithLabelValues(b.table).Add(float64(b.rows))
			s.m.lastSuccess.Set(float64(time.Now().Unix()))
		}
		s.remove(b.id)
	}
}

// remove deletes the batch by id: it may already have been evicted while in
// flight, in which case nothing else must be removed.
func (s *Sink) remove(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.buf {
		if x.id == id {
			s.buf = append(s.buf[:i], s.buf[i+1:]...)
			s.bufBytes -= len(x.body)
			break
		}
	}
	s.m.bufferBytes.Set(float64(s.bufBytes))
}
