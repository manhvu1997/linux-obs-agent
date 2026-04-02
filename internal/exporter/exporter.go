// Package exporter sends collected data to a central server via HTTP.
//
// It buffers events in memory, compresses the payload with gzip, and POSTs
// to the configured URL.  Retries use exponential back-off.  The exporter
// is designed to never block the collection hot path.
package exporter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const agentVersion = "1.0.0"

// Exporter collects Snapshots from channels and ships them to the server.
type Exporter struct {
	cfg      *config.ExporterConfig
	client   *http.Client
	hostname string

	mu      sync.Mutex
	pending []model.EBPFEvent
}

func New(cfg *config.ExporterConfig) *Exporter {
	hostname, _ := os.Hostname()
	return &Exporter{
		cfg:      cfg,
		hostname: hostname,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{IdleConnTimeout: 30 * time.Second},
		},
	}
}

// Run starts the flush loop. It blocks until ctx is cancelled.
func (e *Exporter) Run(ctx context.Context) {
	if e.cfg.URL == "" {
		slog.Info("exporter: no URL configured, export disabled")
		return
	}
	tick := time.NewTicker(e.cfg.FlushInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Nothing to flush here – callers invoke SendSnapshot directly.
		}
	}
}

// QueueEvent adds an eBPF event to the pending buffer (non-blocking).
func (e *Exporter) QueueEvent(ev model.EBPFEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.pending) >= e.cfg.BatchSize {
		// Discard oldest to bound memory usage.
		e.pending = e.pending[1:]
	}
	e.pending = append(e.pending, ev)
}

// SendSnapshot assembles a full Snapshot and ships it.
func (e *Exporter) SendSnapshot(
	ctx context.Context,
	metrics model.NodeMetrics,
	topProcs []model.ProcessStats,
) error {
	if e.cfg.URL == "" {
		return nil
	}

	e.mu.Lock()
	events := make([]model.EBPFEvent, len(e.pending))
	copy(events, e.pending)
	e.pending = e.pending[:0]
	e.mu.Unlock()

	snap := model.Snapshot{
		AgentVersion: agentVersion,
		Timestamp:    time.Now(),
		Hostname:     e.hostname,
		Metrics:      metrics,
		TopProcesses: topProcs,
		EBPFEvents:   events,
	}

	return e.sendWithRetry(ctx, snap)
}

// ─── HTTP transport ───────────────────────────────────────────────────────────

func (e *Exporter) sendWithRetry(ctx context.Context, snap model.Snapshot) error {
	backoff := 2 * time.Second
	const maxRetries = 3

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := e.send(ctx, snap); err == nil {
			return nil
		} else {
			if attempt == maxRetries {
				return fmt.Errorf("send failed after %d retries: %w", maxRetries, err)
			}
			slog.Warn("exporter: send failed, retrying",
				"attempt", attempt+1, "backoff", backoff, "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return nil
}

func (e *Exporter) send(ctx context.Context, snap model.Snapshot) error {
	body, contentType, err := e.encode(snap)
	if err != nil {
		return fmt.Errorf("encoding snapshot: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL+"/api/v1/snapshot", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Agent-Version", agentVersion)
	req.Header.Set("X-Hostname", e.hostname)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	slog.Debug("exporter: snapshot sent",
		"ebpf_events", len(snap.EBPFEvents),
		"status", resp.StatusCode)
	return nil
}

func (e *Exporter) encode(snap model.Snapshot) (*bytes.Reader, string, error) {
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, "", err
	}

	if !e.cfg.Compress {
		return bytes.NewReader(raw), "application/json", nil
	}

	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if _, err := gz.Write(raw); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}

	return bytes.NewReader(buf.Bytes()), "application/json+gzip", nil
}

// ─── Prometheus Metrics (additional lightweight local scraping) ───────────────
// See exporter/prometheus.go for the Prometheus handler registration.
