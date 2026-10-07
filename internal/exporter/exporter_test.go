package exporter

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestQueueEventDropsCPUProfileSamples(t *testing.T) {
	e := New(&config.ExporterConfig{BatchSize: 10})

	e.QueueEvent(model.EBPFEvent{Type: model.EventIOLatency, PID: 1})
	for i := 0; i < recentCap; i++ {
		e.QueueEvent(model.EBPFEvent{Type: model.EventCPUProfile, PID: 2})
	}
	e.QueueEvent(model.EBPFEvent{Type: model.EventTCPRetransmit, PID: 3})

	recent := e.RecentEvents(0)
	if len(recent) != 2 {
		t.Fatalf("recent events = %d, want 2: %+v", len(recent), recent)
	}
	if recent[0].Type != model.EventIOLatency || recent[1].Type != model.EventTCPRetransmit {
		t.Errorf("recent types = %s, %s; want io_latency, tcp_retransmit", recent[0].Type, recent[1].Type)
	}
	if len(e.pending) != 2 {
		t.Errorf("pending export events = %d, want 2", len(e.pending))
	}
}
