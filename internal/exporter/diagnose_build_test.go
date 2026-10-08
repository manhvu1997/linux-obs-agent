package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/collector"
	"github.com/manhvu1997/linux-obs-agent/internal/config"
)

func bareExporter() *PrometheusExporter {
	return &PrometheusExporter{coll: collector.New(&config.Defaults().Collect), hostname: "h1"}
}

func TestBuildDiagnoseReport(t *testing.T) {
	r := bareExporter().BuildDiagnoseReport(10, 5)
	if r.Hostname != "h1" || r.IODiagnosis == nil {
		t.Fatalf("report = %+v", r)
	}
}

func TestHandleDiagnoseUsesBuilder(t *testing.T) {
	rec := httptest.NewRecorder()
	bareExporter().handleDiagnose(rec, httptest.NewRequest(http.MethodGet, "/api/diagnose", nil))
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 || got["hostname"] != "h1" {
		t.Fatalf("code=%d err=%v body=%s", rec.Code, err, rec.Body.String())
	}
}

func TestTriggerStateWithoutManager(t *testing.T) {
	active, verdict := bareExporter().TriggerState()
	if len(active) != 0 || verdict == "" {
		t.Fatalf("active=%v verdict=%q", active, verdict)
	}
}
