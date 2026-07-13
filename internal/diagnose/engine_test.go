package diagnose

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// findFinding returns the first finding for the given resource, or nil.
func findFinding(d *model.Diagnosis, resource string) *model.Finding {
	for i := range d.Findings {
		if d.Findings[i].Resource == resource {
			return &d.Findings[i]
		}
	}
	return nil
}

func TestAnalyze_IdleSystem(t *testing.T) {
	r := &model.DiagnoseReport{
		Metrics: model.NodeMetrics{
			CPU:     model.CPUMetrics{UsagePercent: 12, UserPercent: 8, SysPercent: 4, IOWaitPercent: 1},
			Memory:  model.MemMetrics{UsagePercent: 40, AvailableBytes: 8 << 30},
			LoadAvg: model.LoadMetrics{Load1: 0.5, NumCPU: 4},
		},
	}
	d := Analyze(r)
	if d.Severity != "normal" {
		t.Fatalf("severity = %q, want normal", d.Severity)
	}
	if d.PrimaryResource != "none" {
		t.Fatalf("primary_resource = %q, want none", d.PrimaryResource)
	}
	if d.RootCause != nil {
		t.Fatalf("root_cause should be nil for idle system, got %+v", d.RootCause)
	}
	if len(d.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(d.Findings))
	}
}

func TestAnalyze_NilReport(t *testing.T) {
	d := Analyze(nil)
	if d == nil || d.Severity != "normal" {
		t.Fatalf("nil report should yield a normal diagnosis, got %+v", d)
	}
}

func TestAnalyze_CPUBoundApplication(t *testing.T) {
	r := &model.DiagnoseReport{
		Metrics: model.NodeMetrics{
			CPU:     model.CPUMetrics{UsagePercent: 94, UserPercent: 80, SysPercent: 14},
			Memory:  model.MemMetrics{UsagePercent: 50, AvailableBytes: 4 << 30},
			LoadAvg: model.LoadMetrics{Load1: 3.0, NumCPU: 4},
		},
		TopProcesses: []model.ProcessStats{
			{PID: 12345, Comm: "java", Cmdline: "java -jar app.jar", CPUPercent: 82, State: "R"},
			{PID: 10, Comm: "sshd", CPUPercent: 2, State: "S"},
		},
		CPUProfileReport: &model.CPUProfileReport{
			System: model.CPUProfileSystemInfo{TotalSamples: 1000, UserSamples: 850, KernelSamples: 150},
			Processes: []model.CPUProfileProcess{
				{
					PID: 12345, Comm: "java", Samples: 760, UserSamples: 700, KernelSamples: 60,
					TopUserStacks: []model.CPUStack{
						{SymbolStack: []string{"serializeJSON", "writeValue", "handleRequest"}, Samples: 500, Percent: 65},
					},
				},
			},
		},
	}
	d := Analyze(r)
	if d.PrimaryResource != "cpu" {
		t.Fatalf("primary_resource = %q, want cpu", d.PrimaryResource)
	}
	if d.Severity != "warning" {
		t.Fatalf("severity = %q, want warning (94%% < 95%% critical cutoff)", d.Severity)
	}
	f := findFinding(d, "cpu")
	if f == nil {
		t.Fatal("no cpu finding")
	}
	if f.Activity != "cpu_bound" {
		t.Fatalf("activity = %q, want cpu_bound", f.Activity)
	}
	if f.Process == nil || f.Process.PID != 12345 {
		t.Fatalf("culprit = %+v, want PID 12345", f.Process)
	}
	if f.Confidence < 0.85 {
		t.Fatalf("confidence = %.2f, want >=0.85 (profile shows 76%% share)", f.Confidence)
	}
	if d.RootCause == nil || d.RootCause.Resource != "cpu" {
		t.Fatalf("root_cause = %+v, want cpu", d.RootCause)
	}
}

func TestAnalyze_FsyncStorm(t *testing.T) {
	r := &model.DiagnoseReport{
		Metrics: model.NodeMetrics{
			CPU: model.CPUMetrics{UsagePercent: 40, IOWaitPercent: 35, BlockedProcs: 3},
			Disk: []model.DiskMetrics{
				{Device: "sda", IOUtilPercent: 98, AvgWaitMs: 25, WriteBytesPerSec: 5e7},
			},
			LoadAvg: model.LoadMetrics{Load1: 2.0, NumCPU: 4},
		},
		FsyncReport: &model.FsyncAnalysis{
			TopOffenders: []model.FsyncOffender{
				{PID: 567, Comm: "mongod", Cmdline: "/usr/bin/mongod", FsyncCalls: 1200, AvgLatencyMs: 3.2, MaxLatencyMs: 25.1, AppType: "database"},
			},
		},
	}
	d := Analyze(r)
	if d.PrimaryResource != "disk" {
		t.Fatalf("primary_resource = %q, want disk", d.PrimaryResource)
	}
	f := findFinding(d, "disk")
	if f == nil {
		t.Fatal("no disk finding")
	}
	if f.Activity != "excessive_fsync" {
		t.Fatalf("activity = %q, want excessive_fsync", f.Activity)
	}
	if f.Process == nil || f.Process.Comm != "mongod" || f.Process.AppType != "database" {
		t.Fatalf("culprit = %+v, want mongod/database", f.Process)
	}
	if f.Behavior != "bottleneck" {
		t.Fatalf("behavior = %q, want bottleneck (max latency 25ms)", f.Behavior)
	}
}

func TestAnalyze_TCPRetransmits(t *testing.T) {
	r := &model.DiagnoseReport{
		Metrics: model.NodeMetrics{
			CPU:     model.CPUMetrics{UsagePercent: 30},
			Memory:  model.MemMetrics{UsagePercent: 40},
			LoadAvg: model.LoadMetrics{Load1: 0.8, NumCPU: 4},
		},
		RecentEvents: []model.EBPFEvent{
			{
				Type: model.EventTCPRetransmit,
				Data: model.TCPRetransmitEvent{
					PID: 900, Comm: "app-server", DstIP: "10.0.0.5", DstPort: 5432,
					Flow: "10.0.0.1:44000 → 10.0.0.5:5432", TCPState: "ESTABLISHED",
					RTTUS: 12000, SndCwnd: 4, RetransmitCount: 18, LossRate: 7.5,
				},
			},
		},
	}
	d := Analyze(r)
	if d.PrimaryResource != "network" {
		t.Fatalf("primary_resource = %q, want network", d.PrimaryResource)
	}
	if d.Severity != "critical" {
		t.Fatalf("severity = %q, want critical (loss 7.5%%)", d.Severity)
	}
	f := findFinding(d, "network")
	if f == nil || f.Activity != "tcp_retransmits" {
		t.Fatalf("finding = %+v, want tcp_retransmits", f)
	}
	if f.Process == nil || f.Process.PID != 900 {
		t.Fatalf("culprit = %+v, want PID 900", f.Process)
	}
}

func TestAnalyze_SchedulerHighLoadLowCPU(t *testing.T) {
	r := &model.DiagnoseReport{
		Metrics: model.NodeMetrics{
			CPU:     model.CPUMetrics{UsagePercent: 20, IOWaitPercent: 5, BlockedProcs: 8},
			Memory:  model.MemMetrics{UsagePercent: 50},
			LoadAvg: model.LoadMetrics{Load1: 16, NumCPU: 4}, // normalised 4.0 -> critical
		},
		RecentEvents: []model.EBPFEvent{
			{Type: model.EventRunQLat, Data: model.RunQLatEvent{PID: 42, Comm: "worker", LatencyUs: 150000}},
		},
	}
	d := Analyze(r)
	if d.PrimaryResource != "scheduler" {
		t.Fatalf("primary_resource = %q, want scheduler", d.PrimaryResource)
	}
	f := findFinding(d, "scheduler")
	if f == nil || f.Activity != "runqueue_saturation" {
		t.Fatalf("finding = %+v, want runqueue_saturation", f)
	}
	if d.Severity != "critical" {
		t.Fatalf("severity = %q, want critical", d.Severity)
	}
}

func TestAnalyze_RankingPrefersHigherSeverity(t *testing.T) {
	// CPU warning (90%) vs disk critical (iowait 45%). Disk should win as root cause.
	r := &model.DiagnoseReport{
		Metrics: model.NodeMetrics{
			CPU: model.CPUMetrics{UsagePercent: 90, UserPercent: 60, SysPercent: 30, IOWaitPercent: 45, BlockedProcs: 5},
			Disk: []model.DiskMetrics{
				{Device: "nvme0n1", IOUtilPercent: 99, AvgWaitMs: 40},
			},
			LoadAvg: model.LoadMetrics{Load1: 5, NumCPU: 8},
		},
		TopProcesses: []model.ProcessStats{
			{PID: 1, Comm: "busy", CPUPercent: 88, State: "R"},
		},
	}
	d := Analyze(r)
	if d.PrimaryResource != "disk" {
		t.Fatalf("primary_resource = %q, want disk (critical beats cpu warning)", d.PrimaryResource)
	}
	// Both findings should be present.
	if findFinding(d, "cpu") == nil || findFinding(d, "disk") == nil {
		t.Fatalf("expected both cpu and disk findings, got %d", len(d.Findings))
	}
}
