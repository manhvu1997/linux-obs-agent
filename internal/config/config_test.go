package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestProcessDefaults(t *testing.T) {
	p := Defaults().Process
	if p.TopN != 20 || p.ReportTopN != 10 || p.FamilyBy != "systemd_unit" ||
		p.MaxConnectionsPerProcess != 50 || p.MaxPeersPerProcess != 20 {
		t.Fatalf("process defaults = %+v", p)
	}
}

func TestProcessFamilyByValidated(t *testing.T) {
	c := Defaults()
	c.Process.FamilyBy = "parent"
	if err := c.validate(); err == nil {
		t.Fatal("want error for family_by=parent")
	}
}
func TestNetflowDefaultsAndValidation(t *testing.T) {
	n := Defaults().Netflow
	if !n.Enabled || n.PollInterval != 5*time.Second || n.Window != 60*time.Second || !n.IncludeLoopback ||
		n.ListenRefreshInterval != 30*time.Second || n.MaxFamilies != 50 || n.MaxOutboundPeers != 100 {
		t.Fatalf("netflow defaults = %+v", n)
	}
	c := Defaults()
	c.Netflow.Window = time.Second
	if err := c.validate(); err == nil {
		t.Fatal("window < poll_interval must be rejected")
	}
}

func TestNetflowEnvOverride(t *testing.T) {
	t.Setenv("NETFLOW_ENABLED", "false")
	t.Setenv("NETFLOW_INCLUDE_LOOPBACK", "no")
	c := Defaults()
	applyNetflowEnvOverrides(c)
	if c.Netflow.Enabled || c.Netflow.IncludeLoopback {
		t.Fatalf("env overrides not applied: %+v", c.Netflow)
	}
}

func TestMySQLDigestDefaults(t *testing.T) {
	m := Defaults().MySQL
	if m.Enabled || !m.EmitAllQueries || m.DigestWindow != 60*time.Second || m.TopDigests != 20 ||
		m.StickyDigestsMax != 50 || m.StickyDigestTTL != time.Hour {
		t.Fatalf("mysql defaults = %+v", m)
	}
	c := Defaults()
	c.MySQL.Enabled = true
	c.MySQL.DigestWindow = time.Second
	if err := c.validate(); err == nil {
		t.Fatal("digest_window < poll_interval must be rejected when mysql is enabled")
	}
}

func TestMySQLSampleQueries(t *testing.T) {
	if !Defaults().MySQL.SampleQueries {
		t.Fatal("mysql.sample_queries must default to true")
	}
	t.Setenv("MYSQL_SAMPLE_QUERIES", "false")
	c := Defaults()
	applyMySQLEnvOverrides(c)
	if c.MySQL.SampleQueries {
		t.Fatal("MYSQL_SAMPLE_QUERIES=false not applied")
	}
}

func TestMySQLEnableDelayAcct(t *testing.T) {
	if Defaults().MySQL.EnableDelayAcct {
		t.Fatal("mysql.enable_delayacct must default to false")
	}
	t.Setenv("MYSQL_ENABLE_DELAYACCT", "true")
	c := Defaults()
	applyMySQLEnvOverrides(c)
	if !c.MySQL.EnableDelayAcct {
		t.Fatal("MYSQL_ENABLE_DELAYACCT=true not applied")
	}
}

func TestMySQLCommitWait(t *testing.T) {
	if !Defaults().MySQL.CommitWait {
		t.Fatal("mysql.commit_wait must default to true")
	}
	t.Setenv("MYSQL_COMMIT_WAIT", "false")
	c := Defaults()
	applyMySQLEnvOverrides(c)
	if c.MySQL.CommitWait {
		t.Fatal("MYSQL_COMMIT_WAIT=false not applied")
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("mysql:\n  commit_wait: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYSQL_COMMIT_WAIT", "")
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.MySQL.CommitWait {
		t.Fatal("yaml commit_wait: false not applied")
	}
}

func TestMySQLFoldSystemSchemas(t *testing.T) {
	if !Defaults().MySQL.FoldSystemSchemas {
		t.Fatal("mysql.fold_system_schemas must default to true")
	}
	t.Setenv("MYSQL_FOLD_SYSTEM_SCHEMAS", "false")
	c := Defaults()
	applyMySQLEnvOverrides(c)
	if c.MySQL.FoldSystemSchemas {
		t.Fatal("MYSQL_FOLD_SYSTEM_SCHEMAS=false not applied")
	}
}

func TestProcessReportListSizes(t *testing.T) {
	p := Defaults().Process
	if p.EffectiveReportTopCPU() != 10 || p.EffectiveReportTopMem() != 10 ||
		p.EffectiveReportTopFamiliesCPU() != 10 || p.EffectiveReportTopFamiliesMem() != 10 {
		t.Fatalf("unset list sizes must fall back to report_top_n: %+v", p)
	}
	p.ReportTopCPU, p.ReportTopMem, p.ReportTopFamiliesCPU, p.ReportTopFamiliesMem = 5, 15, 3, 25
	if p.EffectiveReportTopCPU() != 5 || p.EffectiveReportTopMem() != 15 ||
		p.EffectiveReportTopFamiliesCPU() != 3 || p.EffectiveReportTopFamiliesMem() != 25 {
		t.Fatalf("explicit list sizes not honoured: %+v", p)
	}
	c := Defaults()
	c.Process.ReportTopFamiliesMem = -1
	if err := c.validate(); err == nil {
		t.Fatal("negative report_top_families_mem accepted")
	}
}

func TestMySQLOverloadThresholds(t *testing.T) {
	m := Defaults().MySQL
	if m.OverloadNodeCPUPercent != 85 || m.OverloadNodeLoad != 1.5 {
		t.Fatalf("overload defaults = %v / %v", m.OverloadNodeCPUPercent, m.OverloadNodeLoad)
	}
	c := Defaults()
	c.MySQL.Enabled = true
	c.MySQL.OverloadNodeLoad = 0
	if err := c.validate(); err == nil {
		t.Fatal("overload_node_load 0 accepted with mysql enabled")
	}
}

func TestMySQLRoleThresholds(t *testing.T) {
	m := Defaults().MySQL
	if m.CPUCulpritPercentOfNodeCPUUsed != 20 || m.CPUCulpritMinNodeCPUUsedPercent != 50 || m.VictimWaitPercent != 50 {
		t.Fatalf("defaults = %v / %v / %v", m.CPUCulpritPercentOfNodeCPUUsed, m.CPUCulpritMinNodeCPUUsedPercent, m.VictimWaitPercent)
	}
	for _, bad := range []float64{0, -1, 101} {
		c := Defaults()
		c.MySQL.Enabled = true
		c.MySQL.VictimWaitPercent = bad
		if err := c.validate(); err == nil {
			t.Fatalf("victim_wait_percent %v accepted", bad)
		}
	}
}

func TestMySQLIOCulpritThresholds(t *testing.T) {
	m := Defaults().MySQL
	if m.IOCulpritPercentOfDiskRead != 20 || m.IOCulpritMinNodeDiskReadMBPerSec != 5 {
		t.Fatalf("defaults = %v / %v", m.IOCulpritPercentOfDiskRead, m.IOCulpritMinNodeDiskReadMBPerSec)
	}
	for _, bad := range []float64{0, -1, 101} {
		c := Defaults()
		c.MySQL.Enabled = true
		c.MySQL.IOCulpritPercentOfDiskRead = bad
		if err := c.validate(); err == nil {
			t.Fatalf("io_culprit_percent_of_disk_read %v accepted", bad)
		}
	}
	for _, bad := range []float64{0, -1} {
		c := Defaults()
		c.MySQL.Enabled = true
		c.MySQL.IOCulpritMinNodeDiskReadMBPerSec = bad
		if err := c.validate(); err == nil {
			t.Fatalf("io_culprit_min_node_disk_read_mb_per_sec %v accepted", bad)
		}
	}
	c := Defaults()
	c.MySQL.Enabled = true
	c.MySQL.IOCulpritMinNodeDiskReadMBPerSec = 500 // no upper bound on MB/s
	if err := c.validate(); err != nil {
		t.Fatalf("io_culprit_min_node_disk_read_mb_per_sec 500 rejected: %v", err)
	}
}
