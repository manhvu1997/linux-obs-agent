package config

import (
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
		m.StickyDigestsMax != 50 || m.StickyDigestTTL != time.Hour ||
		m.CulpritCPUSharePercent != 20 || m.VictimRunqRatio != 5 {
		t.Fatalf("mysql defaults = %+v", m)
	}
	c := Defaults()
	c.MySQL.Enabled = true
	c.MySQL.DigestWindow = time.Second
	if err := c.validate(); err == nil {
		t.Fatal("digest_window < poll_interval must be rejected when mysql is enabled")
	}
}
