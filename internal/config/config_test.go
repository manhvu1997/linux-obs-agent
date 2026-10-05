package config

import "testing"

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
