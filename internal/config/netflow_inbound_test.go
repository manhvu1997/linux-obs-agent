package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetflowMaxInboundPeers(t *testing.T) {
	if got := Defaults().Netflow.MaxInboundPeers; got != 100 {
		t.Fatalf("default max_inbound_peers = %d, want 100", got)
	}
	t.Setenv("NETFLOW_MAX_INBOUND_PEERS", "0")
	cfg, err := Load("")
	if err != nil || cfg.Netflow.MaxInboundPeers != 0 {
		t.Fatalf("env 0: cfg=%v err=%v", cfg.Netflow.MaxInboundPeers, err)
	}
}

func TestNetflowMaxInboundPeersNegativeRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("netflow:\n  max_inbound_peers: -1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "max_inbound_peers") {
		t.Fatalf("err = %v, want max_inbound_peers error", err)
	}
}
