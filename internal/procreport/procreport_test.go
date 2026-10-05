package procreport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

type fakeNet struct{}

func (fakeNet) Process(tgid uint32) model.NetworkSummary {
	return model.NetworkSummary{Inbound: model.DirectionStats{BytesTx: uint64(tgid)}, TopPeers: []model.PeerStats{}}
}
func (fakeNet) Family(name string) model.NetworkSummary {
	return model.NetworkSummary{Outbound: model.DirectionStats{BytesTx: uint64(len(name))}, TopPeers: []model.PeerStats{}}
}

type fakeInv struct{ calls [][]uint32 }

func (f *fakeInv) ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections {
	f.calls = append(f.calls, pids)
	out := map[uint32]model.ProcessConnections{}
	for _, p := range pids {
		switch p {
		case 1022: // php-fpm master owns the listener
			out[p] = model.ProcessConnections{ListeningPorts: []model.ListenPort{{Proto: "tcp", Addr: "0.0.0.0", Port: 9000}}}
		case 1301: // worker inherited the same listener
			out[p] = model.ProcessConnections{
				ListeningPorts: []model.ListenPort{{Proto: "tcp", Addr: "0.0.0.0", Port: 9000}},
				Connections:    []model.Connection{{Direction: "inbound", State: "ESTABLISHED", Src: "10.0.0.9:50000", Dst: "10.0.0.1:9000"}},
				Truncated:      3,
			}
		}
	}
	return out
}

func inputs(inv *fakeInv) Inputs {
	return Inputs{
		TopCPU: []model.ProcessStats{{PID: 1301, PPID: 1022, Comm: "php-fpm", Family: "php-fpm.service", CPUPercent: 30}},
		TopMem: []model.ProcessStats{{PID: 1301, Comm: "php-fpm", Family: "php-fpm.service"}},
		FamiliesCPU: []model.FamilyStats{{
			Family: "php-fpm.service", RootPID: 1022, ProcessCount: 2,
			TopMembers: []model.FamilyMember{{PID: 1301}},
		}},
		NetworkSource: "ebpf", InboundAccounting: "accept", WindowSeconds: 60,
		Inventory: inv, MaxConnections: 50,
	}
}

func TestBuild(t *testing.T) {
	inv := &fakeInv{}
	in := inputs(inv)
	in.Net = fakeNet{}
	r := Build(in, time.Unix(0, 0))

	if r.Type != "process_analysis" || r.NetworkSource != "ebpf" || r.WindowSeconds != 60 {
		t.Fatalf("header = %+v", r)
	}
	if len(inv.calls) != 1 || len(inv.calls[0]) != 2 {
		t.Fatalf("inventory must be read once for the distinct pids {1301,1022}, got %v", inv.calls)
	}
	p := r.TopCPU[0]
	if p.ProfileURL != "/api/profile?pid=1301" || p.ConnectionsTruncated != 3 || len(p.Connections) != 1 {
		t.Fatalf("process entry = %+v", p)
	}
	if p.Network == nil || p.Network.Inbound.BytesTx != 1301 {
		t.Fatalf("process network = %+v", p.Network)
	}
	f := r.TopFamiliesCPU[0]
	if len(f.ListeningPorts) != 1 || f.ListeningPorts[0].Port != 9000 {
		t.Fatalf("family listening ports must be the de-duplicated union: %+v", f.ListeningPorts)
	}
	if f.Network == nil || f.Network.Outbound.BytesTx != uint64(len("php-fpm.service")) {
		t.Fatalf("family network = %+v", f.Network)
	}
	if r.TopFamiliesMem == nil {
		t.Fatal("empty lists must encode as [] not null")
	}
}

func TestBuildWithoutNetwork(t *testing.T) {
	in := inputs(&fakeInv{})
	in.Net = nil
	in.NetworkSource = "unavailable: kprobe tcp_sendmsg: permission denied"
	r := Build(in, time.Unix(0, 0))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"network":`) {
		t.Fatalf("network must be omitted when netflow is unavailable: %s", b)
	}
}
