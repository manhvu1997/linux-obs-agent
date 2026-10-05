package netinv

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func v4hex(addr string, port uint16) string {
	ip := netip.MustParseAddr(addr).As4()
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], port)
}

func v6hex(addr string, port uint16) string {
	b := netip.MustParseAddr(addr).As16()
	var s strings.Builder
	for w := 0; w < 4; w++ {
		for k := 3; k >= 0; k-- {
			fmt.Fprintf(&s, "%02X", b[w*4+k])
		}
	}
	return fmt.Sprintf("%s:%04X", s.String(), port)
}

func row(i int, local, remote, st string, inode uint64) string {
	return fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000  1000 0 %d 1 0000000000000000 20 4 30 10 -1\n",
		i, local, remote, st, inode)
}

func TestParseNetTCPLiteral(t *testing.T) {
	in := header + row(0, "0100007F:0CEA", "00000000:0000", "0A", 1001)
	socks, err := ParseNetTCP(strings.NewReader(in), "tcp")
	if err != nil || len(socks) != 1 {
		t.Fatalf("socks=%v err=%v", socks, err)
	}
	s := socks[0]
	if s.Local.String() != "127.0.0.1:3306" || s.State != "LISTEN" || s.Inode != 1001 || s.Proto != "tcp" {
		t.Fatalf("parsed %+v", s)
	}
}

func TestParseNetTCP6UnmapsV4(t *testing.T) {
	in := header +
		row(0, "00000000000000000000000001000000:0CEA", "00000000000000000000000000000000:0000", "0A", 1) +
		row(1, v6hex("::ffff:10.0.1.7", 3306), v6hex("::ffff:10.0.3.15", 51844), "01", 2)
	socks, err := ParseNetTCP(strings.NewReader(in), "tcp6")
	if err != nil || len(socks) != 2 {
		t.Fatalf("socks=%v err=%v", socks, err)
	}
	if socks[0].Local.String() != "[::1]:3306" {
		t.Fatalf("v6 loopback = %s", socks[0].Local)
	}
	if socks[1].Remote.String() != "10.0.3.15:51844" || socks[1].State != "ESTABLISHED" {
		t.Fatalf("v4-mapped peer not unmapped: %+v", socks[1])
	}
}

// fakeProc builds <root>/net/tcp, <root>/net/tcp6 and <root>/<pid>/fd/*.
func fakeProc(t *testing.T, tcp string, fds map[uint32][]string) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(header+tcp), 0o644))
	must(os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(header), 0o644))
	for pid, targets := range fds {
		dir := filepath.Join(root, fmt.Sprint(pid), "fd")
		must(os.MkdirAll(dir, 0o755))
		for i, target := range targets {
			must(os.Symlink(target, filepath.Join(dir, fmt.Sprint(i+3))))
		}
	}
	return root
}

func TestForPIDs(t *testing.T) {
	tcp := row(0, v4hex("0.0.0.0", 3306), v4hex("0.0.0.0", 0), "0A", 1001) +
		row(1, v4hex("10.0.1.7", 3306), v4hex("10.0.3.15", 51844), "01", 1002) +
		row(2, v4hex("10.0.1.7", 40000), v4hex("10.0.5.2", 3306), "01", 1003) +
		row(3, v4hex("10.0.1.7", 3306), v4hex("10.0.3.16", 50000), "06", 0) +
		row(4, v4hex("10.0.1.7", 3306), v4hex("10.0.3.17", 50001), "08", 1004)
	root := fakeProc(t, tcp, map[uint32][]string{
		2314: {"socket:[1001]", "socket:[1002]", "socket:[1003]", "socket:[1004]", "socket:[1002]", "/dev/null"},
	})
	got := New(root).ForPIDs([]uint32{2314, 9999}, 50)

	pc := got[2314]
	if pc.Error != "" {
		t.Fatalf("error: %s", pc.Error)
	}
	if len(pc.ListeningPorts) != 1 || pc.ListeningPorts[0] != (modelListen("tcp", "0.0.0.0", 3306)) {
		t.Fatalf("listening = %+v", pc.ListeningPorts)
	}
	want := []string{
		"inbound ESTABLISHED 10.0.3.15:51844 -> 10.0.1.7:3306",
		"outbound ESTABLISHED 10.0.1.7:40000 -> 10.0.5.2:3306",
		"inbound CLOSE_WAIT 10.0.3.17:50001 -> 10.0.1.7:3306",
		"inbound TIME_WAIT 10.0.3.16:50000 -> 10.0.1.7:3306",
	}
	if len(pc.Connections) != len(want) {
		t.Fatalf("connections = %+v", pc.Connections)
	}
	for i, c := range pc.Connections {
		if s := fmt.Sprintf("%s %s %s -> %s", c.Direction, c.State, c.Src, c.Dst); s != want[i] {
			t.Fatalf("conn %d = %q, want %q", i, s, want[i])
		}
	}
	if got[9999].Error == "" {
		t.Fatal("missing pid should report an error")
	}
}

func TestForPIDsCapsAndCountsTruncated(t *testing.T) {
	var tcp strings.Builder
	tcp.WriteString(row(0, v4hex("0.0.0.0", 3306), v4hex("0.0.0.0", 0), "0A", 1))
	fds := []string{"socket:[1]"}
	for i := 0; i < 60; i++ {
		ino := uint64(100 + i)
		tcp.WriteString(row(i+1, v4hex("10.0.1.7", 3306), v4hex("10.0.3.15", uint16(40000+i)), "01", ino))
		fds = append(fds, fmt.Sprintf("socket:[%d]", ino))
	}
	for i := 0; i < 5; i++ {
		tcp.WriteString(row(100+i, v4hex("10.0.1.7", 3306), v4hex("10.0.3.99", uint16(30000+i)), "06", 0))
	}
	root := fakeProc(t, tcp.String(), map[uint32][]string{1: fds})
	pc := New(root).ForPIDs([]uint32{1}, 50)[1]
	if len(pc.Connections) != 50 || pc.Truncated != 15 {
		t.Fatalf("len=%d truncated=%d", len(pc.Connections), pc.Truncated)
	}
	for _, c := range pc.Connections {
		if c.State != "ESTABLISHED" {
			t.Fatalf("ESTABLISHED must sort first, got %s", c.State)
		}
	}
}

func TestListenPorts(t *testing.T) {
	socks := []Socket{
		{State: "LISTEN", Local: netip.MustParseAddrPort("0.0.0.0:3306")},
		{State: "LISTEN", Local: netip.MustParseAddrPort("[::]:3306")},
		{State: "LISTEN", Local: netip.MustParseAddrPort("127.0.0.1:22")},
		{State: "ESTABLISHED", Local: netip.MustParseAddrPort("10.0.0.1:40000")},
	}
	got := ListenPorts(socks)
	if fmt.Sprint(got) != "[22 3306]" {
		t.Fatalf("ListenPorts = %v", got)
	}
}

func modelListen(proto, addr string, port uint16) model.ListenPort {
	return model.ListenPort{Proto: proto, Addr: addr, Port: port}
}
