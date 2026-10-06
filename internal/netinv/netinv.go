// Package netinv builds an on-demand TCP socket inventory from /proc:
// listening ports and live connections per process, mapped through
// /proc/<pid>/fd socket inodes. It runs only when /api/diagnose is called
// (plus a cheap LISTEN-only read used by netflow), so it costs nothing
// between calls.
package netinv

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Socket is one row of /proc/net/tcp or /proc/net/tcp6.
type Socket struct {
	Proto  string // "tcp" | "tcp6"
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  string
	Inode  uint64 // 0 for TIME_WAIT (no owning file)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// ParseNetTCP parses the /proc/net/tcp{,6} format. Malformed rows are skipped.
func ParseNetTCP(r io.Reader, proto string) ([]Socket, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []Socket
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err := parseHexAddrPort(f[1])
		if err != nil {
			continue
		}
		remote, err := parseHexAddrPort(f[2])
		if err != nil {
			continue
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		st, ok := tcpStates[strings.ToUpper(f[3])]
		if !ok {
			st = "UNKNOWN"
		}
		out = append(out, Socket{Proto: proto, Local: local, Remote: remote, State: st, Inode: inode})
	}
	return out, sc.Err()
}

// parseHexAddrPort decodes "0100007F:0CEA". The kernel prints the address as
// host-endian 32-bit words (little-endian on x86/arm64); the port is plain hex.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("netinv: bad address %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ip netip.Addr
	switch len(raw) {
	case 4:
		ip = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			for k := 0; k < 4; k++ {
				b[w*4+k] = raw[w*4+3-k]
			}
		}
		ip = netip.AddrFrom16(b).Unmap()
	default:
		return netip.AddrPort{}, fmt.Errorf("netinv: bad address length %q", s)
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// Inventory reads sockets under a proc root ("/proc" in production).
type Inventory struct{ root string }

func New(procRoot string) *Inventory {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Inventory{root: procRoot}
}

// Sockets returns all TCP sockets in pid 1's network namespace.
//
// <root>/net resolves to <root>/self/net, the agent's OWN namespace; in a pod
// with hostNetwork: false that is the pod's, not the host's. With hostPID,
// <root>/1/net is the init process's (host) namespace, so it is preferred.
// If it cannot be opened (no hostPID, permission, not found) the agent's own
// namespace is used instead. Sockets of processes in other network
// namespaces (containers with their own netns) are never listed; their
// traffic is still counted by the netflow eBPF module.
func (v *Inventory) Sockets() ([]Socket, error) {
	base := filepath.Join(v.root, "1")
	if f, err := os.Open(filepath.Join(base, "net", "tcp")); err == nil {
		f.Close()
	} else {
		base = v.root
	}
	var all []Socket
	for _, p := range []struct{ file, proto string }{{"net/tcp", "tcp"}, {"net/tcp6", "tcp6"}} {
		f, err := os.Open(filepath.Join(base, p.file))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		socks, err := ParseNetTCP(f, p.proto)
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
	}
	return all, nil
}

// Listening returns LISTEN sockets only.
func (v *Inventory) Listening() ([]Socket, error) {
	all, err := v.Sockets()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, s := range all {
		if s.State == "LISTEN" {
			out = append(out, s)
		}
	}
	return out, nil
}

// ListenPorts returns the distinct local ports of the LISTEN sockets, ascending.
func ListenPorts(socks []Socket) []uint16 {
	seen := make(map[uint16]bool)
	var out []uint16
	for _, s := range socks {
		if s.State != "LISTEN" || seen[s.Local.Port()] {
			continue
		}
		seen[s.Local.Port()] = true
		out = append(out, s.Local.Port())
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ForPIDs returns listening ports and live connections for each pid.
// Connections are sorted ESTABLISHED, CLOSE_WAIT, TIME_WAIT, others and
// capped at maxConns (Truncated counts the rest). A connection is inbound when
// its local port is any LISTEN port on the host. TIME_WAIT sockets have no
// owning fd; they are attributed (as inbound) to processes that listen on
// their local port, otherwise omitted.
func (v *Inventory) ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections {
	out := make(map[uint32]model.ProcessConnections, len(pids))
	socks, err := v.Sockets()
	if err != nil {
		for _, p := range pids {
			out[p] = model.ProcessConnections{Error: err.Error()}
		}
		return out
	}
	byInode := make(map[uint64]Socket, len(socks))
	hostListen := make(map[uint16]bool)
	var timeWait []Socket
	for _, s := range socks {
		if s.Inode != 0 {
			byInode[s.Inode] = s
		}
		switch s.State {
		case "LISTEN":
			hostListen[s.Local.Port()] = true
		case "TIME_WAIT":
			timeWait = append(timeWait, s)
		}
	}
	for _, pid := range pids {
		if _, done := out[pid]; done {
			continue
		}
		out[pid] = v.forPID(pid, byInode, hostListen, timeWait, maxConns)
	}
	return out
}

func (v *Inventory) forPID(pid uint32, byInode map[uint64]Socket, hostListen map[uint16]bool,
	timeWait []Socket, maxConns int) model.ProcessConnections {
	pc := model.ProcessConnections{ListeningPorts: []model.ListenPort{}, Connections: []model.Connection{}}
	inodes, err := socketInodes(filepath.Join(v.root, strconv.FormatUint(uint64(pid), 10), "fd"))
	if err != nil {
		pc.Error = err.Error()
		return pc
	}
	ownListen := make(map[uint16]bool)
	seenListen := make(map[model.ListenPort]bool)
	var conns []model.Connection
	for _, ino := range inodes {
		s, ok := byInode[ino]
		if !ok {
			continue
		}
		if s.State == "LISTEN" {
			lp := model.ListenPort{Proto: s.Proto, Addr: s.Local.Addr().String(), Port: s.Local.Port()}
			if !seenListen[lp] {
				seenListen[lp] = true
				pc.ListeningPorts = append(pc.ListeningPorts, lp)
			}
			ownListen[s.Local.Port()] = true
			continue
		}
		conns = append(conns, toConnection(s, hostListen[s.Local.Port()]))
	}
	for _, s := range timeWait {
		if ownListen[s.Local.Port()] {
			conns = append(conns, toConnection(s, true))
		}
	}
	sort.SliceStable(conns, func(i, j int) bool { return stateRank(conns[i].State) < stateRank(conns[j].State) })
	if maxConns > 0 && len(conns) > maxConns {
		pc.Truncated = len(conns) - maxConns
		conns = conns[:maxConns]
	}
	if conns != nil {
		pc.Connections = conns
	}
	sort.Slice(pc.ListeningPorts, func(i, j int) bool {
		a, b := pc.ListeningPorts[i], pc.ListeningPorts[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Addr < b.Addr
	})
	return pc
}

func toConnection(s Socket, inbound bool) model.Connection {
	if inbound {
		return model.Connection{Direction: "inbound", State: s.State, Src: s.Remote.String(), Dst: s.Local.String()}
	}
	return model.Connection{Direction: "outbound", State: s.State, Src: s.Local.String(), Dst: s.Remote.String()}
}

func stateRank(st string) int {
	switch st {
	case "ESTABLISHED":
		return 0
	case "CLOSE_WAIT":
		return 1
	case "TIME_WAIT":
		return 2
	}
	return 3
}

// socketInodes returns the distinct socket inodes referenced by fdDir.
func socketInodes(fdDir string) ([]uint64, error) {
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	seen := make(map[uint64]bool)
	var out []uint64
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		ino, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
		if err != nil || seen[ino] {
			continue
		}
		seen[ino] = true
		out = append(out, ino)
	}
	return out, nil
}
