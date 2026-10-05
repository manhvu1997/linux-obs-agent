//go:build linux && ebpf_integration

package netflow

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"

	nf "github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

func flowsFor(t *testing.T, l *Loader, port uint16) (out, in nf.FlowValue) {
	t.Helper()
	flows, err := l.ReadFlows()
	if err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getpid())
	for k, v := range flows {
		if k.TGID != me || k.ServicePort != port {
			continue
		}
		dst := &out
		if k.Dir == nf.Inbound {
			dst = &in
		}
		dst.BytesTx += v.BytesTx
		dst.BytesRx += v.BytesRx
		dst.Opened += v.Opened
		dst.Closed += v.Closed
	}
	return out, in
}

func start(t *testing.T) (*Loader, net.Listener, uint16) {
	t.Helper()
	l := NewLoader(true)
	if err := l.Start(); err != nil {
		t.Fatalf("start (run as root): %v", err)
	}
	t.Cleanup(l.Stop)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if err := l.SetListenPorts([]uint16{port}); err != nil {
		t.Fatal(err)
	}
	return l, ln, port
}

func TestTransferIsCounted(t *testing.T) {
	l, ln, port := start(t)
	payload := bytes.Repeat([]byte("x"), 1<<20)
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
		close(done)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-done
	time.Sleep(500 * time.Millisecond) // FIN handshake → CLOSE transitions

	out, in := flowsFor(t, l, port)
	if out.BytesTx != 1<<20 || in.BytesRx != 1<<20 {
		t.Fatalf("bytes: out.tx=%d in.rx=%d, want %d", out.BytesTx, in.BytesRx, 1<<20)
	}
	if out.Opened != 1 || in.Opened != 1 || out.Closed != 1 || in.Closed != 1 {
		t.Fatalf("conns: out=%+v in=%+v", out, in)
	}
}

func TestShortLivedConnectionsAreCounted(t *testing.T) {
	l, ln, port := start(t)
	const n = 1000
	go func() {
		for i := 0; i < n; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2)
		io.ReadFull(c, buf)
		c.Close()
	}
	time.Sleep(time.Second)
	out, in := flowsFor(t, l, port)
	if out.Opened != n || in.Opened != n || out.Closed != n || in.Closed != n {
		t.Fatalf("out=%+v in=%+v, want %d opened/closed each", out, in, n)
	}
	if out.BytesRx != 2*n || in.BytesTx != 2*n {
		t.Fatalf("bytes out.rx=%d in.tx=%d", out.BytesRx, in.BytesTx)
	}
}
