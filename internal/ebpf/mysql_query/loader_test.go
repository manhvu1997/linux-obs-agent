package mysql_query

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func TestLoadLiteralSkipFallback(t *testing.T) {
	verr := &ebpf.VerifierError{Cause: errors.New("program too large"), Log: []string{"BPF program is too large"}}
	other := errors.New("map create: operation not permitted")

	t.Run("first load succeeds", func(t *testing.T) {
		var loads, disables int
		skip, err := loadLiteralSkipFallback(
			func() error { loads++; return nil },
			func() error { disables++; return nil })
		if err != nil || !skip || loads != 1 || disables != 0 {
			t.Fatalf("skip=%v err=%v loads=%d disables=%d", skip, err, loads, disables)
		}
	})

	t.Run("verifier error retries once without literal skipping", func(t *testing.T) {
		var loads, disables int
		skip, err := loadLiteralSkipFallback(
			func() error {
				loads++
				if disables == 0 {
					return verr
				}
				return nil
			},
			func() error { disables++; return nil })
		if err != nil || skip || loads != 2 || disables != 1 {
			t.Fatalf("skip=%v err=%v loads=%d disables=%d", skip, err, loads, disables)
		}
	})

	t.Run("wrapped verifier error is recognised", func(t *testing.T) {
		var loads int
		skip, err := loadLiteralSkipFallback(
			func() error {
				loads++
				if loads == 1 {
					return errors.Join(errors.New("field UretprobeDispatchCommand"), verr)
				}
				return nil
			},
			func() error { return nil })
		if err != nil || skip || loads != 2 {
			t.Fatalf("skip=%v err=%v loads=%d", skip, err, loads)
		}
	})

	t.Run("other errors are not retried", func(t *testing.T) {
		var loads, disables int
		_, err := loadLiteralSkipFallback(
			func() error { loads++; return other },
			func() error { disables++; return nil })
		if !errors.Is(err, other) || loads != 1 || disables != 0 {
			t.Fatalf("err=%v loads=%d disables=%d", err, loads, disables)
		}
	})

	t.Run("retry failure is returned", func(t *testing.T) {
		var loads int
		_, err := loadLiteralSkipFallback(
			func() error { loads++; return verr },
			func() error { return nil })
		var ve *ebpf.VerifierError
		if err == nil || !errors.As(err, &ve) || loads != 2 {
			t.Fatalf("err=%v loads=%d", err, loads)
		}
	})

	t.Run("disable failure returns the verifier error", func(t *testing.T) {
		var loads int
		_, err := loadLiteralSkipFallback(
			func() error { loads++; return verr },
			func() error { return errors.New("no variable literal_skip") })
		var ve *ebpf.VerifierError
		if !errors.As(err, &ve) || loads != 1 {
			t.Fatalf("err=%v loads=%d", err, loads)
		}
	})
}

// fakeReader replays errs, then returns ringbuf.ErrClosed.
type fakeReader struct {
	reads atomic.Int32
	next  func(n int32) (ringbuf.Record, error)
}

func (f *fakeReader) Read() (ringbuf.Record, error) { return f.next(f.reads.Add(1)) }

func TestReadLoopStopsOnClose(t *testing.T) {
	f := &fakeReader{next: func(n int32) (ringbuf.Record, error) {
		switch n {
		case 1:
			return ringbuf.Record{RawSample: []byte{1}}, nil
		case 2:
			return ringbuf.Record{}, os.ErrDeadlineExceeded // not an error worth backing off on
		case 3:
			return ringbuf.Record{RawSample: []byte{2}}, nil
		}
		return ringbuf.Record{}, ringbuf.ErrClosed
	}}
	var got []byte
	done := make(chan struct{})
	start := time.Now()
	go func() {
		readLoop(context.Background(), f, "test", func(b []byte) { got = append(got, b...) })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop did not return after ErrClosed")
	}
	if string(got) != "\x01\x02" {
		t.Fatalf("handled %v", got)
	}
	if time.Since(start) >= readErrorBackoff {
		t.Fatalf("ErrDeadlineExceeded must not back off (took %v)", time.Since(start))
	}
}

// A persistent read error must not spin: the loop backs off and still
// honours ctx cancellation promptly.
func TestReadLoopBacksOffOnError(t *testing.T) {
	f := &fakeReader{next: func(int32) (ringbuf.Record, error) {
		return ringbuf.Record{}, errors.New("EIO")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		readLoop(ctx, f, "test", func([]byte) { t.Error("handle called on error") })
		close(done)
	}()
	time.Sleep(3*readErrorBackoff + readErrorBackoff/2)
	cancel()
	select {
	case <-done:
	case <-time.After(readErrorBackoff + time.Second):
		t.Fatal("readLoop ignored ctx cancellation while backing off")
	}
	if n := f.reads.Load(); n < 2 || n > 6 {
		t.Fatalf("%d reads in ~3.5 backoff periods; want a few (no spinning)", n)
	}
}
