package cmdmap

import (
	"strings"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func TestClassifyQuery(t *testing.T) {
	class, d, sample, trunc := Classify(ComQuery, "SELECT * FROM t WHERE id = 5", 28, false)
	if class != "query" || d.Text != "select * from t where id = ?" || sample != "SELECT * FROM t WHERE id = 5" || trunc {
		t.Fatalf("got %q %+v %q %v", class, d, sample, trunc)
	}
}

func TestClassifyTruncated(t *testing.T) {
	q := "SELECT '" + strings.Repeat("x", 600)
	for _, cmd := range []uint32{ComQuery, ComStmtPrepare, ComStmtExecute} {
		if _, _, _, trunc := Classify(cmd, q[:511], uint32(len(q)), true); !trunc {
			t.Fatalf("command %d: text longer than the capture buffer must be marked truncated", cmd)
		}
		if _, _, _, trunc := Classify(cmd, q[:511], 511, true); trunc {
			t.Fatalf("command %d: a 511-byte text fits exactly and is not truncated", cmd)
		}
	}
}

func TestClassifyExecuteWithTextSharesQueryDigest(t *testing.T) {
	const text = "SELECT c FROM sbtest1 WHERE id = ?"
	class, d, sample, trunc := Classify(ComStmtExecute, text, uint32(len(text)), true)
	_, q, _, _ := Classify(ComQuery, text, uint32(len(text)), true)
	if class != "stmt_execute" || d.ID != q.ID || d.Text != "select c from sbtest1 where id = ?" || sample != text || trunc {
		t.Fatalf("got %q %+v %q %v (query digest %+v)", class, d, sample, trunc, q)
	}
}

func TestClassifyExecuteWithoutText(t *testing.T) {
	_, on, sOn, _ := Classify(ComStmtExecute, "", 0, true)
	_, off, sOff, _ := Classify(ComStmtExecute, "", 0, false)
	if on.Text != "<COM_STMT_EXECUTE: prepared before agent start, text unavailable>" || on.ID != sqldigest.HashID(on.Text) || sOn != "" {
		t.Fatalf("tracking on: %+v %q", on, sOn)
	}
	if off.Text != "<COM_STMT_EXECUTE: prepared, text unavailable>" || off.ID != sqldigest.HashID(off.Text) || sOff != "" {
		t.Fatalf("tracking off: %+v %q", off, sOff)
	}
}

func TestClassifyPrepare(t *testing.T) {
	const text = "SELECT c FROM sbtest1 WHERE id = ?"
	class, d, sample, _ := Classify(ComStmtPrepare, text, uint32(len(text)), true)
	_, q, _, _ := Classify(ComQuery, text, uint32(len(text)), true)
	if class != "stmt_prepare" || d.Text != "prepare: select c from sbtest1 where id = ?" ||
		d.ID != sqldigest.HashID(d.Text) || d.ID == q.ID || !d.Normalized || sample != text {
		t.Fatalf("got %q %+v %q", class, d, sample)
	}
	class, d, sample, _ = Classify(ComStmtPrepare, "", 0, true)
	if class != "stmt_prepare" || d.Text != "<COM_STMT_PREPARE>" || sample != "" {
		t.Fatalf("empty prepare: %q %+v %q", class, d, sample)
	}
}

func TestClassifyOtherCommandNames(t *testing.T) {
	cases := map[uint32]string{
		0: "<COM_SLEEP>", 1: "<COM_QUIT>", 2: "<COM_INIT_DB>", 14: "<COM_PING>",
		7: "<COM_REFRESH>", 25: "<COM_STMT_CLOSE>", 31: "<COM_RESET_CONNECTION>", 32: "<COM_CLONE>",
		33: "<COM_SUBSCRIBE_GROUP_REPLICATION_STREAM>",
		99: "<COM command 99>",
	}
	for cmd, want := range cases {
		class, d, sample, trunc := Classify(cmd, "", 0, true)
		if class != "other" || d.Text != want || d.ID != sqldigest.HashID(want) || sample != "" || trunc {
			t.Errorf("command %d: got %q %+v %q %v, want %q", cmd, class, d, sample, trunc, want)
		}
	}
}

func TestClassifyEmptyQuery(t *testing.T) {
	_, a, _, _ := Classify(ComQuery, "", 0, false)
	_, b, _, _ := Classify(ComQuery, "   \n", 4, false)
	if a.Text != "<empty query>" || a.ID != b.ID {
		t.Fatalf("empty queries must share a stable placeholder digest: %+v %+v", a, b)
	}
}

func TestClassifySampleIsValidUTF8(t *testing.T) {
	for _, cmd := range []uint32{ComQuery, ComStmtPrepare, ComStmtExecute} {
		_, _, sample, _ := Classify(cmd, "SELECT 'ab\xe1\xbb", 13, true)
		if strings.ContainsRune(sample, '�') || !strings.HasSuffix(sample, "?") {
			t.Fatalf("command %d: sample = %q", cmd, sample)
		}
	}
}

func TestSlowQueryText(t *testing.T) {
	cases := []struct {
		command  uint32
		query    string
		tracking bool
		want     string
	}{
		{ComQuery, "SELECT SLEEP(1)", true, "SELECT SLEEP(1)"},
		{ComStmtExecute, "SELECT c FROM t WHERE id = ?", true, "SELECT c FROM t WHERE id = ?"},
		{ComStmtExecute, "", true, "<COM_STMT_EXECUTE: prepared before agent start, text unavailable>"},
		{ComStmtExecute, "", false, "<COM_STMT_EXECUTE: prepared, text unavailable>"},
		{ComQuery, "", true, "<empty query>"},
		{ComQuery, "  ", false, "<empty query>"},
	}
	for _, c := range cases {
		if got := SlowQueryText(c.command, c.query, c.tracking); got != c.want {
			t.Errorf("SlowQueryText(%d, %q, %v) = %q, want %q", c.command, c.query, c.tracking, got, c.want)
		}
	}
}
