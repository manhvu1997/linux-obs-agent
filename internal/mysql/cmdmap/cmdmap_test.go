package cmdmap

import (
	"strings"
	"testing"
)

func TestClassifyQuery(t *testing.T) {
	class, d, sample, trunc := Classify(ComQuery, "SELECT * FROM t WHERE id = 5", 28)
	if class != "query" || d.Text != "select * from t where id = ?" || sample != "SELECT * FROM t WHERE id = 5" || trunc {
		t.Fatalf("got %q %+v %q %v", class, d, sample, trunc)
	}
}

func TestClassifyTruncated(t *testing.T) {
	q := "SELECT '" + strings.Repeat("x", 600)
	_, _, _, trunc := Classify(ComQuery, q[:511], uint32(len(q)))
	if !trunc {
		t.Fatal("query longer than the capture buffer must be marked truncated")
	}
	if _, _, _, trunc := Classify(ComQuery, q[:511], 511); trunc {
		t.Fatal("a 511-byte query fits exactly and is not truncated")
	}
}

func TestClassifyPreparedAndOther(t *testing.T) {
	class, d, _, _ := Classify(ComStmtExecute, "", 0)
	if class != "stmt_execute" || d.Text != "<COM_STMT_EXECUTE: prepared, text unavailable>" {
		t.Fatalf("got %q %q", class, d.Text)
	}
	class, d, _, _ = Classify(14, "", 0) // COM_PING
	if class != "other" || d.Text != "<COM command 14>" {
		t.Fatalf("got %q %q", class, d.Text)
	}
}

func TestClassifyEmptyQuery(t *testing.T) {
	_, a, _, _ := Classify(ComQuery, "", 0)
	_, b, _, _ := Classify(ComQuery, "   \n", 4)
	if a.Text != "<empty query>" || a.ID != b.ID {
		t.Fatalf("empty queries must share a stable placeholder digest: %+v %+v", a, b)
	}
}

func TestClassifySampleIsValidUTF8(t *testing.T) {
	_, _, sample, _ := Classify(ComQuery, "SELECT 'ab\xe1\xbb", 13)
	if strings.ContainsRune(sample, '�') || !strings.HasSuffix(sample, "?") {
		t.Fatalf("sample = %q", sample)
	}
}
