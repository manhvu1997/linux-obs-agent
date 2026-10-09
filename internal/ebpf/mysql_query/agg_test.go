package mysql_query

import (
	"encoding/binary"
	"testing"
)

func TestDecodeTextEvent(t *testing.T) {
	b := make([]byte, textEventSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 0x1122334455667788)
	le.PutUint32(b[8:], 23)
	le.PutUint32(b[12:], 600)
	le.PutUint32(b[16:], 1)
	copy(b[24:], "SELECT ? + 41\x00stale")
	ev, ok := decodeTextEvent(b)
	if !ok || ev.Hash != 0x1122334455667788 || ev.Command != 23 || ev.QueryLen != 600 || !ev.Verify || ev.Query != "SELECT ? + 41" {
		t.Fatalf("got %+v, %v", ev, ok)
	}
	if _, ok := decodeTextEvent(b[:10]); ok {
		t.Fatal("short record accepted")
	}
}

// DrainAgg and the text/unsafe maps read the generated mirror types with
// reflection-free fixed sizes; they must match the C structs (16, 64, 16).
func TestAggTypeSizesMatchGenerated(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"agg_key_t", binary.Size(MysqlQueryAggKeyT{}), 16},
		{"agg_val_t", binary.Size(MysqlQueryAggValT{}), 64},
		{"text_key_t", binary.Size(MysqlQueryTextKeyT{}), 16},
	} {
		if c.got != c.want {
			t.Errorf("binary.Size(%s mirror) = %d, want %d", c.name, c.got, c.want)
		}
	}
}
