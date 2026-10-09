package sqlhash

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

func h(s string) uint64 { return KernelHash([]byte(s)) }

// Pairs that MUST share a hash (literals differ only).
func TestSameHash(t *testing.T) {
	for _, p := range [][2]string{
		{"SELECT * FROM t WHERE id = 1", "SELECT * FROM t WHERE id = 42"},
		{"SELECT * FROM t WHERE name = 'bob'", "SELECT * FROM t WHERE name = 'alice'"},
		{`SELECT "x"`, `SELECT "yy"`},
		{"SELECT 'it''s'", "SELECT 'ok'"},
		{`SELECT 'a\'b'`, "SELECT 'zz'"},
		{"SELECT 1.5", "SELECT 2.75"},
		{"SELECT x'AB'", "SELECT x'CDEF'"},
		{"SELECT * FROM t LIMIT 10", "SELECT * FROM t LIMIT 20"},
		{"SELECT -1", "SELECT -7"},
		{"SELECT 'unterminated", "SELECT 'other unterminated"},
	} {
		if h(p[0]) != h(p[1]) {
			t.Errorf("want same hash: %q vs %q", p[0], p[1])
		}
	}
}

// Pairs that MUST differ: the normaliser keeps them apart, or skipping
// would swallow real SQL.
func TestDifferentHash(t *testing.T) {
	for _, p := range [][2]string{
		{"SELECT a FROM t", "SELECT b FROM t"},
		{"SELECT * FROM t1", "SELECT * FROM t2"},         // digits inside identifiers
		{"SELECT `2col` FROM t", "SELECT `3col` FROM t"}, // backtick identifiers
		{"SELECT 1abc FROM t", "SELECT 2abc FROM t"},     // digit run followed by ident char: verbatim
		{"SELECT 0x1F", "SELECT 0x2F"},                   // hex kept verbatim (conservative)
		{"SELECT 1e5", "SELECT 1e6"},                     // exponent kept verbatim (conservative)
		{"SELECT @1", "SELECT @2"},                       // user variables
		{"/* it's */ SELECT a FROM t WHERE x='1'", "/* it's */ SELECT b FROM t WHERE x='1'"},
		{"SELECT a FROM t # it's\nWHERE x=1", "SELECT b FROM t # it's\nWHERE x=1"},
		{"SELECT a -- it's\nFROM t", "SELECT b -- it's\nFROM t"},
		{"SELECT 1", "SELECT  1"}, // whitespace is hashed (more keys, never fewer)
	} {
		if h(p[0]) == h(p[1]) {
			t.Errorf("want different hash: %q vs %q", p[0], p[1])
		}
	}
}

func TestStopsAtNULAndMaxText(t *testing.T) {
	if h("SELECT 1\x00garbage") != h("SELECT 1") {
		t.Error("bytes after NUL must be ignored")
	}
	long := "SELECT '" + strings.Repeat("a", 600)
	if h(long) != KernelHash([]byte(long)[:MaxText]) {
		t.Error("only the first MaxText bytes are hashed")
	}
}

// FuzzEqualHashMeansEqualDigest is the safety property the kernel relies on:
// rewriting only the literals the hash skips never changes the digest.
func FuzzEqualHashMeansEqualDigest(f *testing.F) {
	for _, s := range []string{
		"SELECT * FROM t WHERE id = 1 AND name = 'x'",
		"INSERT INTO t VALUES (1, 'a'), (2, 'b')",
		"/* c */ SELECT `t1`.c2 FROM t1 WHERE a IN (1,2,3) -- x\n",
		"UPDATE t SET a = a + 1 WHERE b = \"q\" # z",
		"SELECT 1.5, .5, -3, 0x10, 1e3, @v1",
	} {
		f.Add(s, int64(1))
	}
	f.Fuzz(func(t *testing.T, s string, seed int64) {
		b := []byte(s)
		if len(b) > MaxText {
			b = b[:MaxText]
		}
		for i, c := range b {
			if c == 0 {
				b = b[:i]
				break
			}
		}
		mutated := mutateSkipped(b, rand.New(rand.NewSource(seed)))
		if len(mutated) > MaxText {
			// The kernel would capture only the first MaxText bytes of the
			// longer text, i.e. a different statement; the property is
			// about texts the kernel sees whole.
			t.Skip("mutation exceeds MaxText")
		}
		if KernelHash(b) != KernelHash(mutated) {
			t.Fatalf("mutating skipped literals changed the hash: %q -> %q", b, mutated)
		}
		if a, m := sqldigest.Normalize(string(b)).ID, sqldigest.Normalize(string(mutated)).ID; a != m {
			t.Fatalf("equal kernel hash but different digest:\n %q\n %q", b, mutated)
		}
	})
}

// mutateSkipped replaces the content of every region KernelHash skips with
// random content of the same kind (digits for numbers, [a-z ] for strings),
// using Regions so the test exercises exactly the hash's own decisions.
func mutateSkipped(b []byte, r *rand.Rand) []byte {
	var out []byte
	last := 0
	for _, rg := range Regions(b) {
		out = append(out, b[last:rg.Start]...)
		n := 1 + r.Intn(4)
		for i := 0; i < n; i++ {
			if rg.Number {
				out = append(out, byte('0'+r.Intn(10)))
			} else {
				out = append(out, "abc xyz"[r.Intn(7)])
			}
		}
		last = rg.End
	}
	return append(out, b[last:]...)
}
