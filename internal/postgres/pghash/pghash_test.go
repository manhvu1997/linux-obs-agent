package pghash

import (
	"math/rand/v2"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

var corpus = []string{
	"select * from orders where id = 42 and status = 'paid'",
	"select a, b from t where x in (1, 2, 3) and y = 'it''s'",
	`select "Col1", "it's" from "T" where n = 7`,
	"select * from t where id = $1 and name = 'abc' -- 'trailing' 9\n and z = 5",
	"/* tag='x' 12 */ update t set v = v + 10 where k = 'key'",
	"insert into t (a, b) values (1, 'one'), (2, 'two')",
	"select 1.5, 2.25e3, -7 from t1 join t2 on t1.c2 = t2.c3",
	"select * from t where a = any(array[10,20]) limit 50 offset 100",
	"select 'unterminated",
	"select 123",
}

// mutate rewrites every skipped region: digit runs with other digits (any
// length), string contents with bytes that cannot end or escape a string.
func mutate(b []byte, regions []Region, r *rand.Rand) []byte {
	out := append([]byte(nil), b...)
	for i := len(regions) - 1; i >= 0; i-- {
		g := regions[i]
		var rep []byte
		if g.Number {
			for k := 0; k < 1+r.IntN(6); k++ {
				rep = append(rep, byte('0'+r.IntN(10)))
			}
		} else {
			const alpha = "abc XYZ 019;:-()*/=,.?#$"
			for k := 0; k < r.IntN(12); k++ {
				rep = append(rep, alpha[r.IntN(len(alpha))])
			}
		}
		out = append(out[:g.Start], append(rep, out[g.End:]...)...)
	}
	return out
}

// The safety property: two texts the kernel cannot tell apart (they differ
// only inside skipped regions) always normalise to the same digest.
func TestSkippedRegionsKeepHashAndDigest(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, s := range corpus {
		b := []byte(s)
		h := KernelHash(b)
		d := sqldigest.NormalizeDialect(s, sqldigest.Postgres)
		for n := 0; n < 300; n++ {
			m := mutate(b, Regions(b), r)
			if KernelHash(m) != h {
				t.Fatalf("hash changed by a skipped-region mutation:\n %q\n %q", s, m)
			}
			if got := sqldigest.NormalizeDialect(string(m), sqldigest.Postgres); got.ID != d.ID {
				t.Fatalf("kernel merges texts Go distinguishes:\n %q → %q\n %q → %q", s, d.Text, m, got.Text)
			}
		}
	}
}

func TestExactModeTriggers(t *testing.T) {
	// After a backslash, E'…', a dollar quote or a nested comment opener
	// every byte is hashed: different literals give different hashes.
	pairs := [][2]string{
		{`select 'a\' where x = 1`, `select 'a\' where x = 2`},
		{"select E'a' where x = 1", "select E'b' where x = 1"},
		{"select $$a$$ where x = 1", "select $$b$$ where x = 1"},
		{"select $f$a$f$, 1", "select $f$a$f$, 2"},
		{"/* /* n */ 'x' */ select 1", "/* /* n */ 'y' */ select 1"},
	}
	for _, p := range pairs {
		if KernelHash([]byte(p[0])) == KernelHash([]byte(p[1])) {
			t.Errorf("exact mode not entered: %q and %q share a hash", p[0], p[1])
		}
	}
}

func TestLiteralsShareAHash(t *testing.T) {
	a := KernelHash([]byte("select * from t where id = 1 and s = 'x'"))
	b := KernelHash([]byte("select * from t where id = 98765 and s = 'other value'"))
	if a != b {
		t.Fatal("statements differing only in literals must share a hash")
	}
	if KernelHash([]byte("select * from t1")) == KernelHash([]byte("select * from t2")) {
		t.Fatal("digits inside identifiers must be hashed")
	}
}

func TestClipAndZero(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	if KernelHash(long) != KernelHash(long[:MaxText]) {
		t.Fatal("text beyond MaxText must be ignored")
	}
	if KernelHash([]byte("ab\x00cd")) != KernelHash([]byte("ab")) {
		t.Fatal("hash stops at NUL")
	}
	if KernelHash(nil) == 0 || ExactHash(nil) == 0 {
		t.Fatal("0 is reserved for no text")
	}
}
