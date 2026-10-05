// internal/sqldigest/sqldigest_test.go
package sqldigest

import (
	"testing"
	"unicode/utf8"
)

func TestNormalize(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"literal int", "SELECT * FROM users WHERE id = 42", "select * from users where id = ?"},
		{"escaped strings", `SELECT 'it\'s', "a""b" FROM t`, "select ? , ? from t"},
		{"in list", "SELECT a FROM t WHERE id IN (1, 2, 3)", "select a from t where id in ( ?+ )"},
		{"in single", "SELECT a FROM t WHERE id IN (9)", "select a from t where id in ( ?+ )"},
		{"values rows", "INSERT INTO t (a,b) VALUES (1,'x'),(2,'y')", "insert into t ( a , b ) values ( ?+ )"},
		{"values with expr kept", "INSERT INTO t (a,b) VALUES (1, NOW())", "insert into t ( a , b ) values ( ? , now ( ) )"},
		{"block and line comments", "/* app:42 */ SELECT 1 -- trailing\n", "select ?"},
		{"hash comment", "# c\nSELECT 1", "select ?"},
		{"backticks keep case", "SELECT `UserName` FROM `Users`", "select `UserName` from `Users`"},
		{"hex bit float", "SELECT 0x1F, X'0A', b'101', 1.5e-3, .5", "select ? , ? , ? , ? , ?"},
		{"bool and null", "UPDATE t SET a = NULL, b = TRUE", "update t set a = ? , b = ?"},
		{"truncated literal", "SELECT * FROM t WHERE name = 'abc", "select * from t where name = ?"},
		{"truncated in list", "SELECT * FROM t WHERE id IN (1, 2", "select * from t where id in ( ? , ?"},
		{"operators", "SELECT a FROM t WHERE a<=>1 AND b!=2", "select a from t where a <=> ? and b != ?"},
		{"unicode", "SELECT * FROM t WHERE name = 'Nguyễn' AND cột = 1", "select * from t where name = ? and cột = ?"},
		{"group by", "SELECT status, COUNT(*) FROM orders WHERE created_at > '2026-10-01' GROUP BY status",
			"select status , count ( * ) from orders where created_at > ? group by status"},
		{"empty", "", ""},
		{"negative in list", "SELECT a FROM t WHERE id IN (-1, -2, 3)", "select a from t where id in ( ?+ )"},
		{"negative values rows", "INSERT INTO t (a,b) VALUES (1,-5),(2,3)", "insert into t ( a , b ) values ( ?+ )"},
		{"negative comparison", "SELECT * FROM t WHERE x = -5", "select * from t where x = ?"},
		{"binary minus kept", "SELECT a-1, 5 -1 FROM t", "select a - ? , ? - ? from t"},
		{"plus unary", "SELECT * FROM t WHERE x > +7", "select * from t where x > ?"},
		{"binary minus after ident digits", "SELECT t1-1 FROM t", "select t1 - ? from t"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Normalize(c.in)
			if d.Text != c.want {
				t.Fatalf("Normalize(%q).Text = %q, want %q", c.in, d.Text, c.want)
			}
			if !d.Normalized {
				t.Fatalf("Normalized = false for %q", c.in)
			}
			if len(d.ID) != 16 || d.ID != HashID(d.Text) {
				t.Fatalf("ID = %q, want HashID(Text)", d.ID)
			}
		})
	}
}

func TestSameShapeSameID(t *testing.T) {
	a := Normalize("SELECT * FROM users WHERE id = 42")
	b := Normalize("select *   from users where id=7")
	if a.ID != b.ID {
		t.Fatalf("IDs differ: %q vs %q (%q vs %q)", a.ID, b.ID, a.Text, b.Text)
	}
}

func TestNormalizeInvalidUTF8(t *testing.T) {
	// Query truncated at the capture limit in the middle of "ễ" (3 bytes).
	d := Normalize("SELECT 1 FROM t\xe1\xbb")
	if !utf8.ValidString(d.Text) {
		t.Fatalf("Text is not valid UTF-8: %q", d.Text)
	}
	if d.Text != "select ? from t ?" {
		t.Fatalf("Text = %q", d.Text)
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"SELECT 1", "x'", "`", "/*", "IN (", "VALUES (?,", "\xff\xfe", "'\\", "-", "+", "--", "1-", "\\"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d := Normalize(s)
		if !utf8.ValidString(d.Text) {
			t.Fatalf("invalid UTF-8 output for %q: %q", s, d.Text)
		}
		if len(d.ID) != 16 {
			t.Fatalf("bad ID %q", d.ID)
		}
	})
}
