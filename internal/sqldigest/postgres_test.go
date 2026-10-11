package sqldigest

import "testing"

func TestNormalizePostgres(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT * FROM t WHERE id = 42", "select * from t where id = ?"},
		{`select $1::int, E'a\'b', $$x'y$$, $tag$ a $ b $tag$, B'101', X'1F', U&'d\0061'`,
			"select ? :: int , ? , ? , ? , ? , ? , ?"},
		{`SELECT "MyCol" FROM "Tbl"`, `select "MyCol" from "Tbl"`},
		{`SELECT "it''s" FROM t`, `select "it''s" from t`},
		{"select a # b from t", "select a # b from t"},
		{"/* outer /* inner */ still */ select 1", "select ?"},
		{"select 1 -- c\n, 2", "select ? , ?"},
		{"select 1 --c\n, 2", "select ? , ?"},
		{"select * from t where id in ($1, $2, $3)", "select * from t where id in ( ?+ )"},
		{"select * from t where id = any(array[1,2,3])", "select * from t where id = any ( array [ ?+ ] )"},
		{"insert into t values (1,'a'),(2,'b')", "insert into t values ( ?+ )"},
		{"select 1_000_000, 0x1F, 1.5e3", "select ? , ? , ?"},
		{"select 'abc", "select ?"},
		{"select $q$abc", "select ?"},
		{"select a->>'k', b @> '{}', c::text", "select a ->> ? , b @> ? , c :: text"},
		{"SELECT x FROM t WHERE y = -5", "select x from t where y = ?"},
		{"select a$b from t", "select a$b from t"},
		{"SELECT TRUE, NULL", "select ? , ?"},
	}
	for _, c := range cases {
		got := NormalizeDialect(c.in, Postgres)
		if got.Text != c.want || !got.Normalized {
			t.Errorf("NormalizeDialect(%q)\n got  %q (normalized=%v)\n want %q", c.in, got.Text, got.Normalized, c.want)
		}
		if got.ID != HashID(got.Text) {
			t.Errorf("%q: ID is not HashID(Text)", c.in)
		}
	}
}

func TestNormalizeDialectMySQLIsNormalize(t *testing.T) {
	for _, s := range []string{"select `a` from t where b = 'x' # c", `select "str" from t`} {
		if NormalizeDialect(s, MySQL) != Normalize(s) {
			t.Errorf("MySQL dialect differs from Normalize for %q", s)
		}
	}
}

func TestReferencesSystemCatalog(t *testing.T) {
	cases := map[string]bool{
		"select * from pg_catalog . pg_class":                  true,
		"select * from information_schema . tables":            true,
		"select * from pg_stat_activity":                       true,
		"select * from t join pg_locks l on l . pid = t . pid": true,
		"select pg_sleep ( ? )":                                false,
		"select pg_catalog from t":                             false,
		"select * from orders where status = ?":                false,
		"select * from public . pg_like_name":                  false,
	}
	for in, want := range cases {
		if got := ReferencesSystemCatalog(in); got != want {
			t.Errorf("ReferencesSystemCatalog(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizePostgresNeverPanics(t *testing.T) {
	for _, s := range []string{"", "$", "$$", "'", `"`, "/*", "/* /*", "E'", "U&'", "\x00\xff", "$1$2$", "--"} {
		_ = NormalizeDialect(s, Postgres)
	}
}
