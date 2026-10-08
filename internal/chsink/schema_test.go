package chsink

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite deploy/clickhouse/schema.sql")

const goldenSchema = "../../deploy/clickhouse/schema.sql"

func TestCreateDDLGolden(t *testing.T) {
	got, err := CreateDDL(DefaultSchemaOptions())
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(goldenSchema, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenSchema)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/chsink -run Golden -update)", err)
	}
	if got != string(want) {
		t.Fatal("deploy/clickhouse/schema.sql is stale; run: go test ./internal/chsink -run Golden -update")
	}
}

func TestCreateDDLCustom(t *testing.T) {
	ddl, err := CreateDDL(SchemaOptions{Database: "metrics", RetentionDays: 60, SnapshotRetentionDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE DATABASE IF NOT EXISTS metrics;",
		"CREATE TABLE IF NOT EXISTS metrics.mysql_digest_stats",
		"TTL window_end + INTERVAL 60 DAY",
		"TTL ts + INTERVAL 7 DAY",
		"DateTime('UTC')",
		"ttl_only_drop_parts = 1",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("DDL missing %q", want)
		}
	}
	if strings.Contains(ddl, "{{") {
		t.Error("unreplaced placeholder in DDL")
	}
}

func TestAlterTTLDDL(t *testing.T) {
	ddl, err := AlterTTLDDL(SchemaOptions{Database: "obs", RetentionDays: 90, SnapshotRetentionDays: 3})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(ddl, "ALTER TABLE"); n != 5 {
		t.Fatalf("ALTER statements = %d, want 5 (every table but mysql_digest_text)\n%s", n, ddl)
	}
	for _, want := range []string{
		"ALTER TABLE obs.mysql_digest_stats MODIFY TTL window_end + INTERVAL 90 DAY;",
		"ALTER TABLE obs.mysql_slow_queries MODIFY TTL toDateTime(ts) + INTERVAL 90 DAY;",
		"ALTER TABLE obs.diagnose_snapshots MODIFY TTL ts + INTERVAL 3 DAY;",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(ddl, "mysql_digest_text") {
		t.Error("mysql_digest_text has no TTL and must not be altered")
	}
}

func TestParseRetentionDays(t *testing.T) {
	for in, want := range map[string]int{"30d": 30, "1d": 1, "3650d": 3650} {
		if got, err := ParseRetentionDays(in); err != nil || got != want {
			t.Errorf("ParseRetentionDays(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"0d", "-1d", "30", "30h", "abc", "", "3651d"} {
		if _, err := ParseRetentionDays(in); err == nil {
			t.Errorf("ParseRetentionDays(%q) accepted", in)
		}
	}
}

func TestRunSchemaCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := RunSchemaCommand([]string{"-database", "x", "-retention", "10d"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "CREATE TABLE IF NOT EXISTS x.family_stats") || !strings.Contains(out.String(), "INTERVAL 10 DAY") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
	out.Reset()
	if code := RunSchemaCommand([]string{"-alter"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "ALTER TABLE obs.") {
		t.Fatalf("-alter: exit %d out %s", code, out.String())
	}
	errb.Reset()
	if code := RunSchemaCommand([]string{"-database", "bad-name"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "database") {
		t.Fatalf("bad database: exit %d stderr %q", code, errb.String())
	}
}
