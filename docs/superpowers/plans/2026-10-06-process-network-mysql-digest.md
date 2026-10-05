# Process Families, Network Flows & MySQL Query Digests — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `/api/diagnose` and `/metrics` so an operator can see the top processes and systemd-unit process families by CPU/memory with their inbound/outbound connections and bytes, and can tell the MySQL query pattern that *causes* high CPU apart from the queries that are merely slowed by it.

**Architecture:** Two always-on eBPF programs feed pure-Go aggregation packages: a new `netflow` module counts TCP bytes/connections per (process, direction, peer, service port), and the existing `mysql_query` uprobe is extended to measure per-command CPU time, run-queue wait and bytes, emitting one ring-buffer event per command. Userspace normalises SQL into digests, aggregates them in a rolling window, groups processes into families by systemd unit, and builds an on-demand connection inventory from `/proc`. All logic lives in packages that depend on interfaces, so it is unit-tested on any OS; eBPF packages are thin loaders verified on a Linux build host.

**Tech Stack:** Go 1.26, cilium/ebpf v0.21 + bpf2go, eBPF C (CO-RE, kprobes, uprobes, tracepoints), prometheus/client_golang v1.20 (`testutil`), `net/netip`.

**Spec:** `docs/superpowers/specs/2026-10-06-process-network-mysql-digest-design.md`

## Global Constraints

- Go 1.26, `CGO_ENABLED=0`, static binary. **No new module dependencies** — `prometheus/client_golang/prometheus/testutil` is already in the required module.
- Kernel ≥ 5.4 with BTF. eBPF programs are **x86_64 only** (the existing `struct x86_regs` cast pattern from `mysql_query.bpf.c`; `gen.go` hard-codes `-D__TARGET_ARCH_x86`).
- eBPF packages compile **only on a Linux build host** after `make generate` (needs clang, bpftool, `/sys/kernel/btf/vmlinux`). Generated `*_bpfel.go`, `*_bpfeb.go`, `*_bpfel.o`, `*_bpfeb.o` are **not committed** — always `git add` explicit paths, never `git add -A`.
- Pure packages (`internal/sqldigest`, `internal/querystats`, `internal/mysql/cmdmap`, `internal/process`, `internal/netinv`, `internal/netflow`, `internal/procreport`, `internal/promcollect`, `internal/config`) must **not** import any `internal/ebpf/...` package, so `go test` works on macOS.
- Metric prefix `obs_agent_`. Never label by PID, client port, or raw SQL. Caps: `netflow.max_families` 50, `netflow.max_outbound_peers` 100, `mysql.sticky_digests_max` 50; overflow → `"other"`.
- Report caps: `process.report_top_n` 10, `process.max_connections_per_process` 50, `process.max_peers_per_process` 20, `mysql.top_digests` 20, bytes-out ranking 10.
- `mysql.enabled` stays default **false**; `netflow.enabled` default **true**. Existing `process.top_n` (20) and `top_processes` are unchanged.
- Query text capture: 512 bytes (`QUERY_MAX`), so ≤ 511 SQL bytes + NUL.
- Every task ends with a Codex review per CLAUDE.md §20.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Invalid UTF-8 in SQL text** (query cut at byte 511 in the middle of a multi-byte character, or binary literals) → digest text, sample query and the `digest_text` Prometheus label must be valid UTF-8; a bad label value makes `MustNewConstMetric` panic and fails the **entire** `/metrics` scrape. Tests: Task 1 (`TestNormalizeInvalidUTF8`, fuzz), Task 7 (`TestMySQLCollectorInvalidUTF8Label`).
2. **Rates computed before a full window has elapsed** (first poll after start, or a process seen once) → bytes/s must be a finite number; `NaN`/`Inf` makes `encoding/json` fail and `/api/diagnose` returns nothing. Test: Task 5 (`TestProcessRatesFiniteAfterFirstIngest`).
3. **A process with thousands of sockets** (mysqld with 5k client connections) → `connections` capped at 50 with an exact `connections_truncated` count, ESTABLISHED first. Test: Task 4 (`TestForPIDsCapsAndCountsTruncated`).
4. **IPv4 clients on a dual-stack (`::`) listener** arrive as `::ffff:a.b.c.d` → must be reported as `a.b.c.d`, or the same client appears as two peers and two Prometheus series. Tests: Task 4 (`TestParseNetTCP6UnmapsV4`), Task 5 (`TestPeerFromBytesUnmapsV4`).
5. **Empty or whitespace-only `COM_QUERY`** (and the typed-nil-interface trap when netflow is disabled) → empty queries get a stable placeholder digest instead of an empty-string digest that merges unrelated garbage; a nil `*netflow.Accumulator` must never be stored in the `procreport.NetSource` interface. Tests: Task 10 (`TestClassifyEmptyQuery`), Task 6 (`TestBuildWithoutNetwork`).

---

## File Map

| File | Status | Responsibility |
|---|---|---|
| `internal/sqldigest/sqldigest.go` | create | `Normalize(sql) Digest`, `HashID` |
| `internal/sqldigest/sqldigest_test.go` | create | table tests + fuzz |
| `internal/model/types.go` | modify | new report/digest/network types; `ProcessStats.Family/StartTime`; `DiagnoseReport.ProcessReport`; `MySQLAnalysis` digest fields |
| `internal/querystats/querystats.go` | create | rolling per-digest aggregator, roles, sticky export set |
| `internal/querystats/querystats_test.go` | create | |
| `internal/process/family.go` | create | `FamilyKey`, `BuildFamilies` |
| `internal/process/family_test.go` | create | |
| `internal/process/inspector.go` | modify | full cgroup read, start time, family accessors, report top-N |
| `internal/process/inspector_test.go` | create | `readProcStat` start-time parse |
| `internal/config/config.go` | modify | `process.*`, `netflow:`, `mysql.*` keys, env overrides, validation |
| `internal/config/config_test.go` | create | |
| `internal/netinv/netinv.go` | create | `/proc/net/tcp*` parsing, inode→PID inventory |
| `internal/netinv/netinv_test.go` | create | |
| `internal/netflow/flow.go` | create | `FlowKey`, `FlowValue`, `Source`, `PeerFromBytes` |
| `internal/netflow/accumulator.go` | create | delta/eviction handling, window, active, label budgets, counters |
| `internal/netflow/analyzer.go` | create | poll loop + listen-port refresh |
| `internal/netflow/*_test.go` | create | |
| `internal/procreport/procreport.go` | create | builds `model.ProcessReport` |
| `internal/procreport/procreport_test.go` | create | |
| `internal/promcollect/family.go` | create | family Prometheus collector |
| `internal/promcollect/mysql.go` | create | MySQL Prometheus collector |
| `internal/promcollect/*_test.go` | create | |
| `internal/ebpf/netflow/netflow.bpf.c` | create | TCP flow accounting |
| `internal/ebpf/netflow/gen.go` | create | bpf2go directive |
| `internal/ebpf/netflow/loader.go` | create | implements `netflow.Source` |
| `internal/ebpf/netflow/loader_integration_test.go` | create | root-only, `ebpf_integration` tag |
| `internal/ebpf/mysql_query/mysql_query.bpf.c` | modify | CPU/runq/bytes, per-command events |
| `internal/ebpf/mysql_query/gen.go` | modify | add `-type mysql_cmd_event_t` |
| `internal/ebpf/mysql_query/loader.go` | modify | `CmdEvents`, `Dropped()`, sendmsg kretprobes |
| `internal/ebpf/mysql_query/loader_integration_test.go` | create | needs local mysqld |
| `internal/mysql/cmdmap/cmdmap.go` | create | command → class + digest |
| `internal/mysql/cmdmap/cmdmap_test.go` | create | |
| `internal/mysql/analyzer.go` | modify | feed `querystats`, publish digests |
| `internal/exporter/prometheus.go` | modify | `process_report`, collector registration |
| `cmd/agent/main.go` | modify | wiring |
| `deploy/prometheus/obs-agent-alerts.yaml` | create | 8 alert rules |
| `deploy/prometheus/obs-agent-alerts_test.yaml` | create | promtool rule tests |
| `deploy/config.yaml.example` | modify | new keys |
| `AGENTS.md`, `CLAUDE.md` | modify | docs |

---

### Task 1: SQL digest normaliser

**Files:**
- Create: `internal/sqldigest/sqldigest.go`
- Test: `internal/sqldigest/sqldigest_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Digest struct { ID string; Text string; Normalized bool }`
  - `func Normalize(sql string) Digest` — never panics; `Text` always valid UTF-8; `ID` = 16 hex chars.
  - `func HashID(text string) string` — first 16 hex chars of sha256(text).

- [ ] **Step 1: Write the failing test**

```go
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
	for _, s := range []string{"SELECT 1", "x'", "`", "/*", "IN (", "VALUES (?,", "\xff\xfe", "'\\"} {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sqldigest/`
Expected: FAIL — `undefined: Normalize`, `undefined: HashID`.

- [ ] **Step 3: Write the implementation**

```go
// internal/sqldigest/sqldigest.go

// Package sqldigest normalises SQL text into a stable "digest": literals
// become ?, value lists collapse, comments and whitespace disappear. Two
// executions of the same statement shape with different literal values
// produce the same digest, so per-digest totals reveal a query pattern that
// is cheap per call but expensive in aggregate.
//
// Database-agnostic: MySQL is the first user; PostgreSQL/others can reuse it.
package sqldigest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Digest is the normalised form of one SQL statement.
type Digest struct {
	ID         string // HashID(Text)
	Text       string // normalised SQL, always valid UTF-8
	Normalized bool   // false when the whitespace-collapsed fallback was used
}

// HashID returns the first 16 hex characters of sha256(text).
func HashID(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

// Normalize never panics and never fails. Text cut off mid-literal (the
// kernel captures at most 511 bytes) is handled: the unterminated literal
// becomes a single ?.
func Normalize(sql string) (d Digest) {
	sql = strings.ToValidUTF8(sql, "?")
	defer func() {
		if recover() != nil {
			text := strings.Join(strings.Fields(sql), " ")
			d = Digest{ID: HashID(text), Text: text, Normalized: false}
		}
	}()
	text := strings.Join(collapseLists(tokenize(sql)), " ")
	return Digest{ID: HashID(text), Text: text, Normalized: true}
}

func tokenize(s string) []string {
	var toks []string
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case isSpace(c):
			i++
		case c == '/' && i+1 < n && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return toks
			}
			i += 2 + end + 2
		case c == '#' || (c == '-' && i+1 < n && s[i+1] == '-' && (i+2 == n || isSpace(s[i+2]))):
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				return toks
			}
			i += end + 1
		case c == '\'' || c == '"':
			toks = append(toks, "?")
			j, ok := skipQuoted(s, i)
			if !ok {
				return toks
			}
			i = j
		case c == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				return append(toks, s[i:])
			}
			toks = append(toks, s[i:i+end+2])
			i += end + 2
		case (c == 'x' || c == 'X' || c == 'b' || c == 'B') && i+1 < n && s[i+1] == '\'':
			toks = append(toks, "?")
			j, ok := skipQuoted(s, i+1)
			if !ok {
				return toks
			}
			i = j
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(s[i+1])):
			toks = append(toks, "?")
			i = skipNumber(s, i)
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(s[j]) {
				j++
			}
			w := strings.ToLower(s[i:j])
			if w == "true" || w == "false" || w == "null" {
				w = "?"
			}
			toks = append(toks, w)
			i = j
		default:
			if i+2 < n && s[i:i+3] == "<=>" {
				toks = append(toks, "<=>")
				i += 3
				continue
			}
			if i+1 < n {
				switch s[i : i+2] {
				case "<=", ">=", "<>", "!=", ":=", "||", "&&":
					toks = append(toks, s[i:i+2])
					i += 2
					continue
				}
			}
			toks = append(toks, s[i:i+1])
			i++
		}
	}
	return toks
}

// skipQuoted returns the index just past the closing quote that matches
// s[i], honouring backslash escapes and doubled quotes. ok=false when the
// literal is unterminated (truncated capture).
func skipQuoted(s string, i int) (int, bool) {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return len(s), false
}

func skipNumber(s string, i int) int {
	n := len(s)
	if i+1 < n && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
		j := i + 2
		for j < n && isHex(s[j]) {
			j++
		}
		return j
	}
	j := i
	for j < n && (isDigit(s[j]) || s[j] == '.') {
		j++
	}
	if j < n && (s[j] == 'e' || s[j] == 'E') {
		k := j + 1
		if k < n && (s[k] == '+' || s[k] == '-') {
			k++
		}
		if k < n && isDigit(s[k]) {
			for k < n && isDigit(s[k]) {
				k++
			}
			j = k
		}
	}
	return j
}

// collapseLists rewrites `in ( ? , ? )` → `in ( ?+ )` and
// `values ( ?.. ) , ( ?.. )` → `values ( ?+ )`, so the number of list
// elements does not create distinct digests. Lists containing anything other
// than ? (e.g. NOW()) are left as-is.
func collapseLists(toks []string) []string {
	out := make([]string, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		out = append(out, t)
		switch t {
		case "in":
			if end, ok := qList(toks, i+1); ok {
				out = append(out, "(", "?+", ")")
				i = end
			}
		case "values":
			last, j := -1, i+1
			for {
				end, ok := qList(toks, j)
				if !ok {
					break
				}
				last = end
				if end+2 < len(toks) && toks[end+1] == "," && toks[end+2] == "(" {
					j = end + 2
					continue
				}
				break
			}
			if last >= 0 {
				out = append(out, "(", "?+", ")")
				i = last
			}
		}
	}
	return out
}

// qList reports whether toks[start:] begins with `( ? [, ?]* )` and returns
// the index of the closing parenthesis.
func qList(toks []string, start int) (int, bool) {
	if start >= len(toks) || toks[start] != "(" {
		return 0, false
	}
	j := start + 1
	for {
		if j >= len(toks) || toks[j] != "?" {
			return 0, false
		}
		j++
		if j < len(toks) && toks[j] == ")" {
			return j, true
		}
		if j >= len(toks) || toks[j] != "," {
			return 0, false
		}
		j++
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c == '@' || c >= 0x80
}
func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sqldigest/ && go test ./internal/sqldigest/ -run '^$' -fuzz FuzzNormalize -fuzztime 30s`
Expected: `ok`, and the fuzz run ends with no failures.

- [ ] **Step 5: Commit**

```bash
git add internal/sqldigest/sqldigest.go internal/sqldigest/sqldigest_test.go
git commit -m "feat(sqldigest): add DB-agnostic SQL normaliser

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 6: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD) of this Go repo for correctness bugs, panics and edge cases in SQL tokenizing. Report findings only."`
Fix any confirmed finding, re-run Step 4, and commit with message `fix(sqldigest): address review`.

---

### Task 2: Generic query-digest aggregator

**Files:**
- Modify: `internal/model/types.go` (append a new section at the end of the file)
- Create: `internal/querystats/querystats.go`
- Test: `internal/querystats/querystats_test.go`

**Interfaces:**
- Consumes: `sqldigest.Digest` (Task 1).
- Produces:
  - `model.QueryCounters{Calls, CPUNs, RunqNs, WallNs, BytesIn, BytesOut uint64}`
  - `model.QueryDigestStats` (JSON shape in spec §5.2), `model.QueryRoleThresholds{CulpritCPUSharePercent, VictimRunqRatio float64}`
  - `querystats.Event{PID uint32; Command string; Digest sqldigest.Digest; SampleQuery string; Truncated bool; WallNs, CPUNs, RunqNs, BytesIn, BytesOut uint64; At time.Time}`
  - `querystats.Config{Window, BucketWidth time.Duration; MaxDigests, TopN, TopNBytes int; CulpritCPUSharePercent, VictimRunqRatio float64; SlowWallNs uint64; StickyMax int; StickyTTL time.Duration}`
  - `func New(cfg Config) *Aggregator`, `func (*Aggregator) Add(Event)`, `func (*Aggregator) Snapshot(now time.Time) Snapshot`
  - `querystats.Snapshot{WindowSeconds int; CPUAccounting string; Thresholds model.QueryRoleThresholds; TopByCPU, TopByBytesOut []model.QueryDigestStats; Exported []ExportedDigest; Commands map[string]model.QueryCounters}`
  - `querystats.ExportedDigest{ID, Text string; Counters model.QueryCounters}`
  - Constants `AccountingOK = "ok"`, `AccountingNoRunDelay = "run_delay_unavailable"`, `RoleCulprit`, `RoleVictim`, `OtherDigestID = "other"`, `OtherDigestText = "<other>"`.

- [ ] **Step 1: Add the model types**

Append to `internal/model/types.go`:

```go
// ─── Query digests (generic, DB-agnostic) ─────────────────────────────────────

// QueryCounters are cumulative totals for one digest or one command class.
type QueryCounters struct {
	Calls    uint64 `json:"calls"`
	CPUNs    uint64 `json:"cpu_ns"`
	RunqNs   uint64 `json:"runq_ns"`
	WallNs   uint64 `json:"wall_ns"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// QueryDigestStats is one digest's aggregate over the report window.
// Ranking by CPUMsTotal separates the query that consumes the CPU (culprit)
// from queries that are slow only because they waited for a CPU (victims).
type QueryDigestStats struct {
	PID             uint32  `json:"pid"`
	DigestID        string  `json:"digest_id"`
	Command         string  `json:"command"`
	DigestText      string  `json:"digest_text"`
	SampleQuery     string  `json:"sample_query,omitempty"`
	Normalized      bool    `json:"normalized"`
	Truncated       bool    `json:"truncated"`
	Calls           uint64  `json:"calls"`
	CPUMsTotal      float64 `json:"cpu_ms_total"`
	CPUMsAvg        float64 `json:"cpu_ms_avg"`
	CPUMsMax        float64 `json:"cpu_ms_max"`
	RunqWaitMsAvg   float64 `json:"runq_wait_ms_avg"`
	WallMsAvg       float64 `json:"wall_ms_avg"`
	WallMsMax       float64 `json:"wall_ms_max"`
	BytesInTotal    uint64  `json:"bytes_in_total"`
	BytesOutTotal   uint64  `json:"bytes_out_total"`
	BytesOutAvg     float64 `json:"bytes_out_avg"`
	CPUSharePercent float64 `json:"cpu_share_percent"`
	Role            string  `json:"role"`
}

// QueryRoleThresholds echoes the culprit/victim cut-offs into the report.
type QueryRoleThresholds struct {
	CulpritCPUSharePercent float64 `json:"culprit_cpu_share_percent"`
	VictimRunqRatio        float64 `json:"victim_runq_ratio"`
}
```

- [ ] **Step 2: Write the failing test**

```go
// internal/querystats/querystats_test.go
package querystats

import (
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

var t0 = time.Unix(1_800_000_000, 0)

func ev(sql string, at time.Time, cpuMs, runqMs, wallMs float64, out uint64) Event {
	ms := func(v float64) uint64 { return uint64(v * 1e6) }
	return Event{
		PID: 100, Command: "query", Digest: sqldigest.Normalize(sql), SampleQuery: sql,
		CPUNs: ms(cpuMs), RunqNs: ms(runqMs), WallNs: ms(wallMs), BytesIn: uint64(len(sql)), BytesOut: out, At: at,
	}
}

func cfg() Config {
	return Config{SlowWallNs: 10_000_000}
}

func TestRanksByTotalCPUNotPerCall(t *testing.T) {
	a := New(cfg())
	for i := 0; i < 10; i++ { // A: 10 × 400ms = 4000ms
		a.Add(ev("SELECT status, COUNT(*) FROM orders GROUP BY status", t0, 400, 5, 410, 200))
	}
	for i := 0; i < 5000; i++ { // C: 5000 × 3ms = 15000ms, never slow
		a.Add(ev("SELECT * FROM carts WHERE user_id = 1", t0, 3, 0.1, 3.2, 500))
	}
	for i := 0; i < 1000; i++ { // B: 1000 × 0.003ms = 3ms
		a.Add(ev("SELECT * FROM users WHERE id = 1", t0, 0.003, 38, 41, 1200))
	}
	s := a.Snapshot(t0.Add(time.Second))
	got := []string{s.TopByCPU[0].DigestText, s.TopByCPU[1].DigestText, s.TopByCPU[2].DigestText}
	want := []string{
		"select * from carts where user_id = ?",
		"select status , count ( * ) from orders group by status",
		"select * from users where id = ?",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rank %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRoles(t *testing.T) {
	a := New(cfg())
	for i := 0; i < 100; i++ {
		a.Add(ev("SELECT COUNT(*) FROM big", t0, 400, 5, 410, 20))
		a.Add(ev("SELECT * FROM users WHERE id = 1", t0, 0.003, 38, 41, 1200))
	}
	s := a.Snapshot(t0.Add(time.Second))
	roles := map[string]string{}
	for _, d := range s.TopByCPU {
		roles[d.DigestText] = d.Role
	}
	if roles["select count ( * ) from big"] != RoleCulprit {
		t.Fatalf("big scan role = %q", roles["select count ( * ) from big"])
	}
	if roles["select * from users where id = ?"] != RoleVictim {
		t.Fatalf("point select role = %q", roles["select * from users where id = ?"])
	}
	if s.CPUAccounting != AccountingOK {
		t.Fatalf("accounting = %q", s.CPUAccounting)
	}
}

func TestRunDelayUnavailableFallback(t *testing.T) {
	a := New(cfg())
	for i := 0; i < 1000; i++ {
		a.Add(ev("SELECT * FROM users WHERE id = 1", t0, 1, 0, 50, 10))
	}
	a.Add(ev("SELECT COUNT(*) FROM big", t0, 5000, 0, 5000, 10))
	s := a.Snapshot(t0.Add(time.Second))
	if s.CPUAccounting != AccountingNoRunDelay {
		t.Fatalf("accounting = %q", s.CPUAccounting)
	}
	for _, d := range s.TopByCPU {
		if d.DigestText == "select * from users where id = ?" && d.Role != RoleVictim {
			t.Fatalf("expected victim via wall-cpu fallback, got %q", d.Role)
		}
	}
}

func TestWindowRollOff(t *testing.T) {
	a := New(cfg())
	a.Add(ev("SELECT 1", t0, 1, 0, 1, 1))
	if s := a.Snapshot(t0.Add(30 * time.Second)); len(s.TopByCPU) != 1 {
		t.Fatalf("want 1 digest inside window, got %d", len(s.TopByCPU))
	}
	if s := a.Snapshot(t0.Add(61 * time.Second)); len(s.TopByCPU) != 0 {
		t.Fatalf("want 0 digests after window, got %d", len(s.TopByCPU))
	}
}

func TestMaxDigestsOverflowToOther(t *testing.T) {
	c := cfg()
	c.MaxDigests = 2
	a := New(c)
	a.Add(ev("SELECT a FROM t1", t0, 1, 0, 1, 1))
	a.Add(ev("SELECT a FROM t2", t0, 1, 0, 1, 1))
	a.Add(ev("SELECT a FROM t3", t0, 1, 0, 1, 1))
	s := a.Snapshot(t0.Add(time.Second))
	var other bool
	for _, d := range s.TopByCPU {
		if d.DigestID == OtherDigestID && d.DigestText == OtherDigestText {
			other = true
		}
	}
	if len(s.TopByCPU) != 3 || !other {
		t.Fatalf("want 2 digests + <other>, got %+v", s.TopByCPU)
	}
}

func TestStickyExportSurvivesThenExpires(t *testing.T) {
	a := New(cfg())
	a.Add(ev("SELECT COUNT(*) FROM big", t0, 400, 0, 400, 1))
	id := sqldigest.Normalize("SELECT COUNT(*) FROM big").ID
	a.Snapshot(t0.Add(time.Second))
	if !exported(a.Snapshot(t0.Add(30*time.Minute)), id) {
		t.Fatal("digest should stay exported for the sticky TTL after leaving the top list")
	}
	if exported(a.Snapshot(t0.Add(62*time.Minute)), id) {
		t.Fatal("digest should be dropped after the sticky TTL")
	}
}

func TestStickyCap(t *testing.T) {
	c := cfg()
	c.StickyMax = 2
	a := New(c)
	a.Add(ev("SELECT a FROM t1", t0, 3, 0, 3, 1))
	a.Add(ev("SELECT a FROM t2", t0, 2, 0, 2, 1))
	a.Add(ev("SELECT a FROM t3", t0, 1, 0, 1, 1))
	if s := a.Snapshot(t0.Add(time.Second)); len(s.Exported) != 2 {
		t.Fatalf("exported = %d, want cap 2", len(s.Exported))
	}
}

func TestCommandCountersAndBytesRanking(t *testing.T) {
	a := New(cfg())
	a.Add(ev("SELECT * FROM t", t0, 1, 0, 1, 9_000_000))
	a.Add(ev("SELECT COUNT(*) FROM t", t0, 50, 0, 50, 10))
	s := a.Snapshot(t0.Add(time.Second))
	if got := s.TopByBytesOut[0].DigestText; got != "select * from t" {
		t.Fatalf("top by bytes = %q", got)
	}
	q := s.Commands["query"]
	if q.Calls != 2 || q.BytesOut != 9_000_010 || q.CPUNs != 51_000_000 {
		t.Fatalf("command counters = %+v", q)
	}
}

func exported(s Snapshot, id string) bool {
	for _, e := range s.Exported {
		if e.ID == id {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/querystats/`
Expected: FAIL — `undefined: New`, `undefined: Event`.

- [ ] **Step 4: Write the implementation**

```go
// internal/querystats/querystats.go

// Package querystats aggregates per-statement measurements (CPU time,
// run-queue wait, wall time, bytes) by normalised digest over a rolling
// window and labels each digest as a CPU culprit or a cascade victim.
//
// Database-agnostic: the MySQL analyzer is the first producer of Events.
package querystats

import (
	"sort"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

const (
	AccountingOK         = "ok"
	AccountingNoRunDelay = "run_delay_unavailable"
	RoleCulprit          = "culprit"
	RoleVictim           = "victim"
	OtherDigestID        = "other"
	OtherDigestText      = "<other>"

	// noRunDelayMinEvents: run_delay is declared unavailable only after this
	// many events that clearly waited (wall − cpu > 10 ms) all reported 0.
	noRunDelayMinEvents = 1000
	waitedGapNs         = 10_000_000
)

// Event is one executed statement.
type Event struct {
	PID         uint32
	Command     string // "query" | "stmt_execute" | "other"
	Digest      sqldigest.Digest
	SampleQuery string
	Truncated   bool
	WallNs      uint64
	CPUNs       uint64
	RunqNs      uint64
	BytesIn     uint64
	BytesOut    uint64
	At          time.Time
}

// Config tunes the aggregator. Zero values take the documented defaults.
type Config struct {
	Window                 time.Duration // 60s
	BucketWidth            time.Duration // 5s
	MaxDigests             int           // 5000 per bucket and in lifetime table
	TopN                   int           // 20
	TopNBytes              int           // 10
	CulpritCPUSharePercent float64       // 20
	VictimRunqRatio        float64       // 5
	SlowWallNs             uint64        // victim needs wall_avg >= this
	StickyMax              int           // 50
	StickyTTL              time.Duration // 1h
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 60 * time.Second
	}
	if c.BucketWidth <= 0 {
		c.BucketWidth = 5 * time.Second
	}
	if c.MaxDigests <= 0 {
		c.MaxDigests = 5000
	}
	if c.TopN <= 0 {
		c.TopN = 20
	}
	if c.TopNBytes <= 0 {
		c.TopNBytes = 10
	}
	if c.CulpritCPUSharePercent <= 0 {
		c.CulpritCPUSharePercent = 20
	}
	if c.VictimRunqRatio <= 0 {
		c.VictimRunqRatio = 5
	}
	if c.StickyMax <= 0 {
		c.StickyMax = 50
	}
	if c.StickyTTL <= 0 {
		c.StickyTTL = time.Hour
	}
	return c
}

// ExportedDigest carries lifetime counters for a digest in the sticky
// Prometheus export set.
type ExportedDigest struct {
	ID       string
	Text     string
	Counters model.QueryCounters
}

// Snapshot is the read-only result of one Snapshot call.
type Snapshot struct {
	WindowSeconds int
	CPUAccounting string
	Thresholds    model.QueryRoleThresholds
	TopByCPU      []model.QueryDigestStats
	TopByBytesOut []model.QueryDigestStats
	Exported      []ExportedDigest
	Commands      map[string]model.QueryCounters
}

type key struct {
	pid uint32
	id  string
}

type acc struct {
	command, text, sample              string
	normalized, truncated              bool
	calls, cpu, cpuMax, runq, wall     uint64
	wallMax, in, out                   uint64
}

func (x *acc) add(e Event) {
	x.calls++
	x.cpu += e.CPUNs
	x.runq += e.RunqNs
	x.wall += e.WallNs
	x.in += e.BytesIn
	x.out += e.BytesOut
	x.cpuMax = max(x.cpuMax, e.CPUNs)
	x.wallMax = max(x.wallMax, e.WallNs)
	x.truncated = x.truncated || e.Truncated
	if x.sample == "" {
		x.sample = e.SampleQuery
	}
}

func (x *acc) merge(y *acc) {
	x.calls += y.calls
	x.cpu += y.cpu
	x.runq += y.runq
	x.wall += y.wall
	x.in += y.in
	x.out += y.out
	x.cpuMax = max(x.cpuMax, y.cpuMax)
	x.wallMax = max(x.wallMax, y.wallMax)
	x.truncated = x.truncated || y.truncated
	if x.sample == "" {
		x.sample = y.sample
	}
}

type bucket struct {
	epoch int64
	m     map[key]*acc
}

type life struct {
	text     string
	c        model.QueryCounters
	lastSeen time.Time
}

// Aggregator is safe for concurrent Add and Snapshot.
type Aggregator struct {
	mu       sync.Mutex
	cfg      Config
	buckets  []bucket
	life     map[string]*life
	commands map[string]model.QueryCounters
	sticky   map[string]time.Time
	waited   uint64 // events with wall − cpu > waitedGapNs
	runqSum  uint64
}

func New(cfg Config) *Aggregator {
	cfg = cfg.withDefaults()
	n := int(cfg.Window / cfg.BucketWidth)
	if n < 1 {
		n = 1
	}
	return &Aggregator{
		cfg:      cfg,
		buckets:  make([]bucket, n),
		life:     make(map[string]*life),
		commands: make(map[string]model.QueryCounters),
		sticky:   make(map[string]time.Time),
	}
}

func addCounters(c *model.QueryCounters, e Event) {
	c.Calls++
	c.CPUNs += e.CPUNs
	c.RunqNs += e.RunqNs
	c.WallNs += e.WallNs
	c.BytesIn += e.BytesIn
	c.BytesOut += e.BytesOut
}

func (a *Aggregator) Add(e Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	b := a.bucketFor(e.At)
	k := key{e.PID, e.Digest.ID}
	x, ok := b.m[k]
	if !ok {
		if len(b.m) >= a.cfg.MaxDigests {
			k = key{e.PID, OtherDigestID}
			if x, ok = b.m[k]; !ok {
				x = &acc{command: "other", text: OtherDigestText, normalized: true}
				b.m[k] = x
			}
		} else {
			x = &acc{command: e.Command, text: e.Digest.Text, normalized: e.Digest.Normalized}
			b.m[k] = x
		}
	}
	x.add(e)

	a.addLife(k.id, x.text, e)
	c := a.commands[e.Command]
	addCounters(&c, e)
	a.commands[e.Command] = c
	if e.WallNs > e.CPUNs+waitedGapNs {
		a.waited++
	}
	a.runqSum += e.RunqNs
}

func (a *Aggregator) addLife(id, text string, e Event) {
	l, ok := a.life[id]
	if !ok {
		if len(a.life) >= a.cfg.MaxDigests {
			id, text = OtherDigestID, OtherDigestText
			if l, ok = a.life[id]; !ok {
				l = &life{text: text}
				a.life[id] = l
			}
		} else {
			l = &life{text: text}
			a.life[id] = l
		}
	}
	addCounters(&l.c, e)
	l.lastSeen = e.At
}

func (a *Aggregator) bucketFor(t time.Time) *bucket {
	epoch := t.UnixNano() / a.cfg.BucketWidth.Nanoseconds()
	b := &a.buckets[int(epoch%int64(len(a.buckets)))]
	if epoch > b.epoch || b.m == nil {
		b.epoch = epoch
		b.m = make(map[key]*acc)
	}
	// epoch < b.epoch: a late event; count it into the newer bucket rather
	// than wiping fresher data.
	return b
}

// Snapshot merges the buckets inside the window, ranks digests, updates the
// sticky export set and returns a copy. Call it periodically (the analyzer
// does so every poll interval); it mutates the sticky set.
func (a *Aggregator) Snapshot(now time.Time) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()

	cur := now.UnixNano() / a.cfg.BucketWidth.Nanoseconds()
	n := int64(len(a.buckets))
	merged := make(map[key]*acc)
	for i := range a.buckets {
		b := &a.buckets[i]
		if b.m == nil || b.epoch <= cur-n || b.epoch > cur {
			continue
		}
		for k, x := range b.m {
			m, ok := merged[k]
			if !ok {
				cp := *x
				merged[k] = &cp
				continue
			}
			m.merge(x)
		}
	}

	acct := AccountingOK
	if a.waited >= noRunDelayMinEvents && a.runqSum == 0 {
		acct = AccountingNoRunDelay
	}
	cpuByPID := make(map[uint32]uint64)
	for k, x := range merged {
		cpuByPID[k.pid] += x.cpu
	}
	stats := make([]model.QueryDigestStats, 0, len(merged))
	for k, x := range merged {
		stats = append(stats, a.toStats(k, x, cpuByPID[k.pid], acct))
	}
	byCPU := topBy(stats, a.cfg.TopN, func(s model.QueryDigestStats) float64 { return s.CPUMsTotal })
	byOut := topBy(stats, a.cfg.TopNBytes, func(s model.QueryDigestStats) float64 { return float64(s.BytesOutTotal) })

	for _, s := range byCPU {
		a.sticky[s.DigestID] = now
	}
	for _, s := range byOut {
		a.sticky[s.DigestID] = now
	}
	a.expire(now)

	exported := make([]ExportedDigest, 0, len(a.sticky))
	for id := range a.sticky {
		if l, ok := a.life[id]; ok {
			exported = append(exported, ExportedDigest{ID: id, Text: l.text, Counters: l.c})
		}
	}
	sort.Slice(exported, func(i, j int) bool { return exported[i].ID < exported[j].ID })

	cmds := make(map[string]model.QueryCounters, len(a.commands))
	for k, v := range a.commands {
		cmds[k] = v
	}
	return Snapshot{
		WindowSeconds: int(a.cfg.Window / time.Second),
		CPUAccounting: acct,
		Thresholds: model.QueryRoleThresholds{
			CulpritCPUSharePercent: a.cfg.CulpritCPUSharePercent,
			VictimRunqRatio:        a.cfg.VictimRunqRatio,
		},
		TopByCPU:      byCPU,
		TopByBytesOut: byOut,
		Exported:      exported,
		Commands:      cmds,
	}
}

func (a *Aggregator) expire(now time.Time) {
	for id, t := range a.sticky {
		if now.Sub(t) > a.cfg.StickyTTL {
			delete(a.sticky, id)
		}
	}
	if over := len(a.sticky) - a.cfg.StickyMax; over > 0 {
		type kv struct {
			id string
			t  time.Time
		}
		all := make([]kv, 0, len(a.sticky))
		for id, t := range a.sticky {
			all = append(all, kv{id, t})
		}
		sort.Slice(all, func(i, j int) bool {
			if !all[i].t.Equal(all[j].t) {
				return all[i].t.Before(all[j].t)
			}
			return all[i].id < all[j].id
		})
		for _, e := range all[:over] {
			delete(a.sticky, e.id)
		}
	}
	for id, l := range a.life {
		if _, sticky := a.sticky[id]; !sticky && now.Sub(l.lastSeen) > a.cfg.StickyTTL {
			delete(a.life, id)
		}
	}
}

func (a *Aggregator) toStats(k key, x *acc, pidCPU uint64, acct string) model.QueryDigestStats {
	ms := func(ns uint64) float64 { return float64(ns) / 1e6 }
	calls := float64(x.calls)
	cpuAvg, runqAvg, wallAvg := ms(x.cpu)/calls, ms(x.runq)/calls, ms(x.wall)/calls
	share := 0.0
	if pidCPU > 0 {
		share = 100 * float64(x.cpu) / float64(pidCPU)
	}
	wait := runqAvg
	if acct == AccountingNoRunDelay {
		wait = wallAvg - cpuAvg
	}
	role := ""
	switch {
	case share >= a.cfg.CulpritCPUSharePercent:
		role = RoleCulprit
	case wait > cpuAvg*a.cfg.VictimRunqRatio && wallAvg >= ms(a.cfg.SlowWallNs):
		role = RoleVictim
	}
	return model.QueryDigestStats{
		PID: k.pid, DigestID: k.id, Command: x.command, DigestText: x.text,
		SampleQuery: x.sample, Normalized: x.normalized, Truncated: x.truncated,
		Calls:      x.calls,
		CPUMsTotal: ms(x.cpu), CPUMsAvg: cpuAvg, CPUMsMax: ms(x.cpuMax),
		RunqWaitMsAvg: runqAvg,
		WallMsAvg:     wallAvg, WallMsMax: ms(x.wallMax),
		BytesInTotal: x.in, BytesOutTotal: x.out, BytesOutAvg: float64(x.out) / calls,
		CPUSharePercent: share,
		Role:            role,
	}
}

func topBy(in []model.QueryDigestStats, n int, metric func(model.QueryDigestStats) float64) []model.QueryDigestStats {
	out := make([]model.QueryDigestStats, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		mi, mj := metric(out[i]), metric(out[j])
		if mi != mj {
			return mi > mj
		}
		if out[i].DigestID != out[j].DigestID {
			return out[i].DigestID < out[j].DigestID
		}
		return out[i].PID < out[j].PID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `gofmt -w internal/ && go test ./internal/querystats/ ./internal/sqldigest/`
Expected: `ok` for both packages.

- [ ] **Step 6: Commit**

```bash
git add internal/model/types.go internal/querystats/querystats.go internal/querystats/querystats_test.go
git commit -m "feat(querystats): rolling per-digest aggregation with culprit/victim roles

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD) for correctness bugs: window bucketing, sticky-set expiry, division by zero, lock usage. Report findings only."`
Fix any confirmed finding, re-run Step 5, and commit with `fix(querystats): address review`.

---

### Task 3: Process families and report top-N

**Files:**
- Modify: `internal/model/types.go` (`ProcessStats` fields; new `FamilyMember`, `FamilyStats`)
- Create: `internal/process/family.go`
- Modify: `internal/process/inspector.go`
- Modify: `internal/config/config.go` (`ProcessConfig`, defaults, validation)
- Test: `internal/process/family_test.go`, `internal/process/inspector_test.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `model.ProcessStats.Family string` (json `family,omitempty`), `model.ProcessStats.StartTime uint64` (json `-`)
  - `model.FamilyMember{PID uint32; Comm string; CPUPercent float64; MemRSSBytes uint64}`
  - `model.FamilyStats{Family string; RootPID uint32; RootCmdline string; ProcessCount int; CPUPercent float64; MemRSSBytes uint64; MemPercent float64; TopMembers []FamilyMember}`
  - `process.FamilyKey(cgroupFile, mode string) string`; `process.BuildFamilies(procs []model.ProcessStats, topMembers int) []model.FamilyStats`
  - Constants `process.FamilyBySystemdUnit = "systemd_unit"`, `process.FamilyByCgroup = "cgroup"`, `process.UnknownFamily = "unknown"`
  - `(*Inspector).ReportTopCPU()`, `ReportTopMem() []model.ProcessStats`; `TopFamiliesCPU()`, `TopFamiliesMem()`, `AllFamilies() []model.FamilyStats` (AllFamilies sorted by CPU desc); `PIDFamilies() map[uint32]string`
  - `config.ProcessConfig.ReportTopN int` (`report_top_n`, default 10), `FamilyBy string` (`family_by`, default `systemd_unit`), `MaxConnectionsPerProcess int` (default 50), `MaxPeersPerProcess int` (default 20)

- [ ] **Step 1: Add model types**

In `internal/model/types.go`, add to `ProcessStats` after the `K8sNamespace` field:

```go
	// Family is the process family (systemd unit, or cgroup path) used to
	// aggregate forked workers under the service that owns them.
	Family string `json:"family,omitempty"`
	// StartTime is /proc/[pid]/stat field 22 (clock ticks since boot); used
	// to pick the oldest process of a family as its root.
	StartTime uint64 `json:"-"`
```

Append to the end of `internal/model/types.go`:

```go
// ─── Process families ─────────────────────────────────────────────────────────

// FamilyMember is a compact view of one process inside a FamilyStats.
type FamilyMember struct {
	PID         uint32  `json:"pid"`
	Comm        string  `json:"comm"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemRSSBytes uint64  `json:"mem_rss_bytes"`
}

// FamilyStats aggregates every process in one family (systemd unit).
type FamilyStats struct {
	Family       string         `json:"family"`
	RootPID      uint32         `json:"root_pid"`
	RootCmdline  string         `json:"root_cmdline"`
	ProcessCount int            `json:"process_count"`
	CPUPercent   float64        `json:"cpu_percent"`
	MemRSSBytes  uint64         `json:"mem_rss_bytes"`
	MemPercent   float64        `json:"mem_percent"`
	TopMembers   []FamilyMember `json:"top_members"`
}
```

- [ ] **Step 2: Write the failing tests**

```go
// internal/process/family_test.go
package process

import (
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

func TestFamilyKey(t *testing.T) {
	cases := []struct{ name, in, mode, want string }{
		{"v2 service", "0::/system.slice/mysql.service\n", FamilyBySystemdUnit, "mysql.service"},
		{"v2 session scope", "0::/user.slice/user-1000.slice/session-42.scope\n", FamilyBySystemdUnit, "session-42.scope"},
		{"service wins over nested scope", "0::/system.slice/php-fpm.service/init.scope\n", FamilyBySystemdUnit, "php-fpm.service"},
		{"kubepods scope", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podx.slice/cri-containerd-abc.scope\n",
			FamilyBySystemdUnit, "cri-containerd-abc.scope"},
		{"kernel thread root", "0::/\n", FamilyBySystemdUnit, "/"},
		{"v1 uses name=systemd", "12:cpu,cpuacct:/\n1:name=systemd:/system.slice/nginx.service\n", FamilyBySystemdUnit, "nginx.service"},
		{"hybrid prefers unified", "1:name=systemd:/system.slice/a.service\n0::/system.slice/a.service\n", FamilyBySystemdUnit, "a.service"},
		{"no unit falls back to path", "0::/custom/group\n", FamilyBySystemdUnit, "/custom/group"},
		{"cgroup mode", "0::/system.slice/mysql.service\n", FamilyByCgroup, "/system.slice/mysql.service"},
		{"unreadable", "", FamilyBySystemdUnit, UnknownFamily},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FamilyKey(c.in, c.mode); got != c.want {
				t.Fatalf("FamilyKey = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBuildFamilies(t *testing.T) {
	procs := []model.ProcessStats{
		{PID: 1022, Comm: "php-fpm", Cmdline: "php-fpm: master process", Family: "php-fpm.service", StartTime: 100, CPUPercent: 1, MemRSSBytes: 10, MemPercent: 0.1},
		{PID: 1301, Comm: "php-fpm", Cmdline: "php-fpm: pool www", Family: "php-fpm.service", StartTime: 200, CPUPercent: 30, MemRSSBytes: 80, MemPercent: 0.8},
		{PID: 1302, Comm: "php-fpm", Cmdline: "php-fpm: pool www", Family: "php-fpm.service", StartTime: 201, CPUPercent: 33, MemRSSBytes: 90, MemPercent: 0.9},
		{PID: 2314, Comm: "mysqld", Cmdline: "/usr/sbin/mysqld", Family: "mysql.service", StartTime: 50, CPUPercent: 87, MemRSSBytes: 6000, MemPercent: 60},
		{PID: 7, Comm: "kworker/0:1", Cmdline: "", Family: "/", StartTime: 1},
	}
	fams := BuildFamilies(procs, 2)
	if len(fams) != 3 {
		t.Fatalf("want 3 families, got %d", len(fams))
	}
	var php model.FamilyStats
	for _, f := range fams {
		if f.Family == "php-fpm.service" {
			php = f
		}
		if f.Family == "/" && f.RootCmdline != "[kworker/0:1]" {
			t.Fatalf("kernel thread root cmdline = %q", f.RootCmdline)
		}
	}
	if php.ProcessCount != 3 || php.CPUPercent != 64 || php.MemRSSBytes != 180 {
		t.Fatalf("php totals wrong: %+v", php)
	}
	if php.RootPID != 1022 || php.RootCmdline != "php-fpm: master process" {
		t.Fatalf("root should be oldest process: %+v", php)
	}
	if len(php.TopMembers) != 2 || php.TopMembers[0].PID != 1302 || php.TopMembers[1].PID != 1301 {
		t.Fatalf("top members by CPU wrong: %+v", php.TopMembers)
	}
}
```

```go
// internal/process/inspector_test.go
package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProcStatStartTimeAndWeirdComm(t *testing.T) {
	// comm contains spaces and parentheses; starttime is field 22 = 987654.
	line := "4821 (my (weird) proc) S 1 4821 4821 0 -1 4194560 1000 0 0 0 " +
		"150 50 0 0 20 0 7 0 987654 123456789 2048 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	p := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(p, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := readProcStat(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.comm != "my (weird) proc" || s.ppid != 1 || s.utime != 150 || s.stime != 50 ||
		s.numThreads != 7 || s.starttime != 987654 || s.vsize != 123456789 || s.rss != 2048 {
		t.Fatalf("parsed = %+v", s)
	}
}
```

```go
// internal/config/config_test.go
package config

import "testing"

func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestProcessDefaults(t *testing.T) {
	p := Defaults().Process
	if p.TopN != 20 || p.ReportTopN != 10 || p.FamilyBy != "systemd_unit" ||
		p.MaxConnectionsPerProcess != 50 || p.MaxPeersPerProcess != 20 {
		t.Fatalf("process defaults = %+v", p)
	}
}

func TestProcessFamilyByValidated(t *testing.T) {
	c := Defaults()
	c.Process.FamilyBy = "parent"
	if err := c.validate(); err == nil {
		t.Fatal("want error for family_by=parent")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/process/ ./internal/config/`
Expected: FAIL — `undefined: FamilyKey`, `s.starttime undefined`, `p.ReportTopN undefined`.

- [ ] **Step 4: Implement `family.go`**

```go
// internal/process/family.go
package process

import (
	"sort"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	FamilyBySystemdUnit = "systemd_unit"
	FamilyByCgroup      = "cgroup"
	UnknownFamily       = "unknown"
)

// FamilyKey derives a process family from the full contents of
// /proc/<pid>/cgroup. In systemd_unit mode it returns the innermost
// "*.service" component of the path, else the innermost "*.scope", else the
// whole path. Grouping by unit keeps double-forking daemons together where a
// PPID chain would break.
func FamilyKey(cgroupFile, mode string) string {
	path, ok := cgroupPath(cgroupFile)
	if !ok {
		return UnknownFamily
	}
	if mode == FamilyByCgroup {
		return path
	}
	parts := strings.Split(path, "/")
	for _, suffix := range []string{".service", ".scope"} {
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], suffix) {
				return parts[i]
			}
		}
	}
	return path
}

// cgroupPath picks the hierarchy systemd manages: unified v2 ("0::"), then
// v1 "name=systemd", then the first well-formed line.
func cgroupPath(content string) (string, bool) {
	var first, v1 string
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 || f[2] == "" {
			continue
		}
		if f[0] == "0" && f[1] == "" {
			return f[2], true
		}
		if f[1] == "name=systemd" {
			v1 = f[2]
		}
		if first == "" {
			first = f[2]
		}
	}
	if v1 != "" {
		return v1, true
	}
	return first, first != ""
}

// BuildFamilies groups processes by Family. The root is the oldest process
// (lowest StartTime, then lowest PID). TopMembers holds up to topMembers
// processes by CPU. The result is sorted by family name.
func BuildFamilies(procs []model.ProcessStats, topMembers int) []model.FamilyStats {
	type agg struct {
		f         model.FamilyStats
		rootStart uint64
		members   []model.ProcessStats
	}
	by := make(map[string]*agg)
	for _, p := range procs {
		a, ok := by[p.Family]
		if !ok {
			a = &agg{f: model.FamilyStats{Family: p.Family}, rootStart: p.StartTime}
			a.f.RootPID, a.f.RootCmdline = p.PID, rootCmdline(p)
			by[p.Family] = a
		} else if p.StartTime < a.rootStart || (p.StartTime == a.rootStart && p.PID < a.f.RootPID) {
			a.rootStart = p.StartTime
			a.f.RootPID, a.f.RootCmdline = p.PID, rootCmdline(p)
		}
		a.f.ProcessCount++
		a.f.CPUPercent += p.CPUPercent
		a.f.MemRSSBytes += p.MemRSSBytes
		a.f.MemPercent += p.MemPercent
		a.members = append(a.members, p)
	}
	out := make([]model.FamilyStats, 0, len(by))
	for _, a := range by {
		m := a.members
		sort.Slice(m, func(i, j int) bool {
			if m[i].CPUPercent != m[j].CPUPercent {
				return m[i].CPUPercent > m[j].CPUPercent
			}
			return m[i].PID < m[j].PID
		})
		if len(m) > topMembers {
			m = m[:topMembers]
		}
		a.f.TopMembers = make([]model.FamilyMember, 0, len(m))
		for _, p := range m {
			a.f.TopMembers = append(a.f.TopMembers, model.FamilyMember{
				PID: p.PID, Comm: p.Comm, CPUPercent: p.CPUPercent, MemRSSBytes: p.MemRSSBytes,
			})
		}
		out = append(out, a.f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

func rootCmdline(p model.ProcessStats) string {
	if p.Cmdline != "" {
		return p.Cmdline
	}
	return "[" + p.Comm + "]"
}
```

- [ ] **Step 5: Update `inspector.go`**

5a. In `procStatFields` add `starttime uint64 // clock ticks since boot` and in `readProcStat` add `starttime: u(19),` to the returned struct.

5b. In `Inspector` struct, add fields:

```go
	reportCPU   []model.ProcessStats
	reportMem   []model.ProcessStats
	famCPU      []model.FamilyStats // all families, sorted by CPU desc
	famMem      []model.FamilyStats // all families, sorted by RSS desc
	pidFamily   map[uint32]string
```

5c. In `readProc`, replace `cgroupPath := readFirstLine(base + "/cgroup")` with:

```go
	cgroupRaw, _ := os.ReadFile(base + "/cgroup")
	cgroupPath := strings.SplitN(string(cgroupRaw), "\n", 2)[0]
```

and add to the `model.ProcessStats` literal:

```go
		Family:      FamilyKey(string(cgroupRaw), i.cfg.FamilyBy),
		StartTime:   stat.starttime,
```

Delete `readFirstLine` if it has no other callers (`grep -n readFirstLine internal/process/` must show only its definition).

5d. Replace the sorting section of `scan()` (from `// Sort by CPU descending.` to the final unlock) with:

```go
	byCPU := sortedProcs(all, func(a, b model.ProcessStats) bool { return a.CPUPercent > b.CPUPercent })
	byMem := sortedProcs(all, func(a, b model.ProcessStats) bool { return a.MemRSSBytes > b.MemRSSBytes })

	fams := BuildFamilies(all, 5)
	famCPU := append([]model.FamilyStats(nil), fams...)
	sort.SliceStable(famCPU, func(a, b int) bool { return famCPU[a].CPUPercent > famCPU[b].CPUPercent })
	famMem := append([]model.FamilyStats(nil), fams...)
	sort.SliceStable(famMem, func(a, b int) bool { return famMem[a].MemRSSBytes > famMem[b].MemRSSBytes })

	pidFamily := make(map[uint32]string, len(all))
	for _, s := range all {
		pidFamily[s.PID] = s.Family
	}

	i.mu.Lock()
	i.topCPU = head(byCPU, i.cfg.TopN)
	i.topMem = head(byMem, i.cfg.TopN)
	i.reportCPU = head(byCPU, i.cfg.ReportTopN)
	i.reportMem = head(byMem, i.cfg.ReportTopN)
	i.famCPU = famCPU
	i.famMem = famMem
	i.pidFamily = pidFamily
	i.mu.Unlock()
}

func sortedProcs(all []model.ProcessStats, less func(a, b model.ProcessStats) bool) []model.ProcessStats {
	out := make([]model.ProcessStats, len(all))
	copy(out, all)
	sort.SliceStable(out, func(a, b int) bool { return less(out[a], out[b]) })
	return out
}

func head[T any](s []T, n int) []T {
	if len(s) > n {
		s = s[:n]
	}
	out := make([]T, len(s))
	copy(out, s)
	return out
}
```

5e. Add accessors after `TopMem`:

```go
// ReportTopCPU / ReportTopMem return process.report_top_n processes for
// process_report (independent of the legacy top_n list).
func (i *Inspector) ReportTopCPU() []model.ProcessStats { return i.copyProcs(func() []model.ProcessStats { return i.reportCPU }) }
func (i *Inspector) ReportTopMem() []model.ProcessStats { return i.copyProcs(func() []model.ProcessStats { return i.reportMem }) }

// TopFamiliesCPU / TopFamiliesMem return the top report_top_n families.
func (i *Inspector) TopFamiliesCPU() []model.FamilyStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return head(i.famCPU, i.cfg.ReportTopN)
}

func (i *Inspector) TopFamiliesMem() []model.FamilyStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return head(i.famMem, i.cfg.ReportTopN)
}

// AllFamilies returns every family sorted by CPU desc (for Prometheus).
func (i *Inspector) AllFamilies() []model.FamilyStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return head(i.famCPU, len(i.famCPU))
}

// PIDFamilies returns a copy of the pid → family map from the last scan.
func (i *Inspector) PIDFamilies() map[uint32]string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make(map[uint32]string, len(i.pidFamily))
	for k, v := range i.pidFamily {
		out[k] = v
	}
	return out
}

func (i *Inspector) copyProcs(get func() []model.ProcessStats) []model.ProcessStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	src := get()
	out := make([]model.ProcessStats, len(src))
	copy(out, src)
	return out
}
```

- [ ] **Step 6: Update config**

In `ProcessConfig` add:

```go
	// ReportTopN: processes and families per list in process_report.
	ReportTopN int `yaml:"report_top_n"`
	// FamilyBy: "systemd_unit" (default) or "cgroup" (full cgroup path).
	FamilyBy string `yaml:"family_by"`
	// MaxConnectionsPerProcess caps the live connection list per process.
	MaxConnectionsPerProcess int `yaml:"max_connections_per_process"`
	// MaxPeersPerProcess caps network.top_peers per process / family.
	MaxPeersPerProcess int `yaml:"max_peers_per_process"`
```

In `Defaults()` `Process:` block add:

```go
			ReportTopN:               10,
			FamilyBy:                 "systemd_unit",
			MaxConnectionsPerProcess: 50,
			MaxPeersPerProcess:       20,
```

In `validate()` after the `process.top_n` check add:

```go
	if c.Process.ReportTopN <= 0 {
		return fmt.Errorf("process.report_top_n must be > 0")
	}
	if c.Process.FamilyBy != "systemd_unit" && c.Process.FamilyBy != "cgroup" {
		return fmt.Errorf("process.family_by must be systemd_unit or cgroup")
	}
	if c.Process.MaxConnectionsPerProcess <= 0 || c.Process.MaxPeersPerProcess <= 0 {
		return fmt.Errorf("process.max_connections_per_process and max_peers_per_process must be > 0")
	}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `gofmt -w internal/ && go vet ./internal/process/ ./internal/config/ && go test ./internal/process/ ./internal/config/`
Expected: vet clean; `ok` for both.

- [ ] **Step 8: Commit**

```bash
git add internal/model/types.go internal/process/family.go internal/process/family_test.go \
        internal/process/inspector.go internal/process/inspector_test.go \
        internal/config/config.go internal/config/config_test.go
git commit -m "feat(process): group processes into systemd-unit families

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 9: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): cgroup parsing for v1/v2/hybrid, family root selection, inspector locking. Report findings only."`
Fix confirmed findings, re-run Step 7, commit `fix(process): address review`.

---

### Task 4: On-demand connection inventory (`netinv`)

**Files:**
- Modify: `internal/model/types.go` (append `ListenPort`, `Connection`, `ProcessConnections`)
- Create: `internal/netinv/netinv.go`
- Test: `internal/netinv/netinv_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `model.ListenPort{Proto, Addr string; Port uint16}` (json `proto`, `addr`, `port`)
  - `model.Connection{Direction, State, Src, Dst string}` (json `direction`, `state`, `src`, `dst`)
  - `model.ProcessConnections{ListeningPorts []ListenPort; Connections []Connection; Truncated int; Error string}`
  - `netinv.Socket{Proto string; Local, Remote netip.AddrPort; State string; Inode uint64}`
  - `func ParseNetTCP(r io.Reader, proto string) ([]Socket, error)`
  - `func New(procRoot string) *Inventory` (`""` → `/proc`)
  - `func (*Inventory) Sockets() ([]Socket, error)`, `Listening() ([]Socket, error)`
  - `func ListenPorts(socks []Socket) []uint16` — distinct, ascending
  - `func (*Inventory) ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections`

- [ ] **Step 1: Add model types**

Append to `internal/model/types.go`:

```go
// ─── Connection inventory ─────────────────────────────────────────────────────

// ListenPort is one listening socket owned by a process.
type ListenPort struct {
	Proto string `json:"proto"` // "tcp" | "tcp6"
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
}

// Connection is one live TCP connection, always rendered client → server:
// inbound = remote client → us, outbound = us → remote server.
type Connection struct {
	Direction string `json:"direction"` // "inbound" | "outbound"
	State     string `json:"state"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
}

// ProcessConnections is the /proc-derived socket inventory of one process.
type ProcessConnections struct {
	ListeningPorts []ListenPort `json:"listening_ports"`
	Connections    []Connection `json:"connections"`
	Truncated      int          `json:"connections_truncated"`
	Error          string       `json:"connections_error,omitempty"`
}
```

- [ ] **Step 2: Write the failing test**

```go
// internal/netinv/netinv_test.go
package netinv

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func v4hex(addr string, port uint16) string {
	ip := netip.MustParseAddr(addr).As4()
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], port)
}

func v6hex(addr string, port uint16) string {
	b := netip.MustParseAddr(addr).As16()
	var s strings.Builder
	for w := 0; w < 4; w++ {
		for k := 3; k >= 0; k-- {
			fmt.Fprintf(&s, "%02X", b[w*4+k])
		}
	}
	return fmt.Sprintf("%s:%04X", s.String(), port)
}

func row(i int, local, remote, st string, inode uint64) string {
	return fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000  1000 0 %d 1 0000000000000000 20 4 30 10 -1\n",
		i, local, remote, st, inode)
}

func TestParseNetTCPLiteral(t *testing.T) {
	in := header + row(0, "0100007F:0CEA", "00000000:0000", "0A", 1001)
	socks, err := ParseNetTCP(strings.NewReader(in), "tcp")
	if err != nil || len(socks) != 1 {
		t.Fatalf("socks=%v err=%v", socks, err)
	}
	s := socks[0]
	if s.Local.String() != "127.0.0.1:3306" || s.State != "LISTEN" || s.Inode != 1001 || s.Proto != "tcp" {
		t.Fatalf("parsed %+v", s)
	}
}

func TestParseNetTCP6UnmapsV4(t *testing.T) {
	in := header +
		row(0, "00000000000000000000000001000000:0CEA", "00000000000000000000000000000000:0000", "0A", 1) +
		row(1, v6hex("::ffff:10.0.1.7", 3306), v6hex("::ffff:10.0.3.15", 51844), "01", 2)
	socks, err := ParseNetTCP(strings.NewReader(in), "tcp6")
	if err != nil || len(socks) != 2 {
		t.Fatalf("socks=%v err=%v", socks, err)
	}
	if socks[0].Local.String() != "[::1]:3306" {
		t.Fatalf("v6 loopback = %s", socks[0].Local)
	}
	if socks[1].Remote.String() != "10.0.3.15:51844" || socks[1].State != "ESTABLISHED" {
		t.Fatalf("v4-mapped peer not unmapped: %+v", socks[1])
	}
}

// fakeProc builds <root>/net/tcp, <root>/net/tcp6 and <root>/<pid>/fd/*.
func fakeProc(t *testing.T, tcp string, fds map[uint32][]string) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(header+tcp), 0o644))
	must(os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(header), 0o644))
	for pid, targets := range fds {
		dir := filepath.Join(root, fmt.Sprint(pid), "fd")
		must(os.MkdirAll(dir, 0o755))
		for i, target := range targets {
			must(os.Symlink(target, filepath.Join(dir, fmt.Sprint(i+3))))
		}
	}
	return root
}

func TestForPIDs(t *testing.T) {
	tcp := row(0, v4hex("0.0.0.0", 3306), v4hex("0.0.0.0", 0), "0A", 1001) +
		row(1, v4hex("10.0.1.7", 3306), v4hex("10.0.3.15", 51844), "01", 1002) +
		row(2, v4hex("10.0.1.7", 40000), v4hex("10.0.5.2", 3306), "01", 1003) +
		row(3, v4hex("10.0.1.7", 3306), v4hex("10.0.3.16", 50000), "06", 0) +
		row(4, v4hex("10.0.1.7", 3306), v4hex("10.0.3.17", 50001), "08", 1004)
	root := fakeProc(t, tcp, map[uint32][]string{
		2314: {"socket:[1001]", "socket:[1002]", "socket:[1003]", "socket:[1004]", "socket:[1002]", "/dev/null"},
	})
	got := New(root).ForPIDs([]uint32{2314, 9999}, 50)

	pc := got[2314]
	if pc.Error != "" {
		t.Fatalf("error: %s", pc.Error)
	}
	if len(pc.ListeningPorts) != 1 || pc.ListeningPorts[0] != (modelListen("tcp", "0.0.0.0", 3306)) {
		t.Fatalf("listening = %+v", pc.ListeningPorts)
	}
	want := []string{
		"inbound ESTABLISHED 10.0.3.15:51844 -> 10.0.1.7:3306",
		"outbound ESTABLISHED 10.0.1.7:40000 -> 10.0.5.2:3306",
		"inbound CLOSE_WAIT 10.0.3.17:50001 -> 10.0.1.7:3306",
		"inbound TIME_WAIT 10.0.3.16:50000 -> 10.0.1.7:3306",
	}
	if len(pc.Connections) != len(want) {
		t.Fatalf("connections = %+v", pc.Connections)
	}
	for i, c := range pc.Connections {
		if s := fmt.Sprintf("%s %s %s -> %s", c.Direction, c.State, c.Src, c.Dst); s != want[i] {
			t.Fatalf("conn %d = %q, want %q", i, s, want[i])
		}
	}
	if got[9999].Error == "" {
		t.Fatal("missing pid should report an error")
	}
}

func TestForPIDsCapsAndCountsTruncated(t *testing.T) {
	var tcp strings.Builder
	tcp.WriteString(row(0, v4hex("0.0.0.0", 3306), v4hex("0.0.0.0", 0), "0A", 1))
	fds := []string{"socket:[1]"}
	for i := 0; i < 60; i++ {
		ino := uint64(100 + i)
		tcp.WriteString(row(i+1, v4hex("10.0.1.7", 3306), v4hex("10.0.3.15", uint16(40000+i)), "01", ino))
		fds = append(fds, fmt.Sprintf("socket:[%d]", ino))
	}
	for i := 0; i < 5; i++ {
		tcp.WriteString(row(100+i, v4hex("10.0.1.7", 3306), v4hex("10.0.3.99", uint16(30000+i)), "06", 0))
	}
	root := fakeProc(t, tcp.String(), map[uint32][]string{1: fds})
	pc := New(root).ForPIDs([]uint32{1}, 50)[1]
	if len(pc.Connections) != 50 || pc.Truncated != 15 {
		t.Fatalf("len=%d truncated=%d", len(pc.Connections), pc.Truncated)
	}
	for _, c := range pc.Connections {
		if c.State != "ESTABLISHED" {
			t.Fatalf("ESTABLISHED must sort first, got %s", c.State)
		}
	}
}

func TestListenPorts(t *testing.T) {
	socks := []Socket{
		{State: "LISTEN", Local: netip.MustParseAddrPort("0.0.0.0:3306")},
		{State: "LISTEN", Local: netip.MustParseAddrPort("[::]:3306")},
		{State: "LISTEN", Local: netip.MustParseAddrPort("127.0.0.1:22")},
		{State: "ESTABLISHED", Local: netip.MustParseAddrPort("10.0.0.1:40000")},
	}
	got := ListenPorts(socks)
	if fmt.Sprint(got) != "[22 3306]" {
		t.Fatalf("ListenPorts = %v", got)
	}
}

func modelListen(proto, addr string, port uint16) model.ListenPort {
	return model.ListenPort{Proto: proto, Addr: addr, Port: port}
}
```

Add `"github.com/manhvu1997/linux-obs-agent/internal/model"` to the test's imports.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/netinv/`
Expected: FAIL — `undefined: ParseNetTCP`, `undefined: New`.

- [ ] **Step 4: Write the implementation**

```go
// internal/netinv/netinv.go

// Package netinv builds an on-demand TCP socket inventory from /proc:
// listening ports and live connections per process, mapped through
// /proc/<pid>/fd socket inodes. It runs only when /api/diagnose is called
// (plus a cheap LISTEN-only read used by netflow), so it costs nothing
// between calls.
package netinv

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// Socket is one row of /proc/net/tcp or /proc/net/tcp6.
type Socket struct {
	Proto  string // "tcp" | "tcp6"
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  string
	Inode  uint64 // 0 for TIME_WAIT (no owning file)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// ParseNetTCP parses the /proc/net/tcp{,6} format. Malformed rows are skipped.
func ParseNetTCP(r io.Reader, proto string) ([]Socket, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []Socket
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err := parseHexAddrPort(f[1])
		if err != nil {
			continue
		}
		remote, err := parseHexAddrPort(f[2])
		if err != nil {
			continue
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		st, ok := tcpStates[strings.ToUpper(f[3])]
		if !ok {
			st = "UNKNOWN"
		}
		out = append(out, Socket{Proto: proto, Local: local, Remote: remote, State: st, Inode: inode})
	}
	return out, sc.Err()
}

// parseHexAddrPort decodes "0100007F:0CEA". The kernel prints the address as
// host-endian 32-bit words (little-endian on x86/arm64); the port is plain hex.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("netinv: bad address %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ip netip.Addr
	switch len(raw) {
	case 4:
		ip = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			for k := 0; k < 4; k++ {
				b[w*4+k] = raw[w*4+3-k]
			}
		}
		ip = netip.AddrFrom16(b).Unmap()
	default:
		return netip.AddrPort{}, fmt.Errorf("netinv: bad address length %q", s)
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// Inventory reads sockets under a proc root ("/proc" in production).
type Inventory struct{ root string }

func New(procRoot string) *Inventory {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Inventory{root: procRoot}
}

// Sockets returns all TCP sockets in the agent's network namespace.
func (v *Inventory) Sockets() ([]Socket, error) {
	var all []Socket
	for _, p := range []struct{ file, proto string }{{"net/tcp", "tcp"}, {"net/tcp6", "tcp6"}} {
		f, err := os.Open(filepath.Join(v.root, p.file))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		socks, err := ParseNetTCP(f, p.proto)
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, socks...)
	}
	return all, nil
}

// Listening returns LISTEN sockets only.
func (v *Inventory) Listening() ([]Socket, error) {
	all, err := v.Sockets()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, s := range all {
		if s.State == "LISTEN" {
			out = append(out, s)
		}
	}
	return out, nil
}

// ListenPorts returns the distinct local ports of the LISTEN sockets, ascending.
func ListenPorts(socks []Socket) []uint16 {
	seen := make(map[uint16]bool)
	var out []uint16
	for _, s := range socks {
		if s.State != "LISTEN" || seen[s.Local.Port()] {
			continue
		}
		seen[s.Local.Port()] = true
		out = append(out, s.Local.Port())
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ForPIDs returns listening ports and live connections for each pid.
// Connections are sorted ESTABLISHED, CLOSE_WAIT, TIME_WAIT, others and
// capped at maxConns (Truncated counts the rest). A connection is inbound when
// its local port is any LISTEN port on the host. TIME_WAIT sockets have no
// owning fd; they are attributed (as inbound) to processes that listen on
// their local port, otherwise omitted.
func (v *Inventory) ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections {
	out := make(map[uint32]model.ProcessConnections, len(pids))
	socks, err := v.Sockets()
	if err != nil {
		for _, p := range pids {
			out[p] = model.ProcessConnections{Error: err.Error()}
		}
		return out
	}
	byInode := make(map[uint64]Socket, len(socks))
	hostListen := make(map[uint16]bool)
	var timeWait []Socket
	for _, s := range socks {
		if s.Inode != 0 {
			byInode[s.Inode] = s
		}
		switch s.State {
		case "LISTEN":
			hostListen[s.Local.Port()] = true
		case "TIME_WAIT":
			timeWait = append(timeWait, s)
		}
	}
	for _, pid := range pids {
		if _, done := out[pid]; done {
			continue
		}
		out[pid] = v.forPID(pid, byInode, hostListen, timeWait, maxConns)
	}
	return out
}

func (v *Inventory) forPID(pid uint32, byInode map[uint64]Socket, hostListen map[uint16]bool,
	timeWait []Socket, maxConns int) model.ProcessConnections {
	pc := model.ProcessConnections{ListeningPorts: []model.ListenPort{}, Connections: []model.Connection{}}
	inodes, err := socketInodes(filepath.Join(v.root, strconv.FormatUint(uint64(pid), 10), "fd"))
	if err != nil {
		pc.Error = err.Error()
		return pc
	}
	ownListen := make(map[uint16]bool)
	seenListen := make(map[model.ListenPort]bool)
	var conns []model.Connection
	for _, ino := range inodes {
		s, ok := byInode[ino]
		if !ok {
			continue
		}
		if s.State == "LISTEN" {
			lp := model.ListenPort{Proto: s.Proto, Addr: s.Local.Addr().String(), Port: s.Local.Port()}
			if !seenListen[lp] {
				seenListen[lp] = true
				pc.ListeningPorts = append(pc.ListeningPorts, lp)
			}
			ownListen[s.Local.Port()] = true
			continue
		}
		conns = append(conns, toConnection(s, hostListen[s.Local.Port()]))
	}
	for _, s := range timeWait {
		if ownListen[s.Local.Port()] {
			conns = append(conns, toConnection(s, true))
		}
	}
	sort.SliceStable(conns, func(i, j int) bool { return stateRank(conns[i].State) < stateRank(conns[j].State) })
	if maxConns > 0 && len(conns) > maxConns {
		pc.Truncated = len(conns) - maxConns
		conns = conns[:maxConns]
	}
	if conns != nil {
		pc.Connections = conns
	}
	sort.Slice(pc.ListeningPorts, func(i, j int) bool {
		a, b := pc.ListeningPorts[i], pc.ListeningPorts[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Addr < b.Addr
	})
	return pc
}

func toConnection(s Socket, inbound bool) model.Connection {
	if inbound {
		return model.Connection{Direction: "inbound", State: s.State, Src: s.Remote.String(), Dst: s.Local.String()}
	}
	return model.Connection{Direction: "outbound", State: s.State, Src: s.Local.String(), Dst: s.Remote.String()}
}

func stateRank(st string) int {
	switch st {
	case "ESTABLISHED":
		return 0
	case "CLOSE_WAIT":
		return 1
	case "TIME_WAIT":
		return 2
	}
	return 3
}

// socketInodes returns the distinct socket inodes referenced by fdDir.
func socketInodes(fdDir string) ([]uint64, error) {
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	seen := make(map[uint64]bool)
	var out []uint64
	for _, e := range ents {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		ino, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
		if err != nil || seen[ino] {
			continue
		}
		seen[ino] = true
		out = append(out, ino)
	}
	return out, nil
}
```

Note the fd order in `TestForPIDs` relies on `os.ReadDir` sorting entries by name: fd names `3`..`8` are single digits, so lexical order equals numeric order.

- [ ] **Step 5: Run tests to verify they pass**

Run: `gofmt -w internal/ && go vet ./internal/netinv/ && go test ./internal/netinv/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/model/types.go internal/netinv/netinv.go internal/netinv/netinv_test.go
git commit -m "feat(netinv): on-demand per-process TCP connection inventory

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): /proc/net/tcp hex decoding (endianness, IPv6 words), direction rules, TIME_WAIT attribution, caps. Report findings only."`
Fix confirmed findings, re-run Step 5, commit `fix(netinv): address review`.

---

### Task 5: Flow accounting (`netflow`)

**Files:**
- Modify: `internal/model/types.go` (append `DirectionStats`, `PeerStats`, `NetworkSummary`)
- Create: `internal/netflow/flow.go`, `internal/netflow/accumulator.go`, `internal/netflow/analyzer.go`
- Modify: `internal/config/config.go` (new `NetflowConfig`)
- Test: `internal/netflow/accumulator_test.go`, `internal/netflow/analyzer_test.go`, extend `internal/config/config_test.go`

**Interfaces:**
- Consumes: `netinv.Socket`, `netinv.ListenPorts` (Task 4).
- Produces:
  - `model.DirectionStats{ConnsActive int64; ConnsOpened, ConnsClosed, BytesRx, BytesTx uint64; BytesRxPerSec, BytesTxPerSec float64}`
  - `model.PeerStats{Direction, PeerIP string; ServicePort uint16; ConnsActive int64; BytesRx, BytesTx uint64}`
  - `model.NetworkSummary{Inbound, Outbound DirectionStats; TopPeers []PeerStats}`
  - `netflow.Direction` (`Inbound = 1`, `Outbound = 2` — must equal the BPF `DIR_IN`/`DIR_OUT`), `func (Direction) String() string`
  - `netflow.FlowKey{TGID uint32; Dir Direction; Peer netip.Addr; ServicePort uint16}`, `netflow.FlowValue{BytesTx, BytesRx, Opened, Closed uint64}`
  - `func PeerFromBytes(b [16]byte) netip.Addr`
  - `type Source interface { ReadFlows() (map[FlowKey]FlowValue, error); SetListenPorts(ports []uint16) error; InboundAccounting() string }`
  - `netflow.Config{Window time.Duration; MaxFamilies, MaxOutboundPeers, MaxPeersPerProcess int; LabelIdleTTL, PIDIdleTTL time.Duration}`
  - `func NewAccumulator(cfg Config) *Accumulator`; `(*Accumulator).Ingest(now time.Time, cur map[FlowKey]FlowValue, pidFamily map[uint32]string)`; `Process(tgid uint32) model.NetworkSummary`; `Family(name string) model.NetworkSummary`; `WindowSeconds() int`; `Counters() Counters`
  - `netflow.Counters{Dir []FamilyDirCounter; Inbound []FamilyPortCounter; Outbound []FamilyPeerCounter}` with `FamilyDirCounter{Family, Direction string; BytesRx, BytesTx, Opened uint64; Active int64}`, `FamilyPortCounter{Family string; ServicePort uint16; BytesRx, BytesTx uint64}`, `FamilyPeerCounter{Family, PeerIP string; ServicePort uint16; BytesRx, BytesTx uint64}`
  - `func NewAnalyzer(src Source, inv ListenLister, procs FamilyLookup, acc *Accumulator, poll, listenEvery time.Duration) *Analyzer`; `(*Analyzer).Run(ctx)`; `(*Analyzer).PollOnce(now time.Time)`; `(*Analyzer).RefreshListen()`
  - `type ListenLister interface { Listening() ([]netinv.Socket, error) }`, `type FamilyLookup interface { PIDFamilies() map[uint32]string }`
  - `config.NetflowConfig{Enabled bool; PollInterval, Window time.Duration; IncludeLoopback bool; ListenRefreshInterval time.Duration; MaxFamilies, MaxOutboundPeers int}` at `Config.Netflow` (`yaml:"netflow"`)

- [ ] **Step 1: Add model types**

Append to `internal/model/types.go`:

```go
// ─── Network flows (eBPF netflow) ─────────────────────────────────────────────

// DirectionStats are TCP totals for one direction over the report window.
// Inbound = connections the process accepted; outbound = connections it
// initiated. Rx/Tx are bytes received/sent on those connections.
type DirectionStats struct {
	ConnsActive   int64   `json:"conns_active"`
	ConnsOpened   uint64  `json:"conns_opened"`
	ConnsClosed   uint64  `json:"conns_closed"`
	BytesRx       uint64  `json:"bytes_rx"`
	BytesTx       uint64  `json:"bytes_tx"`
	BytesRxPerSec float64 `json:"bytes_rx_per_sec"`
	BytesTxPerSec float64 `json:"bytes_tx_per_sec"`
}

// PeerStats aggregates traffic with one remote IP on one service port.
type PeerStats struct {
	Direction   string `json:"direction"`
	PeerIP      string `json:"peer_ip"`
	ServicePort uint16 `json:"service_port"`
	ConnsActive int64  `json:"conns_active"`
	BytesRx     uint64 `json:"bytes_rx"`
	BytesTx     uint64 `json:"bytes_tx"`
}

// NetworkSummary is the eBPF-derived network view of a process or family.
type NetworkSummary struct {
	Inbound  DirectionStats `json:"inbound"`
	Outbound DirectionStats `json:"outbound"`
	TopPeers []PeerStats    `json:"top_peers"`
}
```

- [ ] **Step 2: Write the failing tests**

```go
// internal/netflow/accumulator_test.go
package netflow

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

func cfg() Config { return Config{MaxPeersPerProcess: 20} }

func k(tgid uint32, dir Direction, peer string, port uint16) FlowKey {
	return FlowKey{TGID: tgid, Dir: dir, Peer: netip.MustParseAddr(peer), ServicePort: port}
}

func TestDeltaAcrossEviction(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Outbound, "10.0.5.2", 3306)
	fam := map[uint32]string{10: "app.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {BytesTx: 100}}, fam)
	a.Ingest(t0.Add(5*time.Second), map[FlowKey]FlowValue{key: {BytesTx: 150}}, fam)
	// Entry evicted from the LRU and re-created: value restarts below previous.
	a.Ingest(t0.Add(10*time.Second), map[FlowKey]FlowValue{key: {BytesTx: 30}}, fam)
	if got := a.Process(10).Outbound.BytesTx; got != 180 {
		t.Fatalf("window tx = %d, want 180", got)
	}
	c := a.Counters()
	if len(c.Dir) != 1 || c.Dir[0].BytesTx != 180 || c.Dir[0].Family != "app.service" || c.Dir[0].Direction != "outbound" {
		t.Fatalf("counters = %+v", c.Dir)
	}
}

func TestWindowRollOffKeepsCounters(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {BytesRx: 500}}, fam)
	a.Ingest(t0.Add(90*time.Second), map[FlowKey]FlowValue{key: {BytesRx: 500}}, fam)
	if got := a.Process(10).Inbound.BytesRx; got != 0 {
		t.Fatalf("window rx = %d, want 0 after roll-off", got)
	}
	if got := a.Counters().Dir[0].BytesRx; got != 500 {
		t.Fatalf("lifetime counter = %d, want 500", got)
	}
}

func TestActiveConnections(t *testing.T) {
	a := NewAccumulator(cfg())
	key := k(10, Inbound, "10.0.3.15", 3306)
	fam := map[uint32]string{10: "mysql.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{key: {Opened: 3, Closed: 1}}, fam)
	s := a.Process(10)
	if s.Inbound.ConnsActive != 2 || s.Inbound.ConnsOpened != 3 || s.Inbound.ConnsClosed != 1 {
		t.Fatalf("inbound = %+v", s.Inbound)
	}
	if len(s.TopPeers) != 1 || s.TopPeers[0].ConnsActive != 2 {
		t.Fatalf("peers = %+v", s.TopPeers)
	}
	// More closes than opens (pre-existing connections) never go negative.
	a.Ingest(t0.Add(5*time.Second), map[FlowKey]FlowValue{key: {Opened: 3, Closed: 6}}, fam)
	if got := a.Process(10).Inbound.ConnsActive; got != 0 {
		t.Fatalf("active = %d, want clamped 0", got)
	}
}

func TestFamilyAggregation(t *testing.T) {
	a := NewAccumulator(cfg())
	fam := map[uint32]string{1301: "php-fpm.service", 1302: "php-fpm.service", 99: "other.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1301, Outbound, "10.0.5.2", 3306): {BytesTx: 10, BytesRx: 100},
		k(1302, Outbound, "10.0.5.2", 3306): {BytesTx: 20, BytesRx: 200},
		k(99, Outbound, "10.0.5.2", 3306):   {BytesTx: 1000},
	}, fam)
	s := a.Family("php-fpm.service")
	if s.Outbound.BytesTx != 30 || s.Outbound.BytesRx != 300 {
		t.Fatalf("family outbound = %+v", s.Outbound)
	}
	if len(s.TopPeers) != 1 || s.TopPeers[0].BytesRx != 300 {
		t.Fatalf("merged peers = %+v", s.TopPeers)
	}
}

func TestOutboundPeerLabelCap(t *testing.T) {
	c := cfg()
	c.MaxOutboundPeers = 2
	a := NewAccumulator(c)
	fam := map[uint32]string{1: "app.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1},
		k(1, Outbound, "10.0.0.2", 443): {BytesTx: 2},
		k(1, Outbound, "10.0.0.3", 443): {BytesTx: 4},
	}, fam)
	var total uint64
	labels := map[string]bool{}
	for _, o := range a.Counters().Outbound {
		total += o.BytesTx
		labels[o.PeerIP] = true
	}
	if len(labels) != 3 || !labels["other"] || total != 7 {
		t.Fatalf("labels=%v total=%d", labels, total)
	}
}

func TestFamilyLabelCap(t *testing.T) {
	c := cfg()
	c.MaxFamilies = 1
	a := NewAccumulator(c)
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Inbound, "10.0.0.1", 80): {BytesRx: 1},
		k(2, Inbound, "10.0.0.1", 80): {BytesRx: 2},
	}, map[uint32]string{1: "a.service", 2: "b.service"})
	// Which family wins the single slot depends on map iteration order;
	// assert the invariant instead: one real label + "other", nothing lost.
	fams := map[string]uint64{}
	var total uint64
	for _, d := range a.Counters().Dir {
		fams[d.Family] += d.BytesRx
		total += d.BytesRx
	}
	if len(fams) != 2 || fams["other"] == 0 || total != 3 {
		t.Fatalf("families = %v", fams)
	}
}

func TestLabelExpiryDropsCounters(t *testing.T) {
	c := cfg()
	c.LabelIdleTTL = time.Minute
	a := NewAccumulator(c)
	fam := map[uint32]string{1: "app.service"}
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1}}, fam)
	a.Ingest(t0.Add(2*time.Minute), map[FlowKey]FlowValue{}, fam)
	if n := len(a.Counters().Outbound); n != 0 {
		t.Fatalf("expired peer label still exported (%d series)", n)
	}
}

func TestTopPeersCapAndOrder(t *testing.T) {
	c := cfg()
	c.MaxPeersPerProcess = 2
	a := NewAccumulator(c)
	a.Ingest(t0, map[FlowKey]FlowValue{
		k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1},
		k(1, Outbound, "10.0.0.2", 443): {BytesTx: 50},
		k(1, Inbound, "10.0.0.3", 80):   {BytesRx: 20},
	}, map[uint32]string{1: "app.service"})
	p := a.Process(1).TopPeers
	if len(p) != 2 || p[0].PeerIP != "10.0.0.2" || p[1].PeerIP != "10.0.0.3" || p[1].Direction != "inbound" {
		t.Fatalf("top peers = %+v", p)
	}
}

func TestProcessRatesFiniteAfterFirstIngest(t *testing.T) {
	a := NewAccumulator(cfg())
	a.Ingest(t0, map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.1", 443): {BytesTx: 1000}}, nil)
	s := a.Process(1)
	if s.Outbound.BytesTxPerSec != 0 {
		t.Fatalf("rate with zero elapsed = %v, want 0", s.Outbound.BytesTxPerSec)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatalf("summary not JSON-encodable: %v", err)
	}
	a.Ingest(t0.Add(10*time.Second), map[FlowKey]FlowValue{k(1, Outbound, "10.0.0.1", 443): {BytesTx: 2000}}, nil)
	if got := a.Process(1).Outbound.BytesTxPerSec; got != 200 {
		t.Fatalf("rate = %v, want 200 B/s", got)
	}
}

func TestUnknownProcessHasEmptyPeers(t *testing.T) {
	s := NewAccumulator(cfg()).Process(42)
	if s.TopPeers == nil {
		t.Fatal("TopPeers must be an empty slice, not nil (JSON [] not null)")
	}
}

func TestPeerFromBytesUnmapsV4(t *testing.T) {
	var b [16]byte
	b[10], b[11] = 0xff, 0xff
	copy(b[12:], []byte{10, 0, 0, 1})
	if got := PeerFromBytes(b).String(); got != "10.0.0.1" {
		t.Fatalf("PeerFromBytes = %s", got)
	}
	v6 := netip.MustParseAddr("2001:db8::1").As16()
	if got := PeerFromBytes(v6).String(); got != "2001:db8::1" {
		t.Fatalf("PeerFromBytes v6 = %s", got)
	}
}
```

```go
// internal/netflow/analyzer_test.go
package netflow

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/netinv"
)

type fakeSource struct {
	flows  map[FlowKey]FlowValue
	err    error
	listen []uint16
}

func (f *fakeSource) ReadFlows() (map[FlowKey]FlowValue, error) { return f.flows, f.err }
func (f *fakeSource) SetListenPorts(p []uint16) error          { f.listen = p; return nil }
func (f *fakeSource) InboundAccounting() string                 { return "accept" }

type fakeInv struct{ socks []netinv.Socket }

func (f fakeInv) Listening() ([]netinv.Socket, error) { return f.socks, nil }

type fakeProcs map[uint32]string

func (f fakeProcs) PIDFamilies() map[uint32]string { return f }

func TestAnalyzerPollAndListen(t *testing.T) {
	src := &fakeSource{flows: map[FlowKey]FlowValue{k(7, Inbound, "10.0.0.9", 3306): {BytesRx: 42}}}
	inv := fakeInv{socks: []netinv.Socket{{State: "LISTEN", Local: netip.MustParseAddrPort("0.0.0.0:3306")}}}
	acc := NewAccumulator(cfg())
	an := NewAnalyzer(src, inv, fakeProcs{7: "mysql.service"}, acc, 5*time.Second, 30*time.Second)

	an.RefreshListen()
	if len(src.listen) != 1 || src.listen[0] != 3306 {
		t.Fatalf("listen ports pushed = %v", src.listen)
	}
	an.PollOnce(t0)
	if got := acc.Family("mysql.service").Inbound.BytesRx; got != 42 {
		t.Fatalf("family rx = %d", got)
	}

	src.err = errors.New("map read failed")
	an.PollOnce(t0.Add(5 * time.Second)) // must not panic or reset counters
	if got := acc.Counters().Dir[0].BytesRx; got != 42 {
		t.Fatalf("counter after failed poll = %d", got)
	}
}
```

Append to `internal/config/config_test.go`:

```go
func TestNetflowDefaultsAndValidation(t *testing.T) {
	n := Defaults().Netflow
	if !n.Enabled || n.PollInterval != 5*time.Second || n.Window != 60*time.Second || !n.IncludeLoopback ||
		n.ListenRefreshInterval != 30*time.Second || n.MaxFamilies != 50 || n.MaxOutboundPeers != 100 {
		t.Fatalf("netflow defaults = %+v", n)
	}
	c := Defaults()
	c.Netflow.Window = time.Second
	if err := c.validate(); err == nil {
		t.Fatal("window < poll_interval must be rejected")
	}
}

func TestNetflowEnvOverride(t *testing.T) {
	t.Setenv("NETFLOW_ENABLED", "false")
	t.Setenv("NETFLOW_INCLUDE_LOOPBACK", "no")
	c := Defaults()
	applyNetflowEnvOverrides(c)
	if c.Netflow.Enabled || c.Netflow.IncludeLoopback {
		t.Fatalf("env overrides not applied: %+v", c.Netflow)
	}
}
```

Add `"time"` to the config test imports.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/netflow/ ./internal/config/`
Expected: FAIL — `undefined: NewAccumulator`, `c.Netflow undefined`.

- [ ] **Step 4: Implement `flow.go`**

```go
// internal/netflow/flow.go

// Package netflow turns the in-kernel per-(process, direction, peer, port)
// TCP counters into windowed per-process / per-family summaries and
// monotonic Prometheus counters. It depends only on the Source interface, so
// it is testable without eBPF; internal/ebpf/netflow implements Source.
package netflow

import "net/netip"

// Direction values must match DIR_IN / DIR_OUT in netflow.bpf.c.
type Direction uint8

const (
	Inbound  Direction = 1 // the process accepted the connection
	Outbound Direction = 2 // the process initiated the connection
)

func (d Direction) String() string {
	switch d {
	case Inbound:
		return "inbound"
	case Outbound:
		return "outbound"
	}
	return "unknown"
}

// FlowKey identifies one aggregation bucket. ServicePort is the local
// listening port for inbound and the remote port for outbound — never the
// client's ephemeral port.
type FlowKey struct {
	TGID        uint32
	Dir         Direction
	Peer        netip.Addr
	ServicePort uint16
}

// FlowValue holds cumulative kernel counters for a FlowKey.
type FlowValue struct {
	BytesTx uint64
	BytesRx uint64
	Opened  uint64
	Closed  uint64
}

// Source is implemented by the eBPF loader.
type Source interface {
	ReadFlows() (map[FlowKey]FlowValue, error)
	SetListenPorts(ports []uint16) error
	// InboundAccounting is "accept" when inet_csk_accept is hooked, "lazy"
	// when inbound sockets are only adopted on first bytes.
	InboundAccounting() string
}

// PeerFromBytes converts the BPF 16-byte peer (IPv4 stored v4-mapped) to an
// address, unmapping IPv4 so dual-stack clients are not counted twice.
func PeerFromBytes(b [16]byte) netip.Addr { return netip.AddrFrom16(b).Unmap() }
```

- [ ] **Step 5: Implement `accumulator.go`**

```go
// internal/netflow/accumulator.go
package netflow

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

const (
	otherLabel    = "other"
	unknownFamily = "unknown"
)

// Config tunes the accumulator. Zero values take the documented defaults.
type Config struct {
	Window             time.Duration // 60s
	MaxFamilies        int           // 50
	MaxOutboundPeers   int           // 100
	MaxPeersPerProcess int           // 20
	LabelIdleTTL       time.Duration // 1h
	PIDIdleTTL         time.Duration // 10m
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 60 * time.Second
	}
	if c.MaxFamilies <= 0 {
		c.MaxFamilies = 50
	}
	if c.MaxOutboundPeers <= 0 {
		c.MaxOutboundPeers = 100
	}
	if c.MaxPeersPerProcess <= 0 {
		c.MaxPeersPerProcess = 20
	}
	if c.LabelIdleTTL <= 0 {
		c.LabelIdleTTL = time.Hour
	}
	if c.PIDIdleTTL <= 0 {
		c.PIDIdleTTL = 10 * time.Minute
	}
	return c
}

type FamilyDirCounter struct {
	Family, Direction string
	BytesRx, BytesTx  uint64
	Opened            uint64
	Active            int64
}

type FamilyPortCounter struct {
	Family           string
	ServicePort      uint16
	BytesRx, BytesTx uint64
}

type FamilyPeerCounter struct {
	Family, PeerIP   string
	ServicePort      uint16
	BytesRx, BytesTx uint64
}

// Counters is a point-in-time copy of the lifetime counters.
type Counters struct {
	Dir      []FamilyDirCounter
	Inbound  []FamilyPortCounter
	Outbound []FamilyPeerCounter
}

type famDirKey struct {
	fam string
	dir Direction
}
type famPortKey struct {
	fam  string
	port uint16
}
type famPeerKey struct {
	fam, peer string
	port      uint16
}
type dirCounter struct{ rx, tx, opened uint64 }
type byteCounter struct{ rx, tx uint64 }

type sample struct {
	at     time.Time
	deltas map[FlowKey]FlowValue
}

// labelBudget hands out at most max distinct label values; later values map
// to "other". Idle values are released after a TTL.
type labelBudget struct {
	max  int
	seen map[string]time.Time
}

func (b *labelBudget) label(v string, now time.Time) string {
	if _, ok := b.seen[v]; ok || len(b.seen) < b.max {
		b.seen[v] = now
		return v
	}
	return otherLabel
}

func (b *labelBudget) peek(v string) string {
	if _, ok := b.seen[v]; ok {
		return v
	}
	return otherLabel
}

func (b *labelBudget) expire(now time.Time, ttl time.Duration) map[string]bool {
	gone := make(map[string]bool)
	for v, t := range b.seen {
		if now.Sub(t) > ttl {
			delete(b.seen, v)
			gone[v] = true
		}
	}
	return gone
}

// Accumulator is safe for concurrent use.
type Accumulator struct {
	mu        sync.Mutex
	cfg       Config
	prev      map[FlowKey]FlowValue
	samples   []sample
	firstAt   time.Time
	lastAt    time.Time
	active    map[FlowKey]int64
	pidSeen   map[uint32]time.Time
	pidFamily map[uint32]string

	famDir     map[famDirKey]*dirCounter
	famIn      map[famPortKey]*byteCounter
	famOut     map[famPeerKey]*byteCounter
	famLabels  labelBudget
	peerLabels labelBudget
}

func NewAccumulator(cfg Config) *Accumulator {
	cfg = cfg.withDefaults()
	return &Accumulator{
		cfg:        cfg,
		prev:       make(map[FlowKey]FlowValue),
		active:     make(map[FlowKey]int64),
		pidSeen:    make(map[uint32]time.Time),
		pidFamily:  make(map[uint32]string),
		famDir:     make(map[famDirKey]*dirCounter),
		famIn:      make(map[famPortKey]*byteCounter),
		famOut:     make(map[famPeerKey]*byteCounter),
		famLabels:  labelBudget{max: cfg.MaxFamilies, seen: make(map[string]time.Time)},
		peerLabels: labelBudget{max: cfg.MaxOutboundPeers, seen: make(map[string]time.Time)},
	}
}

func delta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur // LRU entry evicted and re-created since the last poll
}

// Ingest records one poll of the kernel map. cur is owned by the
// accumulator afterwards. Keys absent from cur were evicted; if they
// reappear they count from zero.
func (a *Accumulator) Ingest(now time.Time, cur map[FlowKey]FlowValue, pidFamily map[uint32]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.firstAt.IsZero() {
		a.firstAt = now
	}
	a.lastAt = now
	if pidFamily != nil {
		a.pidFamily = pidFamily
	}

	deltas := make(map[FlowKey]FlowValue)
	for k, v := range cur {
		p := a.prev[k]
		d := FlowValue{
			BytesTx: delta(v.BytesTx, p.BytesTx), BytesRx: delta(v.BytesRx, p.BytesRx),
			Opened: delta(v.Opened, p.Opened), Closed: delta(v.Closed, p.Closed),
		}
		if d != (FlowValue{}) {
			deltas[k] = d
			a.pidSeen[k.TGID] = now
		}
	}
	a.prev = cur

	a.samples = append(a.samples, sample{at: now, deltas: deltas})
	cut := 0
	for cut < len(a.samples) && now.Sub(a.samples[cut].at) > a.cfg.Window {
		cut++
	}
	a.samples = a.samples[cut:]

	for k, d := range deltas {
		a.active[k] += int64(d.Opened) - int64(d.Closed)
		fam := a.famLabels.label(a.familyOf(k.TGID), now)
		dc := a.famDir[famDirKey{fam, k.Dir}]
		if dc == nil {
			dc = &dirCounter{}
			a.famDir[famDirKey{fam, k.Dir}] = dc
		}
		dc.rx += d.BytesRx
		dc.tx += d.BytesTx
		dc.opened += d.Opened
		if k.Dir == Inbound {
			bc := a.famIn[famPortKey{fam, k.ServicePort}]
			if bc == nil {
				bc = &byteCounter{}
				a.famIn[famPortKey{fam, k.ServicePort}] = bc
			}
			bc.rx += d.BytesRx
			bc.tx += d.BytesTx
		} else {
			peer := a.peerLabels.label(k.Peer.String(), now)
			pk := famPeerKey{fam, peer, k.ServicePort}
			bc := a.famOut[pk]
			if bc == nil {
				bc = &byteCounter{}
				a.famOut[pk] = bc
			}
			bc.rx += d.BytesRx
			bc.tx += d.BytesTx
		}
	}

	for tgid, seen := range a.pidSeen {
		if now.Sub(seen) > a.cfg.PIDIdleTTL {
			delete(a.pidSeen, tgid)
			for k := range a.active {
				if k.TGID == tgid {
					delete(a.active, k)
				}
			}
		}
	}
	if gone := a.famLabels.expire(now, a.cfg.LabelIdleTTL); len(gone) > 0 {
		for k := range a.famDir {
			if gone[k.fam] {
				delete(a.famDir, k)
			}
		}
		for k := range a.famIn {
			if gone[k.fam] {
				delete(a.famIn, k)
			}
		}
		for k := range a.famOut {
			if gone[k.fam] {
				delete(a.famOut, k)
			}
		}
	}
	if gone := a.peerLabels.expire(now, a.cfg.LabelIdleTTL); len(gone) > 0 {
		for k := range a.famOut {
			if gone[k.peer] {
				delete(a.famOut, k)
			}
		}
	}
}

func (a *Accumulator) familyOf(tgid uint32) string {
	if f, ok := a.pidFamily[tgid]; ok && f != "" {
		return f
	}
	return unknownFamily
}

// WindowSeconds is the configured window length in seconds.
func (a *Accumulator) WindowSeconds() int { return int(a.cfg.Window / time.Second) }

// Process summarises one tgid over the window.
func (a *Accumulator) Process(tgid uint32) model.NetworkSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.summary(func(t uint32) bool { return t == tgid })
}

// Family summarises every tgid currently mapped to the family.
func (a *Accumulator) Family(name string) model.NetworkSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.summary(func(t uint32) bool { return a.familyOf(t) == name })
}

type peerKey struct {
	dir  Direction
	peer netip.Addr
	port uint16
}

func (a *Accumulator) summary(match func(uint32) bool) model.NetworkSummary {
	var s model.NetworkSummary
	peers := make(map[peerKey]*model.PeerStats)
	peerOf := func(k FlowKey) *model.PeerStats {
		pk := peerKey{k.Dir, k.Peer, k.ServicePort}
		p := peers[pk]
		if p == nil {
			p = &model.PeerStats{Direction: k.Dir.String(), PeerIP: k.Peer.String(), ServicePort: k.ServicePort}
			peers[pk] = p
		}
		return p
	}
	dirOf := func(d Direction) *model.DirectionStats {
		if d == Inbound {
			return &s.Inbound
		}
		return &s.Outbound
	}
	for _, smp := range a.samples {
		for k, d := range smp.deltas {
			if !match(k.TGID) {
				continue
			}
			ds := dirOf(k.Dir)
			ds.BytesRx += d.BytesRx
			ds.BytesTx += d.BytesTx
			ds.ConnsOpened += d.Opened
			ds.ConnsClosed += d.Closed
			p := peerOf(k)
			p.BytesRx += d.BytesRx
			p.BytesTx += d.BytesTx
		}
	}
	for k, n := range a.active {
		if n <= 0 || !match(k.TGID) {
			continue
		}
		dirOf(k.Dir).ConnsActive += n
		peerOf(k).ConnsActive += n
	}

	elapsed := a.lastAt.Sub(a.firstAt)
	if elapsed > a.cfg.Window {
		elapsed = a.cfg.Window
	}
	if secs := elapsed.Seconds(); secs > 0 {
		for _, ds := range []*model.DirectionStats{&s.Inbound, &s.Outbound} {
			ds.BytesRxPerSec = float64(ds.BytesRx) / secs
			ds.BytesTxPerSec = float64(ds.BytesTx) / secs
		}
	}

	s.TopPeers = make([]model.PeerStats, 0, len(peers))
	for _, p := range peers {
		s.TopPeers = append(s.TopPeers, *p)
	}
	sort.Slice(s.TopPeers, func(i, j int) bool {
		a, b := s.TopPeers[i], s.TopPeers[j]
		if a.BytesRx+a.BytesTx != b.BytesRx+b.BytesTx {
			return a.BytesRx+a.BytesTx > b.BytesRx+b.BytesTx
		}
		if a.ConnsActive != b.ConnsActive {
			return a.ConnsActive > b.ConnsActive
		}
		if a.PeerIP != b.PeerIP {
			return a.PeerIP < b.PeerIP
		}
		return a.ServicePort < b.ServicePort
	})
	if len(s.TopPeers) > a.cfg.MaxPeersPerProcess {
		s.TopPeers = s.TopPeers[:a.cfg.MaxPeersPerProcess]
	}
	return s
}

// Counters returns sorted copies of the lifetime counters for Prometheus.
func (a *Accumulator) Counters() Counters {
	a.mu.Lock()
	defer a.mu.Unlock()

	dir := make(map[famDirKey]*FamilyDirCounter)
	for k, c := range a.famDir {
		dir[k] = &FamilyDirCounter{Family: k.fam, Direction: k.dir.String(), BytesRx: c.rx, BytesTx: c.tx, Opened: c.opened}
	}
	for k, n := range a.active {
		if n <= 0 {
			continue
		}
		dk := famDirKey{a.famLabels.peek(a.familyOf(k.TGID)), k.Dir}
		d := dir[dk]
		if d == nil {
			d = &FamilyDirCounter{Family: dk.fam, Direction: dk.dir.String()}
			dir[dk] = d
		}
		d.Active += n
	}
	var out Counters
	for _, d := range dir {
		out.Dir = append(out.Dir, *d)
	}
	for k, c := range a.famIn {
		out.Inbound = append(out.Inbound, FamilyPortCounter{Family: k.fam, ServicePort: k.port, BytesRx: c.rx, BytesTx: c.tx})
	}
	for k, c := range a.famOut {
		out.Outbound = append(out.Outbound, FamilyPeerCounter{Family: k.fam, PeerIP: k.peer, ServicePort: k.port, BytesRx: c.rx, BytesTx: c.tx})
	}
	sort.Slice(out.Dir, func(i, j int) bool {
		if out.Dir[i].Family != out.Dir[j].Family {
			return out.Dir[i].Family < out.Dir[j].Family
		}
		return out.Dir[i].Direction < out.Dir[j].Direction
	})
	sort.Slice(out.Inbound, func(i, j int) bool {
		if out.Inbound[i].Family != out.Inbound[j].Family {
			return out.Inbound[i].Family < out.Inbound[j].Family
		}
		return out.Inbound[i].ServicePort < out.Inbound[j].ServicePort
	})
	sort.Slice(out.Outbound, func(i, j int) bool {
		x, y := out.Outbound[i], out.Outbound[j]
		if x.Family != y.Family {
			return x.Family < y.Family
		}
		if x.PeerIP != y.PeerIP {
			return x.PeerIP < y.PeerIP
		}
		return x.ServicePort < y.ServicePort
	})
	return out
}
```

- [ ] **Step 6: Implement `analyzer.go`**

```go
// internal/netflow/analyzer.go
package netflow

import (
	"context"
	"log/slog"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/netinv"
)

// ListenLister lists LISTEN sockets (implemented by *netinv.Inventory).
type ListenLister interface {
	Listening() ([]netinv.Socket, error)
}

// FamilyLookup maps PIDs to families (implemented by *process.Inspector).
type FamilyLookup interface {
	PIDFamilies() map[uint32]string
}

// Analyzer polls a Source into an Accumulator and keeps the kernel's
// listen_ports map current so lazily adopted sockets get the right direction.
type Analyzer struct {
	src         Source
	inv         ListenLister
	procs       FamilyLookup
	acc         *Accumulator
	poll        time.Duration
	listenEvery time.Duration
}

func NewAnalyzer(src Source, inv ListenLister, procs FamilyLookup, acc *Accumulator, poll, listenEvery time.Duration) *Analyzer {
	return &Analyzer{src: src, inv: inv, procs: procs, acc: acc, poll: poll, listenEvery: listenEvery}
}

// Run blocks until ctx is cancelled.
func (a *Analyzer) Run(ctx context.Context) {
	a.RefreshListen()
	pt := time.NewTicker(a.poll)
	defer pt.Stop()
	lt := time.NewTicker(a.listenEvery)
	defer lt.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-pt.C:
			a.PollOnce(now)
		case <-lt.C:
			a.RefreshListen()
		}
	}
}

// PollOnce reads the kernel map once. A failed read is logged and skipped;
// counters are never reset.
func (a *Analyzer) PollOnce(now time.Time) {
	flows, err := a.src.ReadFlows()
	if err != nil {
		slog.Warn("netflow: reading flow map", "err", err)
		return
	}
	a.acc.Ingest(now, flows, a.procs.PIDFamilies())
}

// RefreshListen pushes the host's listening ports into the kernel map.
func (a *Analyzer) RefreshListen() {
	socks, err := a.inv.Listening()
	if err != nil {
		slog.Warn("netflow: listing listening sockets", "err", err)
		return
	}
	if err := a.src.SetListenPorts(netinv.ListenPorts(socks)); err != nil {
		slog.Warn("netflow: updating listen_ports map", "err", err)
	}
}
```

- [ ] **Step 7: Add `NetflowConfig`**

In `internal/config/config.go`:

Add to `Config` after `MySQL`: `Netflow NetflowConfig `yaml:"netflow"``.

Add the type:

```go
// NetflowConfig controls always-on per-process TCP flow accounting
// (eBPF netflow module). It feeds process_report.network and the
// obs_agent_family_net_* Prometheus metrics.
type NetflowConfig struct {
	// Enabled is the master switch. Default true. Env NETFLOW_ENABLED.
	Enabled bool `yaml:"enabled"`
	// PollInterval: how often the in-kernel flow map is read.
	PollInterval time.Duration `yaml:"poll_interval"`
	// Window: length of the bytes/connection window in process_report.
	Window time.Duration `yaml:"window"`
	// IncludeLoopback counts 127.0.0.0/8 and ::1 traffic. Env NETFLOW_INCLUDE_LOOPBACK.
	IncludeLoopback bool `yaml:"include_loopback"`
	// ListenRefreshInterval: how often listening ports are pushed to the kernel.
	ListenRefreshInterval time.Duration `yaml:"listen_refresh_interval"`
	// MaxFamilies caps the family label; overflow → "other".
	MaxFamilies int `yaml:"max_families"`
	// MaxOutboundPeers caps the peer_ip label per node; overflow → "other".
	MaxOutboundPeers int `yaml:"max_outbound_peers"`
}
```

In `Defaults()` add:

```go
		Netflow: NetflowConfig{
			Enabled:               true,
			PollInterval:          5 * time.Second,
			Window:                60 * time.Second,
			IncludeLoopback:       true,
			ListenRefreshInterval: 30 * time.Second,
			MaxFamilies:           50,
			MaxOutboundPeers:      100,
		},
```

Add the override function and call `applyNetflowEnvOverrides(cfg)` in **both** branches of `Load` (next to `applyMySQLEnvOverrides(cfg)`):

```go
// applyNetflowEnvOverrides:
//
//	NETFLOW_ENABLED=true|false           – master switch
//	NETFLOW_INCLUDE_LOOPBACK=true|false  – count loopback traffic
func applyNetflowEnvOverrides(cfg *Config) {
	if v := os.Getenv("NETFLOW_ENABLED"); v != "" {
		cfg.Netflow.Enabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("NETFLOW_INCLUDE_LOOPBACK"); v != "" {
		cfg.Netflow.IncludeLoopback = v == "true" || v == "1" || v == "yes"
	}
}
```

In `validate()` add:

```go
	if c.Netflow.Enabled {
		if c.Netflow.PollInterval <= 0 || c.Netflow.Window < c.Netflow.PollInterval {
			return fmt.Errorf("netflow.window must be >= netflow.poll_interval > 0")
		}
		if c.Netflow.ListenRefreshInterval <= 0 || c.Netflow.MaxFamilies < 1 || c.Netflow.MaxOutboundPeers < 1 {
			return fmt.Errorf("netflow.listen_refresh_interval, max_families and max_outbound_peers must be > 0")
		}
	}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `gofmt -w internal/ && go vet ./internal/netflow/ ./internal/config/ && go test -race ./internal/netflow/ ./internal/config/`
Expected: `ok` for both.

- [ ] **Step 9: Commit**

```bash
git add internal/model/types.go internal/netflow/ internal/config/config.go internal/config/config_test.go
git commit -m "feat(netflow): windowed per-process/family flow accounting with bounded labels

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 10: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): counter monotonicity across LRU eviction, label-budget expiry, active-connection clamping, rate math, locking. Report findings only."`
Fix confirmed findings, re-run Step 8, commit `fix(netflow): address review`.

---

### Task 6: `process_report` builder

**Files:**
- Modify: `internal/model/types.go` (append `ProcessEntry`, `FamilyEntry`, `ProcessReport`; add field to `DiagnoseReport`)
- Create: `internal/procreport/procreport.go`
- Test: `internal/procreport/procreport_test.go`

**Interfaces:**
- Consumes: `model.ProcessStats`, `model.FamilyStats` (Task 3); `model.ProcessConnections` (Task 4); `model.NetworkSummary` (Task 5).
- Produces:
  - `model.ProcessEntry`, `model.FamilyEntry` (embeds `FamilyStats`), `model.ProcessReport{Type string; Timestamp time.Time; WindowSeconds int; NetworkSource, InboundAccounting string; TopCPU, TopMem []ProcessEntry; TopFamiliesCPU, TopFamiliesMem []FamilyEntry}`
  - `model.DiagnoseReport.ProcessReport *ProcessReport` (json `process_report,omitempty`)
  - `procreport.NetSource interface { Process(tgid uint32) model.NetworkSummary; Family(name string) model.NetworkSummary }` — satisfied by `*netflow.Accumulator`
  - `procreport.InventorySource interface { ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections }` — satisfied by `*netinv.Inventory`
  - `procreport.Inputs{TopCPU, TopMem []model.ProcessStats; FamiliesCPU, FamiliesMem []model.FamilyStats; Net NetSource; NetworkSource, InboundAccounting string; WindowSeconds int; Inventory InventorySource; MaxConnections int}`
  - `func Build(in Inputs, now time.Time) *model.ProcessReport`

- [ ] **Step 1: Add model types**

Append to `internal/model/types.go`:

```go
// ─── Process report ───────────────────────────────────────────────────────────

// ProcessEntry is one process in process_report.
type ProcessEntry struct {
	PID                  uint32          `json:"pid"`
	PPID                 uint32          `json:"ppid"`
	Comm                 string          `json:"comm"`
	Cmdline              string          `json:"cmdline"`
	Family               string          `json:"family"`
	CPUPercent           float64         `json:"cpu_percent"`
	MemRSSBytes          uint64          `json:"mem_rss_bytes"`
	MemPercent           float64         `json:"mem_percent"`
	Threads              uint32          `json:"threads"`
	OpenFiles            int             `json:"open_files"`
	ListeningPorts       []ListenPort    `json:"listening_ports"`
	Network              *NetworkSummary `json:"network,omitempty"`
	Connections          []Connection    `json:"connections"`
	ConnectionsTruncated int             `json:"connections_truncated"`
	ConnectionsError     string          `json:"connections_error,omitempty"`
	ProfileURL           string          `json:"profile_url"`
}

// FamilyEntry is one process family in process_report. No connection list:
// drill into TopMembers[].PID instead.
type FamilyEntry struct {
	FamilyStats
	ListeningPorts []ListenPort     `json:"listening_ports"`
	Network        *NetworkSummary `json:"network,omitempty"`
}

// ProcessReport answers "which process / service is heavy, and who is it
// talking to?" for GET /api/diagnose.
type ProcessReport struct {
	Type              string         `json:"type"` // always "process_analysis"
	Timestamp         time.Time      `json:"timestamp"`
	WindowSeconds     int            `json:"window_seconds"`
	NetworkSource     string         `json:"network_source"`
	InboundAccounting string         `json:"inbound_accounting,omitempty"`
	TopCPU            []ProcessEntry `json:"top_cpu"`
	TopMem            []ProcessEntry `json:"top_mem"`
	TopFamiliesCPU    []FamilyEntry  `json:"top_families_cpu"`
	TopFamiliesMem    []FamilyEntry  `json:"top_families_mem"`
}
```

In `DiagnoseReport`, directly after the `TopProcesses` field, add:

```go
	// ProcessReport lists the top processes and process families by CPU and
	// memory with their network activity and live connections.
	ProcessReport *ProcessReport `json:"process_report,omitempty"`
```

- [ ] **Step 2: Write the failing test**

```go
// internal/procreport/procreport_test.go
package procreport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

type fakeNet struct{}

func (fakeNet) Process(tgid uint32) model.NetworkSummary {
	return model.NetworkSummary{Inbound: model.DirectionStats{BytesTx: uint64(tgid)}, TopPeers: []model.PeerStats{}}
}
func (fakeNet) Family(name string) model.NetworkSummary {
	return model.NetworkSummary{Outbound: model.DirectionStats{BytesTx: uint64(len(name))}, TopPeers: []model.PeerStats{}}
}

type fakeInv struct{ calls [][]uint32 }

func (f *fakeInv) ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections {
	f.calls = append(f.calls, pids)
	out := map[uint32]model.ProcessConnections{}
	for _, p := range pids {
		switch p {
		case 1022: // php-fpm master owns the listener
			out[p] = model.ProcessConnections{ListeningPorts: []model.ListenPort{{Proto: "tcp", Addr: "0.0.0.0", Port: 9000}}}
		case 1301: // worker inherited the same listener
			out[p] = model.ProcessConnections{
				ListeningPorts: []model.ListenPort{{Proto: "tcp", Addr: "0.0.0.0", Port: 9000}},
				Connections:    []model.Connection{{Direction: "inbound", State: "ESTABLISHED", Src: "10.0.0.9:50000", Dst: "10.0.0.1:9000"}},
				Truncated:      3,
			}
		}
	}
	return out
}

func inputs(inv *fakeInv) Inputs {
	return Inputs{
		TopCPU: []model.ProcessStats{{PID: 1301, PPID: 1022, Comm: "php-fpm", Family: "php-fpm.service", CPUPercent: 30}},
		TopMem: []model.ProcessStats{{PID: 1301, Comm: "php-fpm", Family: "php-fpm.service"}},
		FamiliesCPU: []model.FamilyStats{{
			Family: "php-fpm.service", RootPID: 1022, ProcessCount: 2,
			TopMembers: []model.FamilyMember{{PID: 1301}},
		}},
		NetworkSource: "ebpf", InboundAccounting: "accept", WindowSeconds: 60,
		Inventory: inv, MaxConnections: 50,
	}
}

func TestBuild(t *testing.T) {
	inv := &fakeInv{}
	in := inputs(inv)
	in.Net = fakeNet{}
	r := Build(in, time.Unix(0, 0))

	if r.Type != "process_analysis" || r.NetworkSource != "ebpf" || r.WindowSeconds != 60 {
		t.Fatalf("header = %+v", r)
	}
	if len(inv.calls) != 1 || len(inv.calls[0]) != 2 {
		t.Fatalf("inventory must be read once for the distinct pids {1301,1022}, got %v", inv.calls)
	}
	p := r.TopCPU[0]
	if p.ProfileURL != "/api/profile?pid=1301" || p.ConnectionsTruncated != 3 || len(p.Connections) != 1 {
		t.Fatalf("process entry = %+v", p)
	}
	if p.Network == nil || p.Network.Inbound.BytesTx != 1301 {
		t.Fatalf("process network = %+v", p.Network)
	}
	f := r.TopFamiliesCPU[0]
	if len(f.ListeningPorts) != 1 || f.ListeningPorts[0].Port != 9000 {
		t.Fatalf("family listening ports must be the de-duplicated union: %+v", f.ListeningPorts)
	}
	if f.Network == nil || f.Network.Outbound.BytesTx != uint64(len("php-fpm.service")) {
		t.Fatalf("family network = %+v", f.Network)
	}
	if r.TopFamiliesMem == nil {
		t.Fatal("empty lists must encode as [] not null")
	}
}

func TestBuildWithoutNetwork(t *testing.T) {
	in := inputs(&fakeInv{})
	in.Net = nil
	in.NetworkSource = "unavailable: kprobe tcp_sendmsg: permission denied"
	r := Build(in, time.Unix(0, 0))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"network":`) {
		t.Fatalf("network must be omitted when netflow is unavailable: %s", b)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/procreport/`
Expected: FAIL — `undefined: Build`, `undefined: Inputs`.

- [ ] **Step 4: Write the implementation**

```go
// internal/procreport/procreport.go

// Package procreport assembles process_report for GET /api/diagnose from the
// process inspector's top lists, the netflow accumulator and the /proc
// connection inventory. Pure: every dependency is an interface.
package procreport

import (
	"fmt"
	"sort"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
)

// NetSource is satisfied by *netflow.Accumulator.
type NetSource interface {
	Process(tgid uint32) model.NetworkSummary
	Family(name string) model.NetworkSummary
}

// InventorySource is satisfied by *netinv.Inventory.
type InventorySource interface {
	ForPIDs(pids []uint32, maxConns int) map[uint32]model.ProcessConnections
}

// Inputs to Build. Net must be a nil interface (not a typed nil pointer)
// when network accounting is unavailable.
type Inputs struct {
	TopCPU, TopMem           []model.ProcessStats
	FamiliesCPU, FamiliesMem []model.FamilyStats
	Net                      NetSource
	NetworkSource            string
	InboundAccounting        string
	WindowSeconds            int
	Inventory                InventorySource
	MaxConnections           int
}

func Build(in Inputs, now time.Time) *model.ProcessReport {
	var pids []uint32
	seen := make(map[uint32]bool)
	add := func(pid uint32) {
		if pid != 0 && !seen[pid] {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	for _, list := range [][]model.ProcessStats{in.TopCPU, in.TopMem} {
		for _, p := range list {
			add(p.PID)
		}
	}
	for _, list := range [][]model.FamilyStats{in.FamiliesCPU, in.FamiliesMem} {
		for _, f := range list {
			add(f.RootPID)
			for _, m := range f.TopMembers {
				add(m.PID)
			}
		}
	}
	conns := map[uint32]model.ProcessConnections{}
	if in.Inventory != nil && len(pids) > 0 {
		conns = in.Inventory.ForPIDs(pids, in.MaxConnections)
	}

	r := &model.ProcessReport{
		Type:              "process_analysis",
		Timestamp:         now,
		WindowSeconds:     in.WindowSeconds,
		NetworkSource:     in.NetworkSource,
		InboundAccounting: in.InboundAccounting,
		TopCPU:            make([]model.ProcessEntry, 0, len(in.TopCPU)),
		TopMem:            make([]model.ProcessEntry, 0, len(in.TopMem)),
		TopFamiliesCPU:    make([]model.FamilyEntry, 0, len(in.FamiliesCPU)),
		TopFamiliesMem:    make([]model.FamilyEntry, 0, len(in.FamiliesMem)),
	}
	for _, p := range in.TopCPU {
		r.TopCPU = append(r.TopCPU, processEntry(p, conns[p.PID], in.Net))
	}
	for _, p := range in.TopMem {
		r.TopMem = append(r.TopMem, processEntry(p, conns[p.PID], in.Net))
	}
	for _, f := range in.FamiliesCPU {
		r.TopFamiliesCPU = append(r.TopFamiliesCPU, familyEntry(f, conns, in.Net))
	}
	for _, f := range in.FamiliesMem {
		r.TopFamiliesMem = append(r.TopFamiliesMem, familyEntry(f, conns, in.Net))
	}
	return r
}

func processEntry(p model.ProcessStats, pc model.ProcessConnections, net NetSource) model.ProcessEntry {
	e := model.ProcessEntry{
		PID: p.PID, PPID: p.PPID, Comm: p.Comm, Cmdline: p.Cmdline, Family: p.Family,
		CPUPercent: p.CPUPercent, MemRSSBytes: p.MemRSSBytes, MemPercent: p.MemPercent,
		Threads: p.Threads, OpenFiles: p.OpenFiles,
		ListeningPorts:       nonNil(pc.ListeningPorts),
		Connections:          pc.Connections,
		ConnectionsTruncated: pc.Truncated,
		ConnectionsError:     pc.Error,
		ProfileURL:           fmt.Sprintf("/api/profile?pid=%d", p.PID),
	}
	if e.Connections == nil {
		e.Connections = []model.Connection{}
	}
	if net != nil {
		s := net.Process(p.PID)
		e.Network = &s
	}
	return e
}

func familyEntry(f model.FamilyStats, conns map[uint32]model.ProcessConnections, net NetSource) model.FamilyEntry {
	e := model.FamilyEntry{FamilyStats: f}
	seen := make(map[model.ListenPort]bool)
	pids := []uint32{f.RootPID}
	for _, m := range f.TopMembers {
		pids = append(pids, m.PID)
	}
	for _, pid := range pids {
		for _, lp := range conns[pid].ListeningPorts {
			if !seen[lp] {
				seen[lp] = true
				e.ListeningPorts = append(e.ListeningPorts, lp)
			}
		}
	}
	e.ListeningPorts = nonNil(e.ListeningPorts)
	sort.Slice(e.ListeningPorts, func(i, j int) bool { return e.ListeningPorts[i].Port < e.ListeningPorts[j].Port })
	if e.TopMembers == nil {
		e.TopMembers = []model.FamilyMember{}
	}
	if net != nil {
		s := net.Family(f.Family)
		e.Network = &s
	}
	return e
}

func nonNil(lp []model.ListenPort) []model.ListenPort {
	if lp == nil {
		return []model.ListenPort{}
	}
	return lp
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `gofmt -w internal/ && go vet ./internal/procreport/ && go test ./internal/procreport/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/model/types.go internal/procreport/
git commit -m "feat(procreport): build process_report from inspector, netflow and netinv

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): nil handling, JSON null vs [], duplicate inventory reads, listening-port union. Report findings only."`
Fix confirmed findings, re-run Step 5, commit `fix(procreport): address review`.

---

### Task 7: Prometheus collectors (`promcollect`)

**Files:**
- Create: `internal/promcollect/family.go`, `internal/promcollect/mysql.go`
- Test: `internal/promcollect/family_test.go`, `internal/promcollect/mysql_test.go`

**Interfaces:**
- Consumes: `model.FamilyStats` (Task 3); `netflow.Counters` (Task 5); `querystats.Snapshot` (Task 2).
- Produces:
  - `func NewFamilyCollector(families func() []model.FamilyStats, counters func() (netflow.Counters, bool), maxFamilies int) *FamilyCollector` (implements `prometheus.Collector`)
  - `func NewMySQLCollector(snap func() *querystats.Snapshot, dropped func() uint64) *MySQLCollector` (implements `prometheus.Collector`)
  - `func SanitizeLabel(s string, max int) string` — valid UTF-8, at most `max` bytes, cut on a rune boundary.

- [ ] **Step 1: Write the failing tests**

```go
// internal/promcollect/family_test.go
package promcollect

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

func families() []model.FamilyStats {
	return []model.FamilyStats{
		{Family: "mysql.service", CPUPercent: 80, MemRSSBytes: 6000, ProcessCount: 1},
		{Family: "php-fpm.service", CPUPercent: 64, MemRSSBytes: 180, ProcessCount: 3},
		{Family: "cron.service", CPUPercent: 3, MemRSSBytes: 5, ProcessCount: 2},
	}
}

func TestFamilyGaugesFoldOverflowIntoOther(t *testing.T) {
	c := NewFamilyCollector(families, func() (netflow.Counters, bool) { return netflow.Counters{}, false }, 2)
	want := `
# HELP obs_agent_family_cpu_percent CPU usage of all processes in a process family (systemd unit), percent of total CPU.
# TYPE obs_agent_family_cpu_percent gauge
obs_agent_family_cpu_percent{family="mysql.service"} 80
obs_agent_family_cpu_percent{family="other"} 3
obs_agent_family_cpu_percent{family="php-fpm.service"} 64
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_cpu_percent"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_family_net_bytes_total"); n != 0 {
		t.Fatalf("net metrics must be absent when netflow is unavailable, got %d", n)
	}
}

func TestFamilyNetCounters(t *testing.T) {
	counters := netflow.Counters{
		Dir:      []netflow.FamilyDirCounter{{Family: "mysql.service", Direction: "inbound", BytesRx: 10, BytesTx: 900, Opened: 4, Active: 3}},
		Inbound:  []netflow.FamilyPortCounter{{Family: "mysql.service", ServicePort: 3306, BytesRx: 10, BytesTx: 900}},
		Outbound: []netflow.FamilyPeerCounter{{Family: "app.service", PeerIP: "10.0.5.2", ServicePort: 3306, BytesRx: 900, BytesTx: 10}},
	}
	c := NewFamilyCollector(families, func() (netflow.Counters, bool) { return counters, true }, 50)
	want := `
# HELP obs_agent_family_outbound_peer_bytes_total Outbound TCP bytes per process family, remote peer IP and remote service port.
# TYPE obs_agent_family_outbound_peer_bytes_total counter
obs_agent_family_outbound_peer_bytes_total{family="app.service",flow="rx",peer_ip="10.0.5.2",service_port="3306"} 900
obs_agent_family_outbound_peer_bytes_total{family="app.service",flow="tx",peer_ip="10.0.5.2",service_port="3306"} 10
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "obs_agent_family_outbound_peer_bytes_total"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "obs_agent_family_net_bytes_total"); n != 2 {
		t.Fatalf("net_bytes series = %d, want rx+tx = 2", n)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("pedantic gather: %v", err)
	}
}
```

```go
// internal/promcollect/mysql_test.go
package promcollect

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func snap(text string) *querystats.Snapshot {
	return &querystats.Snapshot{
		Commands: map[string]model.QueryCounters{"query": {Calls: 2, CPUNs: 1_500_000_000, RunqNs: 500_000_000, WallNs: 3_000_000_000, BytesIn: 100, BytesOut: 9000}},
		Exported: []querystats.ExportedDigest{{ID: "aaa", Text: text, Counters: model.QueryCounters{Calls: 2, CPUNs: 1_500_000_000, BytesOut: 9000}}},
	}
}

func TestMySQLCollector(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap("select * from t") }, func() uint64 { return 7 })
	want := `
# HELP obs_agent_mysql_digest_cpu_seconds_total On-CPU seconds spent executing statements of this digest.
# TYPE obs_agent_mysql_digest_cpu_seconds_total counter
obs_agent_mysql_digest_cpu_seconds_total{digest_id="aaa"} 1.5
# HELP obs_agent_mysql_events_dropped_total Per-statement events lost (ring buffer full or consumer behind); digest totals undercount when this rises.
# TYPE obs_agent_mysql_events_dropped_total counter
obs_agent_mysql_events_dropped_total 7
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"obs_agent_mysql_digest_cpu_seconds_total", "obs_agent_mysql_events_dropped_total"); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLCollectorNilSnapshot(t *testing.T) {
	c := NewMySQLCollector(func() *querystats.Snapshot { return nil }, func() uint64 { return 0 })
	if n := testutil.CollectAndCount(c, "obs_agent_mysql_queries_total"); n != 0 {
		t.Fatalf("got %d series before any snapshot", n)
	}
}

func TestMySQLCollectorInvalidUTF8Label(t *testing.T) {
	long := strings.Repeat("ễ", 100) + "\xff"
	c := NewMySQLCollector(func() *querystats.Snapshot { return snap(long) }, func() uint64 { return 0 })
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed — one bad digest must not break /metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "obs_agent_mysql_digest_info" {
			continue
		}
		for _, lp := range mf.GetMetric()[0].GetLabel() {
			if lp.GetName() == "digest_text" && (!utf8.ValidString(lp.GetValue()) || len(lp.GetValue()) > 120) {
				t.Fatalf("digest_text label invalid or too long (%d bytes)", len(lp.GetValue()))
			}
		}
	}
}

func TestSanitizeLabel(t *testing.T) {
	if got := SanitizeLabel("abcdef", 4); got != "abcd" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeLabel("ễễ", 4); got != "ễ" { // 3-byte rune; never split it
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/promcollect/`
Expected: FAIL — `undefined: NewFamilyCollector`, `undefined: NewMySQLCollector`.

- [ ] **Step 3: Implement `family.go`**

```go
// internal/promcollect/family.go

// Package promcollect exposes process-family and MySQL digest data as
// Prometheus metrics. Collectors read analyzer snapshots at scrape time, so
// a label that disappears from the snapshot disappears from /metrics.
package promcollect

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/model"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

var (
	famCPUDesc = prometheus.NewDesc("obs_agent_family_cpu_percent",
		"CPU usage of all processes in a process family (systemd unit), percent of total CPU.", []string{"family"}, nil)
	famMemDesc = prometheus.NewDesc("obs_agent_family_mem_rss_bytes",
		"Resident memory of all processes in a process family.", []string{"family"}, nil)
	famProcsDesc = prometheus.NewDesc("obs_agent_family_processes",
		"Number of processes in a process family.", []string{"family"}, nil)
	famNetBytesDesc = prometheus.NewDesc("obs_agent_family_net_bytes_total",
		"TCP bytes per process family, direction (inbound = accepted, outbound = initiated) and flow (rx|tx).",
		[]string{"family", "direction", "flow"}, nil)
	famOpenedDesc = prometheus.NewDesc("obs_agent_family_net_connections_opened_total",
		"TCP connections opened per process family and direction.", []string{"family", "direction"}, nil)
	famActiveDesc = prometheus.NewDesc("obs_agent_family_net_connections_active",
		"Open TCP connections per process family and direction, as tracked by eBPF.", []string{"family", "direction"}, nil)
	famInDesc = prometheus.NewDesc("obs_agent_family_inbound_bytes_total",
		"Inbound TCP bytes per process family and local service port.", []string{"family", "service_port", "flow"}, nil)
	famOutDesc = prometheus.NewDesc("obs_agent_family_outbound_peer_bytes_total",
		"Outbound TCP bytes per process family, remote peer IP and remote service port.",
		[]string{"family", "peer_ip", "service_port", "flow"}, nil)
)

// FamilyCollector exports family gauges and netflow counters.
type FamilyCollector struct {
	families    func() []model.FamilyStats
	counters    func() (netflow.Counters, bool)
	maxFamilies int
}

func NewFamilyCollector(families func() []model.FamilyStats, counters func() (netflow.Counters, bool), maxFamilies int) *FamilyCollector {
	if maxFamilies < 1 {
		maxFamilies = 50
	}
	return &FamilyCollector{families: families, counters: counters, maxFamilies: maxFamilies}
}

func (c *FamilyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{famCPUDesc, famMemDesc, famProcsDesc, famNetBytesDesc, famOpenedDesc, famActiveDesc, famInDesc, famOutDesc} {
		ch <- d
	}
}

func (c *FamilyCollector) Collect(ch chan<- prometheus.Metric) {
	fams := c.families()
	sort.SliceStable(fams, func(i, j int) bool {
		if fams[i].CPUPercent != fams[j].CPUPercent {
			return fams[i].CPUPercent > fams[j].CPUPercent
		}
		return fams[i].Family < fams[j].Family
	})
	var other model.FamilyStats
	for i, f := range fams {
		if i >= c.maxFamilies || f.Family == "other" {
			other.CPUPercent += f.CPUPercent
			other.MemRSSBytes += f.MemRSSBytes
			other.ProcessCount += f.ProcessCount
			continue
		}
		emitFamily(ch, SanitizeLabel(f.Family, 200), f)
	}
	if other.ProcessCount > 0 {
		emitFamily(ch, "other", other)
	}

	nc, ok := c.counters()
	if !ok {
		return
	}
	for _, d := range nc.Dir {
		fam := SanitizeLabel(d.Family, 200)
		ch <- prometheus.MustNewConstMetric(famNetBytesDesc, prometheus.CounterValue, float64(d.BytesRx), fam, d.Direction, "rx")
		ch <- prometheus.MustNewConstMetric(famNetBytesDesc, prometheus.CounterValue, float64(d.BytesTx), fam, d.Direction, "tx")
		ch <- prometheus.MustNewConstMetric(famOpenedDesc, prometheus.CounterValue, float64(d.Opened), fam, d.Direction)
		ch <- prometheus.MustNewConstMetric(famActiveDesc, prometheus.GaugeValue, float64(d.Active), fam, d.Direction)
	}
	for _, p := range nc.Inbound {
		fam, port := SanitizeLabel(p.Family, 200), strconv.Itoa(int(p.ServicePort))
		ch <- prometheus.MustNewConstMetric(famInDesc, prometheus.CounterValue, float64(p.BytesRx), fam, port, "rx")
		ch <- prometheus.MustNewConstMetric(famInDesc, prometheus.CounterValue, float64(p.BytesTx), fam, port, "tx")
	}
	for _, p := range nc.Outbound {
		fam, port := SanitizeLabel(p.Family, 200), strconv.Itoa(int(p.ServicePort))
		ch <- prometheus.MustNewConstMetric(famOutDesc, prometheus.CounterValue, float64(p.BytesRx), fam, p.PeerIP, port, "rx")
		ch <- prometheus.MustNewConstMetric(famOutDesc, prometheus.CounterValue, float64(p.BytesTx), fam, p.PeerIP, port, "tx")
	}
}

func emitFamily(ch chan<- prometheus.Metric, label string, f model.FamilyStats) {
	ch <- prometheus.MustNewConstMetric(famCPUDesc, prometheus.GaugeValue, f.CPUPercent, label)
	ch <- prometheus.MustNewConstMetric(famMemDesc, prometheus.GaugeValue, float64(f.MemRSSBytes), label)
	ch <- prometheus.MustNewConstMetric(famProcsDesc, prometheus.GaugeValue, float64(f.ProcessCount), label)
}

// SanitizeLabel returns s as valid UTF-8 of at most max bytes, never
// splitting a multi-byte rune. Invalid UTF-8 in a label value makes the
// whole /metrics scrape fail, so every free-text label goes through this.
func SanitizeLabel(s string, max int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= max {
		return s
	}
	cut := 0
	for i, r := range s {
		if i+utf8.RuneLen(r) > max {
			break
		}
		cut = i + utf8.RuneLen(r)
	}
	return s[:cut]
}
```

- [ ] **Step 4: Implement `mysql.go`**

```go
// internal/promcollect/mysql.go
package promcollect

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

const digestTextMaxBytes = 120

var (
	myQueriesDesc = prometheus.NewDesc("obs_agent_mysql_queries_total",
		"MySQL commands executed, by command class (query | stmt_execute | other).", []string{"command"}, nil)
	myCPUDesc = prometheus.NewDesc("obs_agent_mysql_query_cpu_seconds_total",
		"On-CPU seconds spent inside dispatch_command, by command class.", []string{"command"}, nil)
	myRunqDesc = prometheus.NewDesc("obs_agent_mysql_query_runq_wait_seconds_total",
		"Seconds MySQL worker threads waited for a CPU while executing commands.", []string{"command"}, nil)
	myWallDesc = prometheus.NewDesc("obs_agent_mysql_query_wall_seconds_total",
		"Wall-clock seconds spent inside dispatch_command, by command class.", []string{"command"}, nil)
	myBytesDesc = prometheus.NewDesc("obs_agent_mysql_query_bytes_total",
		"Bytes received (statement) and sent (result) per command class.", []string{"command", "flow"}, nil)
	myDigestCPUDesc = prometheus.NewDesc("obs_agent_mysql_digest_cpu_seconds_total",
		"On-CPU seconds spent executing statements of this digest.", []string{"digest_id"}, nil)
	myDigestCallsDesc = prometheus.NewDesc("obs_agent_mysql_digest_calls_total",
		"Executions of statements of this digest.", []string{"digest_id"}, nil)
	myDigestOutDesc = prometheus.NewDesc("obs_agent_mysql_digest_bytes_out_total",
		"Result bytes sent for statements of this digest.", []string{"digest_id"}, nil)
	myDigestRunqDesc = prometheus.NewDesc("obs_agent_mysql_digest_runq_wait_seconds_total",
		"Seconds statements of this digest waited for a CPU.", []string{"digest_id"}, nil)
	myDigestInfoDesc = prometheus.NewDesc("obs_agent_mysql_digest_info",
		"Normalised SQL text of a digest (value is always 1); join with * on(digest_id) group_left(digest_text).",
		[]string{"digest_id", "digest_text"}, nil)
	myDroppedDesc = prometheus.NewDesc("obs_agent_mysql_events_dropped_total",
		"Per-statement events lost (ring buffer full or consumer behind); digest totals undercount when this rises.", nil, nil)
)

// MySQLCollector exports MySQL command and sticky-digest counters.
type MySQLCollector struct {
	snap    func() *querystats.Snapshot
	dropped func() uint64
}

func NewMySQLCollector(snap func() *querystats.Snapshot, dropped func() uint64) *MySQLCollector {
	return &MySQLCollector{snap: snap, dropped: dropped}
}

func (c *MySQLCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{myQueriesDesc, myCPUDesc, myRunqDesc, myWallDesc, myBytesDesc,
		myDigestCPUDesc, myDigestCallsDesc, myDigestOutDesc, myDigestRunqDesc, myDigestInfoDesc, myDroppedDesc} {
		ch <- d
	}
}

func (c *MySQLCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.snap()
	if s == nil {
		return
	}
	sec := func(ns uint64) float64 { return float64(ns) / 1e9 }
	for cmd, q := range s.Commands {
		ch <- prometheus.MustNewConstMetric(myQueriesDesc, prometheus.CounterValue, float64(q.Calls), cmd)
		ch <- prometheus.MustNewConstMetric(myCPUDesc, prometheus.CounterValue, sec(q.CPUNs), cmd)
		ch <- prometheus.MustNewConstMetric(myRunqDesc, prometheus.CounterValue, sec(q.RunqNs), cmd)
		ch <- prometheus.MustNewConstMetric(myWallDesc, prometheus.CounterValue, sec(q.WallNs), cmd)
		ch <- prometheus.MustNewConstMetric(myBytesDesc, prometheus.CounterValue, float64(q.BytesIn), cmd, "in")
		ch <- prometheus.MustNewConstMetric(myBytesDesc, prometheus.CounterValue, float64(q.BytesOut), cmd, "out")
	}
	for _, d := range s.Exported {
		ch <- prometheus.MustNewConstMetric(myDigestCPUDesc, prometheus.CounterValue, sec(d.Counters.CPUNs), d.ID)
		ch <- prometheus.MustNewConstMetric(myDigestCallsDesc, prometheus.CounterValue, float64(d.Counters.Calls), d.ID)
		ch <- prometheus.MustNewConstMetric(myDigestOutDesc, prometheus.CounterValue, float64(d.Counters.BytesOut), d.ID)
		ch <- prometheus.MustNewConstMetric(myDigestRunqDesc, prometheus.CounterValue, sec(d.Counters.RunqNs), d.ID)
		ch <- prometheus.MustNewConstMetric(myDigestInfoDesc, prometheus.GaugeValue, 1, d.ID, SanitizeLabel(d.Text, digestTextMaxBytes))
	}
	ch <- prometheus.MustNewConstMetric(myDroppedDesc, prometheus.CounterValue, float64(c.dropped()))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `gofmt -w internal/ && go vet ./internal/promcollect/ && go test ./internal/promcollect/`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/promcollect/
git commit -m "feat(promcollect): bounded-cardinality family and MySQL digest metrics

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): Prometheus label cardinality, UTF-8 safety, counter vs gauge types, Describe/Collect consistency. Report findings only."`
Fix confirmed findings, re-run Step 5, commit `fix(promcollect): address review`.

---

### Task 8: eBPF `netflow` module (Linux build host)

**Files:**
- Create: `internal/ebpf/netflow/netflow.bpf.c`, `internal/ebpf/netflow/gen.go`, `internal/ebpf/netflow/loader.go`
- Test: `internal/ebpf/netflow/loader_integration_test.go`

**Interfaces:**
- Consumes: `netflow.FlowKey`, `netflow.FlowValue`, `netflow.Direction`, `netflow.PeerFromBytes`, `netflow.Source` (Task 5).
- Produces: `func NewLoader(includeLoopback bool) *Loader`; `(*Loader).Start() error`; `Stop()`; and the `netflow.Source` methods `ReadFlows`, `SetListenPorts`, `InboundAccounting`. Package name `netflow`; importers alias it `netflowbpf`.

**Where to run:** an x86_64 Linux host, kernel ≥ 5.4 with `/sys/kernel/btf/vmlinux`, with clang, llvm, libbpf-dev, bpftool and Go 1.26 (see AGENTS.md §9). Run `make vmlinux` once.

- [ ] **Step 1: Write the eBPF program**

```c
//go:build ignore
// Compiled by bpf2go, not the Go toolchain.

// netflow.bpf.c – always-on per-process TCP flow accounting.
//
// Aggregates bytes and connection counts per
//   {tgid, direction, family, peer IP, service port}
// in an LRU map that userspace reads every few seconds. No ring buffer.
//
// Attribution: several TCP state changes run in softirq where `current` is
// unrelated to the socket. The OWNER is therefore recorded only in
// process-context hooks (connect → SYN_SENT, accept return) and stored per
// socket in sock_meta; bytes are charged to the CURRENT tgid in
// tcp_sendmsg / tcp_cleanup_rbuf, which always run in the reading/writing
// process — so a socket handed from a parent to a forked worker is charged
// to the worker.
//
// service port = local listening port for inbound, remote port for outbound;
// the client's ephemeral port is never a key.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* Same x86-64 register frame as mysql_query.bpf.c (see the comment there). */
struct x86_regs {
    __u64 r15, r14, r13, r12, rbp, rbx;
    __u64 r11, r10, r9, r8;
    __u64 rax, rcx, rdx, rsi, rdi;
};

#define AF_INET         2
#define AF_INET6        10
#define PROTO_TCP       6
#define ST_ESTABLISHED  1
#define ST_SYN_SENT     2
#define ST_CLOSE        7
#define DIR_IN          1   /* must equal netflow.Inbound  */
#define DIR_OUT         2   /* must equal netflow.Outbound */

struct flow_key {
    __u32 tgid;
    __u8  dir;
    __u8  family;
    __u16 svc_port;   /* host byte order */
    __u8  peer[16];   /* IPv4 stored v4-mapped (::ffff:a.b.c.d) */
};

struct flow_val {
    __u64 bytes_tx;
    __u64 bytes_rx;
    __u64 opened;
    __u64 closed;
    __u64 last_seen_ns;
};

struct sock_meta {
    struct flow_key k;  /* k.tgid = owner recorded at connect/accept */
    __u8 established;
    __u8 ignored;       /* loopback while include_loopback == 0 */
    __u8 _pad[6];
};

struct flow_key *__flow_key_unused __attribute__((unused));
struct flow_val *__flow_val_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);               /* struct sock * */
    __type(value, struct sock_meta);
    __uint(max_entries, 65536);
} sock_meta SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);               /* tid */
    __type(value, __u64);             /* struct sock * passed to tcp_sendmsg */
    __uint(max_entries, 16384);
} send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 16384);
} flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);               /* local listening port, host order */
    __type(value, __u8);
    __uint(max_entries, 4096);
} listen_ports SEC(".maps");

const volatile __u8 include_loopback = 1;

static __always_inline int is_loopback(const __u8 *p)
{
    int zero10 = 1;
#pragma unroll
    for (int i = 0; i < 10; i++)
        if (p[i])
            zero10 = 0;
    if (!zero10)
        return 0;
    if (p[10] == 0xff && p[11] == 0xff && p[12] == 127)
        return 1;                                         /* 127.0.0.0/8 */
    return p[10] == 0 && p[11] == 0 && p[12] == 0 && p[13] == 0 &&
           p[14] == 0 && p[15] == 1;                       /* ::1 */
}

static __always_inline void set_v4(__u8 *peer, const void *addr4)
{
    __builtin_memset(peer, 0, 16);
    peer[10] = 0xff;
    peer[11] = 0xff;
    __builtin_memcpy(&peer[12], addr4, 4);
}

static __always_inline int fill_from_sk(struct sock *sk, struct flow_key *k, __u8 dir)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        __be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        set_v4(k->peer, &d);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&k->peer, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    } else {
        return -1;
    }
    k->family = (__u8)family;
    k->dir = dir;
    if (dir == DIR_IN)
        k->svc_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    else
        k->svc_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    return 0;
}

static __always_inline void bump(const struct flow_key *k, __u64 tx, __u64 rx, __u64 op, __u64 cl)
{
    struct flow_val *v = bpf_map_lookup_elem(&flow_stats, k);
    if (!v) {
        struct flow_val zero = {};
        bpf_map_update_elem(&flow_stats, k, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&flow_stats, k);
        if (!v)
            return;
    }
    if (tx)
        __sync_fetch_and_add(&v->bytes_tx, tx);
    if (rx)
        __sync_fetch_and_add(&v->bytes_rx, rx);
    if (op)
        __sync_fetch_and_add(&v->opened, op);
    if (cl)
        __sync_fetch_and_add(&v->closed, cl);
    v->last_seen_ns = bpf_ktime_get_ns();
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != PROTO_TCP)
        return 0;
    __u64 skp = (__u64)ctx->skaddr;
    int os = ctx->oldstate, ns = ctx->newstate;

    if (os == ST_CLOSE && ns == ST_SYN_SENT) {     /* connect(): process context */
        struct sock_meta m = {};
        m.k.tgid = bpf_get_current_pid_tgid() >> 32;
        m.k.dir = DIR_OUT;
        m.k.family = (__u8)ctx->family;
        m.k.svc_port = ctx->dport;
        if (ctx->family == AF_INET)
            set_v4(m.k.peer, ctx->daddr);
        else
            __builtin_memcpy(m.k.peer, ctx->daddr_v6, 16);
        m.ignored = !include_loopback && is_loopback(m.k.peer);
        bpf_map_update_elem(&sock_meta, &skp, &m, BPF_ANY);
        return 0;
    }

    struct sock_meta *m = bpf_map_lookup_elem(&sock_meta, &skp);
    if (!m)
        return 0;
    if (os == ST_SYN_SENT && ns == ST_ESTABLISHED) {
        m->established = 1;
        if (!m->ignored)
            bump(&m->k, 0, 0, 1, 0);
    } else if (ns == ST_CLOSE) {
        if (m->established && !m->ignored)
            bump(&m->k, 0, 0, 0, 1);
        bpf_map_delete_elem(&sock_meta, &skp);
    }
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)((struct x86_regs *)ctx)->rax;
    if (!sk)
        return 0;
    struct sock_meta m = {};
    if (fill_from_sk(sk, &m.k, DIR_IN) < 0)
        return 0;
    m.k.tgid = bpf_get_current_pid_tgid() >> 32;
    m.established = 1;
    m.ignored = !include_loopback && is_loopback(m.k.peer);
    __u64 skp = (__u64)sk;
    bpf_map_update_elem(&sock_meta, &skp, &m, BPF_ANY);
    if (!m.ignored)
        bump(&m.k, 0, 0, 1, 0);
    return 0;
}

/* account charges bytes to the current tgid. Sockets with no sock_meta
 * (open before the agent started, or accept hook unavailable) are adopted
 * lazily: direction comes from listen_ports, filled by userspace. */
static __always_inline void account(struct sock *sk, __u64 tx, __u64 rx)
{
    __u64 skp = (__u64)sk;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct sock_meta *m = bpf_map_lookup_elem(&sock_meta, &skp);
    if (!m) {
        __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        __u8 dir = bpf_map_lookup_elem(&listen_ports, &lport) ? DIR_IN : DIR_OUT;
        struct sock_meta nm = {};
        if (fill_from_sk(sk, &nm.k, dir) < 0)
            return;
        nm.k.tgid = tgid;
        nm.established = 1;
        nm.ignored = !include_loopback && is_loopback(nm.k.peer);
        bpf_map_update_elem(&sock_meta, &skp, &nm, BPF_NOEXIST);
        m = bpf_map_lookup_elem(&sock_meta, &skp);
        if (!m)
            return;
        if (!m->ignored)
            bump(&m->k, 0, 0, 1, 0);   /* adopted counts as opened */
    }
    if (m->ignored)
        return;
    struct flow_key k = m->k;
    k.tgid = tgid;
    bump(&k, tx, rx, 0, 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 sk = ((struct x86_regs *)ctx)->rdi;
    bpf_map_update_elem(&send_args, &tid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *skp = bpf_map_lookup_elem(&send_args, &tid);
    if (!skp)
        return 0;
    struct sock *sk = (struct sock *)*skp;
    bpf_map_delete_elem(&send_args, &tid);
    int ret = (int)((struct x86_regs *)ctx)->rax;   /* int return: never read as long */
    if (ret > 0)
        account(sk, (__u64)ret, 0);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
    struct x86_regs *r = (struct x86_regs *)ctx;
    int copied = (int)r->rsi;
    if (copied <= 0)
        return 0;
    account((struct sock *)r->rdi, 0, (__u64)copied);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

- [ ] **Step 2: Add `gen.go`**

```go
package netflow

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" -tags linux -type flow_key -type flow_val Netflow netflow.bpf.c -- -I../headers
```

- [ ] **Step 3: Generate and confirm the program compiles**

Run: `make generate`
Expected: success; `internal/ebpf/netflow/netflow_bpfel.go` exists and declares `NetflowFlowKey` with fields `Tgid uint32; Dir uint8; Family uint8; SvcPort uint16; Peer [16]uint8`, and `NetflowObjects` with `HandleSetState`, `KprobeTcpSendmsg`, `KretprobeTcpSendmsg`, `KprobeTcpCleanupRbuf`, `KretprobeInetCskAccept`, `FlowStats`, `ListenPorts`. If a field name differs, use the generated name in Step 5.

- [ ] **Step 4: Write the failing integration test**

```go
// internal/ebpf/netflow/loader_integration_test.go
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
```

Run: `go test -c -tags ebpf_integration -o /tmp/netflow.test ./internal/ebpf/netflow/`
Expected: FAIL to compile — `undefined: NewLoader`.

- [ ] **Step 5: Write the loader**

```go
// internal/ebpf/netflow/loader.go

// Package netflow loads the always-on TCP flow accounting eBPF program and
// implements internal/netflow.Source. Import it as netflowbpf.
package netflow

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	nf "github.com/manhvu1997/linux-obs-agent/internal/netflow"
)

var _ nf.Source = (*Loader)(nil)

// Loader owns the netflow eBPF objects and links.
type Loader struct {
	includeLoopback bool
	objs            NetflowObjects
	links           []link.Link
	inbound         string
}

func NewLoader(includeLoopback bool) *Loader {
	return &Loader{includeLoopback: includeLoopback}
}

// Start loads the program and attaches all hooks. The accept kretprobe is
// optional: without it inbound sockets are adopted on first bytes.
func (l *Loader) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("netflow: removing memlock: %w", err)
	}
	spec, err := LoadNetflow()
	if err != nil {
		return fmt.Errorf("netflow: loading spec: %w", err)
	}
	var lb uint8
	if l.includeLoopback {
		lb = 1
	}
	if err := spec.Variables["include_loopback"].Set(lb); err != nil {
		return fmt.Errorf("netflow: setting include_loopback: %w", err)
	}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return fmt.Errorf("netflow: loading objects: %w", err)
	}

	required := []struct {
		name   string
		attach func() (link.Link, error)
	}{
		{"tracepoint sock/inet_sock_set_state", func() (link.Link, error) {
			return link.Tracepoint("sock", "inet_sock_set_state", l.objs.HandleSetState, nil)
		}},
		{"kprobe tcp_sendmsg", func() (link.Link, error) { return link.Kprobe("tcp_sendmsg", l.objs.KprobeTcpSendmsg, nil) }},
		{"kretprobe tcp_sendmsg", func() (link.Link, error) {
			return link.Kretprobe("tcp_sendmsg", l.objs.KretprobeTcpSendmsg, nil)
		}},
		{"kprobe tcp_cleanup_rbuf", func() (link.Link, error) {
			return link.Kprobe("tcp_cleanup_rbuf", l.objs.KprobeTcpCleanupRbuf, nil)
		}},
	}
	for _, h := range required {
		lnk, err := h.attach()
		if err != nil {
			l.Stop()
			return fmt.Errorf("netflow: attaching %s: %w", h.name, err)
		}
		l.links = append(l.links, lnk)
	}
	if lnk, err := link.Kretprobe("inet_csk_accept", l.objs.KretprobeInetCskAccept, nil); err != nil {
		slog.Warn("netflow: inet_csk_accept unavailable; inbound connections adopted on first bytes", "err", err)
		l.inbound = "lazy"
	} else {
		l.links = append(l.links, lnk)
		l.inbound = "accept"
	}
	slog.Info("netflow: started", "include_loopback", l.includeLoopback, "inbound_accounting", l.inbound)
	return nil
}

func (l *Loader) Stop() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	l.objs.Close()
}

func (l *Loader) InboundAccounting() string { return l.inbound }

// ReadFlows iterates flow_stats. IPv4 and v4-mapped IPv6 sockets of the
// same peer collapse into one key (the family is not part of FlowKey).
func (l *Loader) ReadFlows() (map[nf.FlowKey]nf.FlowValue, error) {
	out := make(map[nf.FlowKey]nf.FlowValue)
	var k NetflowFlowKey
	var v NetflowFlowVal
	it := l.objs.FlowStats.Iterate()
	for it.Next(&k, &v) {
		key := nf.FlowKey{TGID: k.Tgid, Dir: nf.Direction(k.Dir), Peer: nf.PeerFromBytes(k.Peer), ServicePort: k.SvcPort}
		cur := out[key]
		cur.BytesTx += v.BytesTx
		cur.BytesRx += v.BytesRx
		cur.Opened += v.Opened
		cur.Closed += v.Closed
		out[key] = cur
	}
	return out, it.Err()
}

// SetListenPorts makes listen_ports equal to ports.
func (l *Loader) SetListenPorts(ports []uint16) error {
	want := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		want[p] = true
		if err := l.objs.ListenPorts.Put(p, uint8(1)); err != nil {
			return fmt.Errorf("netflow: listen_ports put %d: %w", p, err)
		}
	}
	var (
		k     uint16
		v     uint8
		stale []uint16
	)
	it := l.objs.ListenPorts.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, p := range stale {
		if err := l.objs.ListenPorts.Delete(p); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 6: Build and run the integration tests as root**

Run:
```bash
go vet ./internal/ebpf/netflow/
go test -c -tags ebpf_integration -o /tmp/netflow.test ./internal/ebpf/netflow/
sudo /tmp/netflow.test -test.v -test.run 'TestTransferIsCounted|TestShortLivedConnectionsAreCounted'
```
Expected: both tests PASS. If the verifier rejects a program, the error names the instruction; the usual fix is a missing NULL check after `bpf_map_lookup_elem`.

- [ ] **Step 7: Confirm the hooks and maps exist while a test runs**

Run (second terminal, during Step 6): `sudo bpftool prog list | grep -E 'handle_set_state|tcp_sendmsg|tcp_cleanup_rbuf|inet_csk_accept' && sudo bpftool map show name flow_stats`
Expected: five programs and one `lru_hash` map with `max_entries 16384`.

- [ ] **Step 8: Commit (source only — never the generated files)**

```bash
git add internal/ebpf/netflow/netflow.bpf.c internal/ebpf/netflow/gen.go \
        internal/ebpf/netflow/loader.go internal/ebpf/netflow/loader_integration_test.go
git commit -m "feat(ebpf): always-on per-process TCP flow accounting

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 9: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): eBPF attribution in softirq vs process context, int return handling in kretprobes, sock_meta lifecycle (leaks, double counting), byte-order of ports, verifier safety. Report findings only."`
Fix confirmed findings, re-run Step 6, commit `fix(ebpf/netflow): address review`.

---

### Task 9: Extend the `mysql_query` eBPF module (Linux build host)

**Files:**
- Modify: `internal/ebpf/mysql_query/mysql_query.bpf.c`
- Modify: `internal/ebpf/mysql_query/loader.go`
- Test: `internal/ebpf/mysql_query/loader_integration_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func NewLoader(thresholdNs uint64, mysqldPath string, emitAll bool) *Loader` (**signature change** — the only caller is `internal/mysql/analyzer.go`, updated in Task 10)
  - `Loader.CmdEvents chan CmdEvent` (buffer 8192)
  - `type CmdEvent struct { PID, TID, Command, QueryLen uint32; WallNs, CPUNs, RunqNs, BytesIn, BytesOut uint64; Comm, Query string }`
  - `func (*Loader) Dropped() uint64` — kernel ring-buffer drops + userspace channel drops
  - Existing `SlowEvents`, `TopSlowPIDs` unchanged.

- [ ] **Step 1: Rewrite the eBPF program**

Replace everything in `mysql_query.bpf.c` **after** the `struct x86_regs { … };` definition with the code below (keep the file header comment and `struct x86_regs` as they are, and change the header's "Only intercept COM_QUERY" bullet to "Measure every command; COM_QUERY also feeds the legacy per-PID stats and slow events").

```c
// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN    16
#define QUERY_MAX       512   /* must equal cmdmap.QueryMax in Go            */
#define MAX_ENTRIES     8192  /* in-flight commands ≤ mysqld worker threads   */
#define MAX_PID_ENTRIES 10240
#define COM_QUERY 3

// ─── Value structs ────────────────────────────────────────────────────────────

/* In-flight command state, keyed by TID. 576 bytes: built in pending_scratch
 * because it does not fit the 512-byte BPF stack. */
struct mysql_pending_t {
    __u64 start_ts;
    __u64 cpu_start;   /* task->se.sum_exec_runtime at entry  */
    __u64 rq_start;    /* task->sched_info.run_delay at entry */
    __u64 bytes_in;    /* COM_QUERY length                    */
    __u64 bytes_out;   /* tcp/unix sendmsg bytes during call   */
    __u32 command;
    __u32 query_len;
    __u8  query[QUERY_MAX];
    __u8  comm[TASK_COMM_LEN];
};

struct mysql_pid_stats_t {
    __u64 total_queries;
    __u64 slow_queries;
    __u64 total_latency_ns;
    __u64 max_latency_ns;
    __u64 last_seen_ts;
    __u8  comm[TASK_COMM_LEN];
};
struct mysql_pid_stats_t *__mysql_pid_stats_t_unused __attribute__((unused));

struct mysql_slow_event_t {
    __u32 pid;
    __u32 tid;
    __u64 latency_ns;
    __u64 timestamp_ns;
    __u8  comm[TASK_COMM_LEN];
    __u8  query[QUERY_MAX];
};
struct mysql_slow_event_t *__mysql_slow_event_t_unused __attribute__((unused));

/* One record per dispatch_command call. Layout is decoded by hand in
 * loader.go (decodeCmdEvent) — keep offsets in sync: 584 bytes, no padding. */
struct mysql_cmd_event_t {
    __u32 pid;          /*   0 */
    __u32 tid;          /*   4 */
    __u32 command;      /*   8 */
    __u32 query_len;    /*  12 */
    __u64 wall_ns;      /*  16 */
    __u64 cpu_ns;       /*  24 */
    __u64 runq_ns;      /*  32 */
    __u64 bytes_in;     /*  40 */
    __u64 bytes_out;    /*  48 */
    __u8  comm[TASK_COMM_LEN];  /* 56 */
    __u8  query[QUERY_MAX];     /* 72 */
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct mysql_pending_t);
    __uint(max_entries, MAX_ENTRIES);
} mysql_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct mysql_pending_t);
    __uint(max_entries, 1);
} pending_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct mysql_pid_stats_t);
    __uint(max_entries, MAX_PID_ENTRIES);
} mysql_pid_stats SEC(".maps");

/* Slow-query outliers (unchanged consumer). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KB */
} events SEC(".maps");

/* Every command: < 20k QPS × 584 B ≈ 12 MB/s; 4 MB absorbs ~7k-event bursts. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MB */
} cmd_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} dropped SEC(".maps");

// ─── Config ───────────────────────────────────────────────────────────────────

const volatile __u64 slow_query_threshold_ns = 100000000ULL;
/* 1: emit cmd_events for every command. 0: legacy COM_QUERY-only behaviour. */
const volatile __u8 emit_all_queries = 1;

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u64 task_cpu_ns(struct task_struct *t)
{
    return BPF_CORE_READ(t, se.sum_exec_runtime);
}

/* sched_info exists only with CONFIG_SCHED_INFO; report 0 otherwise and let
 * userspace detect "run_delay_unavailable". */
static __always_inline __u64 task_runq_ns(struct task_struct *t)
{
    if (bpf_core_field_exists(t->sched_info.run_delay))
        return BPF_CORE_READ(t, sched_info.run_delay);
    return 0;
}

// ─── Programs ─────────────────────────────────────────────────────────────────

SEC("uprobe/dispatch_command")
int uprobe_dispatch_command(struct pt_regs *ctx)
{
    struct x86_regs *regs = (struct x86_regs *)ctx;
    __u32 command = (__u32)regs->rdx;
    if (!emit_all_queries && command != COM_QUERY)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct mysql_pending_t *p = bpf_map_lookup_elem(&pending_scratch, &zero);
    if (!p)
        return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    p->start_ts  = bpf_ktime_get_ns();
    p->cpu_start = task_cpu_ns(task);
    p->rq_start  = task_runq_ns(task);
    p->bytes_in  = 0;
    p->bytes_out = 0;
    p->command   = command;
    p->query_len = 0;
    p->query[0]  = 0;
    bpf_get_current_comm(&p->comm, sizeof(p->comm));

    /* COM_DATA for COM_QUERY: offset 0 = const char *query, offset 8 = size_t length. */
    void *com_data = (void *)regs->rsi;
    if (command == COM_QUERY && com_data) {
        const char *query_str = NULL;
        __u64 len = 0;
        if (bpf_probe_read_user(&query_str, sizeof(query_str), com_data) == 0 && query_str)
            bpf_probe_read_user_str(p->query, sizeof(p->query), query_str);
        if (bpf_probe_read_user(&len, sizeof(len), (char *)com_data + 8) == 0) {
            p->bytes_in  = len;
            p->query_len = len > 0xffffffffULL ? 0xffffffff : (__u32)len;
        }
    }
    bpf_map_update_elem(&mysql_pending, &tid, p, BPF_ANY);
    return 0;
}

/* Result bytes: add the int return of the protocol sendmsg while the calling
 * thread is inside dispatch_command. Hooked at tcp/unix level, not
 * sock_sendmsg, because since 6.6 send()/write() reach the protocol through
 * the static, inlinable __sock_sendmsg. */
static __always_inline int add_bytes_out(struct pt_regs *ctx)
{
    int ret = (int)((struct x86_regs *)ctx)->rax;
    if (ret <= 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (p)
        __sync_fetch_and_add(&p->bytes_out, (__u64)ret);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx) { return add_bytes_out(ctx); }

SEC("kretprobe/unix_stream_sendmsg")
int kretprobe_unix_stream_sendmsg(struct pt_regs *ctx) { return add_bytes_out(ctx); }

SEC("uretprobe/dispatch_command")
int uretprobe_dispatch_command(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid  = (__u32)pid_tgid;

    struct mysql_pending_t *p = bpf_map_lookup_elem(&mysql_pending, &tid);
    if (!p)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 now        = bpf_ktime_get_ns();
    __u64 latency_ns = now - p->start_ts;
    __u64 cpu_now = task_cpu_ns(task), rq_now = task_runq_ns(task);
    __u64 cpu_ns  = cpu_now > p->cpu_start ? cpu_now - p->cpu_start : 0;
    __u64 runq_ns = rq_now > p->rq_start ? rq_now - p->rq_start : 0;
    /* sum_exec_runtime is tick-granular: keep cpu, runq <= wall. */
    if (cpu_ns > latency_ns)
        cpu_ns = latency_ns;
    if (runq_ns > latency_ns)
        runq_ns = latency_ns;

    if (p->command == COM_QUERY) {
        struct mysql_pid_stats_t *stats = bpf_map_lookup_elem(&mysql_pid_stats, &tgid);
        if (stats) {
            __sync_fetch_and_add(&stats->total_queries, 1);
            __sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
            if (latency_ns > stats->max_latency_ns)
                stats->max_latency_ns = latency_ns;
            if (latency_ns >= slow_query_threshold_ns)
                __sync_fetch_and_add(&stats->slow_queries, 1);
            stats->last_seen_ts = now;
            bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
        } else {
            struct mysql_pid_stats_t ns;
            __builtin_memset(&ns, 0, sizeof(ns));
            ns.total_queries    = 1;
            ns.total_latency_ns = latency_ns;
            ns.max_latency_ns   = latency_ns;
            ns.slow_queries     = latency_ns >= slow_query_threshold_ns ? 1 : 0;
            ns.last_seen_ts     = now;
            bpf_get_current_comm(&ns.comm, sizeof(ns.comm));
            bpf_map_update_elem(&mysql_pid_stats, &tgid, &ns, BPF_NOEXIST);
        }
        if (latency_ns >= slow_query_threshold_ns) {
            struct mysql_slow_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
            if (ev) {
                ev->pid = tgid;
                ev->tid = tid;
                ev->latency_ns = latency_ns;
                ev->timestamp_ns = now;
                __builtin_memcpy(ev->comm, p->comm, sizeof(ev->comm));
                __builtin_memcpy(ev->query, p->query, sizeof(ev->query));
                bpf_ringbuf_submit(ev, 0);
            }
        }
    }

    if (emit_all_queries) {
        struct mysql_cmd_event_t *ev = bpf_ringbuf_reserve(&cmd_events, sizeof(*ev), 0);
        if (ev) {
            ev->pid       = tgid;
            ev->tid       = tid;
            ev->command   = p->command;
            ev->query_len = p->query_len;
            ev->wall_ns   = latency_ns;
            ev->cpu_ns    = cpu_ns;
            ev->runq_ns   = runq_ns;
            ev->bytes_in  = p->bytes_in;
            ev->bytes_out = p->bytes_out;
            __builtin_memcpy(ev->comm, p->comm, sizeof(ev->comm));
            __builtin_memcpy(ev->query, p->query, sizeof(ev->query));
            bpf_ringbuf_submit(ev, 0);
        } else {
            __u32 zero = 0;
            __u64 *d = bpf_map_lookup_elem(&dropped, &zero);
            if (d)
                *d += 1; /* per-CPU slot: no atomic needed */
        }
    }

    bpf_map_delete_elem(&mysql_pending, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

- [ ] **Step 2: Regenerate**

Run: `make generate`
Expected: success; `MysqlQueryObjects` now has `CmdEvents`, `Dropped`, `PendingScratch`, `KretprobeTcpSendmsg`, `KretprobeUnixStreamSendmsg`. `go build ./internal/ebpf/mysql_query/` fails with `too many arguments` / unknown fields until Step 4.

- [ ] **Step 3: Write the failing integration test**

```go
// internal/ebpf/mysql_query/loader_integration_test.go
//go:build linux && ebpf_integration

package mysql_query

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Needs a running local mysqld and the mysql client.
// MYSQLD_PATH (default /usr/sbin/mysqld), MYSQL_TEST_ARGS e.g. "-uroot -psecret -h127.0.0.1".
func TestCmdEventCarriesCPUAndBytes(t *testing.T) {
	path := os.Getenv("MYSQLD_PATH")
	if path == "" {
		path = "/usr/sbin/mysqld"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no mysqld at %s", path)
	}
	if _, err := exec.LookPath("mysql"); err != nil {
		t.Skip("mysql client not installed")
	}
	l := NewLoader(100_000_000, path, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatalf("start (run as root): %v", err)
	}
	defer l.Stop()

	args := append(strings.Fields(os.Getenv("MYSQL_TEST_ARGS")), "-e", "SELECT REPEAT('a', 100000) AS big")
	if out, err := exec.Command("mysql", args...).CombinedOutput(); err != nil {
		t.Fatalf("mysql: %v: %s", err, out)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-l.CmdEvents:
			if ev.Command != 3 || !strings.Contains(ev.Query, "REPEAT('a', 100000)") {
				continue
			}
			if ev.BytesOut < 100000 {
				t.Fatalf("bytes_out = %d, want >= 100000", ev.BytesOut)
			}
			if ev.CPUNs > ev.WallNs || ev.RunqNs > ev.WallNs || ev.WallNs == 0 {
				t.Fatalf("timing invariant broken: %+v", ev)
			}
			if ev.BytesIn != uint64(len("SELECT REPEAT('a', 100000) AS big")) {
				t.Fatalf("bytes_in = %d", ev.BytesIn)
			}
			return
		case <-deadline:
			t.Fatal("no cmd event for the test query within 5s")
		}
	}
}
```

- [ ] **Step 4: Update the loader**

4a. Add imports `"sync/atomic"`. Add to `Loader`:

```go
	emitAll     bool
	cmdRd       *ringbuf.Reader
	userDropped atomic.Uint64

	// CmdEvents receives one record per dispatch_command call when emitAll
	// is set. Buffered; when full, events are dropped and counted.
	CmdEvents chan CmdEvent
```

4b. Add the type and decoder:

```go
// CmdEvent is one MySQL command measured in the kernel.
type CmdEvent struct {
	PID, TID, Command, QueryLen     uint32
	WallNs, CPUNs, RunqNs           uint64
	BytesIn, BytesOut               uint64
	Comm, Query                     string
}

const cmdEventSize = 584 // sizeof(struct mysql_cmd_event_t)

// decodeCmdEvent reads struct mysql_cmd_event_t by fixed offsets. At up to
// 20k events/s, reflection-based binary.Read would cost several percent of
// a core; this costs a few hundred nanoseconds.
func decodeCmdEvent(b []byte) (CmdEvent, bool) {
	if len(b) < cmdEventSize {
		return CmdEvent{}, false
	}
	le := binary.LittleEndian
	return CmdEvent{
		PID: le.Uint32(b[0:]), TID: le.Uint32(b[4:]), Command: le.Uint32(b[8:]), QueryLen: le.Uint32(b[12:]),
		WallNs: le.Uint64(b[16:]), CPUNs: le.Uint64(b[24:]), RunqNs: le.Uint64(b[32:]),
		BytesIn: le.Uint64(b[40:]), BytesOut: le.Uint64(b[48:]),
		Comm:  nullTermU8(b[56:72]),
		Query: nullTermU8(b[72:cmdEventSize]),
	}, true
}

// Dropped returns command events lost in the kernel (ring buffer full) plus
// events dropped because CmdEvents was full.
func (l *Loader) Dropped() uint64 {
	total := l.userDropped.Load()
	var perCPU []uint64
	if l.objs.Dropped != nil {
		if err := l.objs.Dropped.Lookup(uint32(0), &perCPU); err == nil {
			for _, v := range perCPU {
				total += v
			}
		}
	}
	return total
}
```

4c. Change `NewLoader`:

```go
func NewLoader(thresholdNs uint64, mysqldPath string, emitAll bool) *Loader {
	if thresholdNs == 0 {
		thresholdNs = 100_000_000 // 100 ms
	}
	if mysqldPath == "" {
		mysqldPath = "/usr/sbin/mysqld"
	}
	return &Loader{
		thresholdNs: thresholdNs,
		mysqldPath:  mysqldPath,
		emitAll:     emitAll,
		SlowEvents:  make(chan model.EBPFEvent, 256),
		CmdEvents:   make(chan CmdEvent, 8192),
	}
}
```

4d. In `Start`, after the `slow_query_threshold_ns` `Set`:

```go
	var emit uint8
	if l.emitAll {
		emit = 1
	}
	if err := spec.Variables["emit_all_queries"].Set(emit); err != nil {
		slog.Warn("mysql_query: could not set emit_all_queries", "err", err)
	}
```

After `l.rd = rd`:

```go
	cmdRd, err := ringbuf.NewReader(l.objs.CmdEvents)
	if err != nil {
		l.cleanup()
		return fmt.Errorf("mysql_query: opening cmd ringbuf: %w", err)
	}
	l.cmdRd = cmdRd
```

After the uretprobe is attached:

```go
	// Result bytes per command. Optional: without them bytes_out stays 0.
	for _, fn := range []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"tcp_sendmsg", l.objs.KretprobeTcpSendmsg},
		{"unix_stream_sendmsg", l.objs.KretprobeUnixStreamSendmsg},
	} {
		krp, err := link.Kretprobe(fn.sym, fn.prog, nil)
		if err != nil {
			slog.Warn("mysql_query: bytes_out hook unavailable", "symbol", fn.sym, "err", err)
			continue
		}
		l.links = append(l.links, krp)
	}
```

and replace `go l.consume(ctx)` with:

```go
	go l.consume(ctx)
	go l.consumeCmd(ctx)
```

Add `"github.com/cilium/ebpf"` to the imports.

4e. In `cleanup()` close the new reader:

```go
	if l.cmdRd != nil {
		l.cmdRd.Close()
		l.cmdRd = nil
	}
```

4f. Add the consumer:

```go
// consumeCmd forwards per-command events. Never blocks the reader: a full
// channel drops the event and counts it in Dropped().
func (l *Loader) consumeCmd(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rec, err := l.cmdRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn("mysql_query: cmd ringbuf read error", "err", err)
			continue
		}
		ev, ok := decodeCmdEvent(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case l.CmdEvents <- ev:
		default:
			l.userDropped.Add(1)
		}
	}
}
```

4g. Update the package doc comment: replace "Only COM_QUERY commands (command type == 3) are traced" with "Every command is measured (wall, on-CPU, run-queue wait, bytes) and emitted on cmd_events; COM_QUERY additionally feeds the per-PID stats map and slow-query events."

- [ ] **Step 5: Build, vet and run the integration test**

The analyzer still calls the old `NewLoader` signature until Task 10, so build only this package now:

```bash
go vet ./internal/ebpf/mysql_query/
go test -c -tags ebpf_integration -o /tmp/mysqlq.test ./internal/ebpf/mysql_query/
sudo MYSQL_TEST_ARGS="-uroot -p<password> -h127.0.0.1" /tmp/mysqlq.test -test.v -test.run TestCmdEventCarriesCPUAndBytes
```
Expected: PASS (or SKIP on a host without MySQL — then run it on the MySQL test VM before merging). Also run once with the client over the unix socket (`MYSQL_TEST_ARGS="-uroot -p<password>"`, no `-h`) — must still PASS, which proves the `unix_stream_sendmsg` hook.

- [ ] **Step 6: Commit**

```bash
git add internal/ebpf/mysql_query/mysql_query.bpf.c internal/ebpf/mysql_query/loader.go \
        internal/ebpf/mysql_query/loader_integration_test.go
git commit -m "feat(ebpf/mysql): per-command CPU, run-queue wait and result bytes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 7: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): BPF stack usage, per-CPU scratch reuse, CO-RE field_exists usage, int return of sendmsg, event layout vs decodeCmdEvent offsets, behaviour with emit_all_queries=0. Report findings only."`
Fix confirmed findings, re-run Step 5, commit `fix(ebpf/mysql): address review`.

---

### Task 10: MySQL analyzer publishes query digests

**Files:**
- Create: `internal/mysql/cmdmap/cmdmap.go`, `internal/mysql/cmdmap/cmdmap_test.go`
- Modify: `internal/mysql/analyzer.go`
- Modify: `internal/model/types.go` (`MySQLAnalysis` fields)
- Modify: `internal/config/config.go` (`MySQLConfig` keys), `internal/config/config_test.go`

**Interfaces:**
- Consumes: `sqldigest.Normalize`, `sqldigest.HashID` (Task 1); `querystats` (Task 2); `mysql_query.NewLoader(threshold, path, emitAll)`, `Loader.CmdEvents`, `Loader.Dropped()` (Task 9).
- Produces:
  - `cmdmap.Classify(command uint32, query string, queryLen uint32) (class string, d sqldigest.Digest, sample string, truncated bool)`; constants `cmdmap.ComQuery = 3`, `cmdmap.ComStmtExecute = 23`, `cmdmap.QueryMax = 512`
  - `(*mysql.Analyzer).DigestSnapshot() *querystats.Snapshot`, `(*mysql.Analyzer).Dropped() uint64`
  - `model.MySQLAnalysis` new fields: `WindowSeconds int`, `CPUAccounting string`, `DroppedEvents uint64`, `Thresholds *QueryRoleThresholds`, `TopDigests`, `TopDigestsByBytesOut []QueryDigestStats`
  - `config.MySQLConfig` new fields: `EmitAllQueries bool`, `DigestWindow time.Duration`, `TopDigests int`, `StickyDigestsMax int`, `StickyDigestTTL time.Duration`, `CulpritCPUSharePercent float64`, `VictimRunqRatio float64`

- [ ] **Step 1: Write the failing tests**

```go
// internal/mysql/cmdmap/cmdmap_test.go
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
```

Append to `internal/config/config_test.go`:

```go
func TestMySQLDigestDefaults(t *testing.T) {
	m := Defaults().MySQL
	if m.Enabled || !m.EmitAllQueries || m.DigestWindow != 60*time.Second || m.TopDigests != 20 ||
		m.StickyDigestsMax != 50 || m.StickyDigestTTL != time.Hour ||
		m.CulpritCPUSharePercent != 20 || m.VictimRunqRatio != 5 {
		t.Fatalf("mysql defaults = %+v", m)
	}
	c := Defaults()
	c.MySQL.Enabled = true
	c.MySQL.DigestWindow = time.Second
	if err := c.validate(); err == nil {
		t.Fatal("digest_window < poll_interval must be rejected when mysql is enabled")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/mysql/cmdmap/ ./internal/config/`
Expected: FAIL — `undefined: Classify`, `m.EmitAllQueries undefined`.

- [ ] **Step 3: Implement `cmdmap`**

```go
// internal/mysql/cmdmap/cmdmap.go

// Package cmdmap maps a MySQL enum_server_command plus captured text to a
// command class and digest. Pure, so it is testable without eBPF.
package cmdmap

import (
	"fmt"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/sqldigest"
)

const (
	ComQuery       = 3
	ComStmtExecute = 23
	QueryMax       = 512 // must equal QUERY_MAX in mysql_query.bpf.c
)

// Classify returns the command class ("query" | "stmt_execute" | "other"),
// its digest, a UTF-8-safe sample of the raw text, and whether the captured
// text was cut at the kernel buffer (QueryMax-1 bytes + NUL).
func Classify(command uint32, query string, queryLen uint32) (class string, d sqldigest.Digest, sample string, truncated bool) {
	switch command {
	case ComQuery:
		truncated = queryLen >= QueryMax
		if strings.TrimSpace(query) == "" {
			return "query", placeholder("<empty query>"), "", truncated
		}
		return "query", sqldigest.Normalize(query), strings.ToValidUTF8(query, "?"), truncated
	case ComStmtExecute:
		return "stmt_execute", placeholder("<COM_STMT_EXECUTE: prepared, text unavailable>"), "", false
	default:
		return "other", placeholder(fmt.Sprintf("<COM command %d>", command)), "", false
	}
}

func placeholder(text string) sqldigest.Digest {
	return sqldigest.Digest{ID: sqldigest.HashID(text), Text: text, Normalized: true}
}
```

- [ ] **Step 4: Add the config keys**

In `MySQLConfig` add:

```go
	// EmitAllQueries emits one kernel event per command (needed for digests).
	// Default true. Env MYSQL_EMIT_ALL_QUERIES. false = legacy slow-only mode.
	EmitAllQueries bool `yaml:"emit_all_queries"`
	// DigestWindow: rolling window for top_digests. Env MYSQL_DIGEST_WINDOW.
	DigestWindow time.Duration `yaml:"digest_window"`
	// TopDigests: digests in mysql_report.top_digests (ranked by total CPU).
	TopDigests int `yaml:"top_digests"`
	// StickyDigestsMax / StickyDigestTTL bound the digests exported to Prometheus.
	StickyDigestsMax int           `yaml:"sticky_digests_max"`
	StickyDigestTTL  time.Duration `yaml:"sticky_digest_ttl"`
	// CulpritCPUSharePercent: digest share of mysqld query CPU that marks it "culprit".
	CulpritCPUSharePercent float64 `yaml:"culprit_cpu_share_percent"`
	// VictimRunqRatio: run-queue wait > cpu × ratio (and wall ≥ slow threshold) marks "victim".
	VictimRunqRatio float64 `yaml:"victim_runq_ratio"`
```

In `Defaults()` `MySQL:` block add:

```go
			EmitAllQueries:         true,
			DigestWindow:           60 * time.Second,
			TopDigests:             20,
			StickyDigestsMax:       50,
			StickyDigestTTL:        time.Hour,
			CulpritCPUSharePercent: 20,
			VictimRunqRatio:        5,
```

In `applyMySQLEnvOverrides` add:

```go
	if v := os.Getenv("MYSQL_EMIT_ALL_QUERIES"); v != "" {
		cfg.MySQL.EmitAllQueries = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("MYSQL_DIGEST_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.MySQL.DigestWindow = d
		}
	}
```

In `validate()` add:

```go
	if c.MySQL.Enabled {
		if c.MySQL.DigestWindow < c.MySQL.PollInterval {
			return fmt.Errorf("mysql.digest_window must be >= mysql.poll_interval")
		}
		if c.MySQL.TopDigests <= 0 || c.MySQL.StickyDigestsMax <= 0 || c.MySQL.StickyDigestTTL <= 0 {
			return fmt.Errorf("mysql.top_digests, sticky_digests_max and sticky_digest_ttl must be > 0")
		}
		if c.MySQL.CulpritCPUSharePercent <= 0 || c.MySQL.VictimRunqRatio <= 0 {
			return fmt.Errorf("mysql.culprit_cpu_share_percent and victim_runq_ratio must be > 0")
		}
	}
```

- [ ] **Step 5: Run the pure tests**

Run: `gofmt -w internal/ && go test ./internal/mysql/cmdmap/ ./internal/config/`
Expected: `ok` for both.

- [ ] **Step 6: Extend `model.MySQLAnalysis`**

Add after `TopProcesses`:

```go
	// Query digests (present when mysql.emit_all_queries is on).
	WindowSeconds        int                  `json:"window_seconds,omitempty"`
	CPUAccounting        string               `json:"cpu_accounting,omitempty"` // "ok" | "run_delay_unavailable"
	DroppedEvents        uint64               `json:"dropped_events"`
	Thresholds           *QueryRoleThresholds `json:"thresholds,omitempty"`
	TopDigests           []QueryDigestStats   `json:"top_digests,omitempty"`            // by total CPU
	TopDigestsByBytesOut []QueryDigestStats   `json:"top_digests_by_bytes_out,omitempty"`
```

- [ ] **Step 7: Update the analyzer**

7a. Imports: add `"github.com/manhvu1997/linux-obs-agent/internal/mysql/cmdmap"` and `"github.com/manhvu1997/linux-obs-agent/internal/querystats"`.

7b. `Analyzer` fields — add:

```go
	agg     *querystats.Aggregator
	digests atomic.Pointer[querystats.Snapshot]
	started atomic.Bool
```

7c. Replace `NewAnalyzer`:

```go
func NewAnalyzer(cfg *config.MySQLConfig, coll *collector.Collector) *Analyzer {
	thresholdNs := cfg.SlowQueryThresholdMs * uint64(time.Millisecond)
	return &Analyzer{
		cfg:    cfg,
		coll:   coll,
		loader: mysqlq.NewLoader(thresholdNs, cfg.MysqldPath, cfg.EmitAllQueries),
		agg: querystats.New(querystats.Config{
			Window:                 cfg.DigestWindow,
			TopN:                   cfg.TopDigests,
			TopNBytes:              10,
			CulpritCPUSharePercent: cfg.CulpritCPUSharePercent,
			VictimRunqRatio:        cfg.VictimRunqRatio,
			SlowWallNs:             thresholdNs,
			StickyMax:              cfg.StickyDigestsMax,
			StickyTTL:              cfg.StickyDigestTTL,
		}),
	}
}
```

7d. In `Start`, after `defer a.loader.Stop()`:

```go
	a.started.Store(true)
	defer a.started.Store(false)
```

and after `go a.drainSlowEvents(ctx)` add `go a.drainCmdEvents(ctx)`.

7e. Add:

```go
// DigestSnapshot returns the latest digest snapshot (nil before the first
// poll). Used by the Prometheus collector.
func (a *Analyzer) DigestSnapshot() *querystats.Snapshot { return a.digests.Load() }

// Dropped returns lost per-command events; 0 when the tracer is not running.
func (a *Analyzer) Dropped() uint64 {
	if !a.started.Load() {
		return 0
	}
	return a.loader.Dropped()
}

// drainCmdEvents feeds every measured command into the digest aggregator.
func (a *Analyzer) drainCmdEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.loader.CmdEvents:
			if !ok {
				return
			}
			class, d, sample, trunc := cmdmap.Classify(ev.Command, ev.Query, ev.QueryLen)
			a.agg.Add(querystats.Event{
				PID: ev.PID, Command: class, Digest: d, SampleQuery: sample, Truncated: trunc,
				WallNs: ev.WallNs, CPUNs: ev.CPUNs, RunqNs: ev.RunqNs,
				BytesIn: ev.BytesIn, BytesOut: ev.BytesOut, At: time.Now(),
			})
		}
	}
}
```

7f. In `poll()`, replace the start (`staleNs := …` through `if len(raw) == 0 { return }`) with:

```go
	snap := a.agg.Snapshot(time.Now())
	a.digests.Store(&snap)

	staleNs := uint64(a.cfg.StaleSeconds) * uint64(time.Second)
	raw := a.loader.TopSlowPIDs(a.cfg.TopN, staleNs)
	if len(raw) == 0 && len(snap.TopByCPU) == 0 {
		return
	}
```

and add to the `&model.MySQLAnalysis{…}` literal:

```go
		WindowSeconds:        snap.WindowSeconds,
		CPUAccounting:        snap.CPUAccounting,
		DroppedEvents:        a.loader.Dropped(),
		Thresholds:           &snap.Thresholds,
		TopDigests:           snap.TopByCPU,
		TopDigestsByBytesOut: snap.TopByBytesOut,
```

Change the `slog.Debug("mysql: analysis updated", …)` call to also log `"digests", len(snap.TopByCPU)`.

- [ ] **Step 8: Build on the Linux host**

Run: `make generate && go build ./... && go vet ./internal/mysql/... && go test ./internal/...`
Expected: build succeeds (the old `NewLoader` call site is gone); all unit tests `ok` (eBPF integration tests are excluded without the tag).

- [ ] **Step 9: Commit**

```bash
git add internal/mysql/cmdmap/ internal/mysql/analyzer.go internal/model/types.go \
        internal/config/config.go internal/config/config_test.go
git commit -m "feat(mysql): rank query digests by CPU and label culprits vs victims

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 10: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): analyzer goroutine lifecycle, behaviour when mysql is disabled, nil snapshot handling, config validation. Report findings only."`
Fix confirmed findings, re-run Step 8, commit `fix(mysql): address review`.

---

### Task 11: Wire everything into the agent

**Files:**
- Modify: `internal/exporter/prometheus.go`
- Modify: `cmd/agent/main.go`

**Interfaces:**
- Consumes: `process.Inspector` accessors (Task 3), `netinv.New` (Task 4), `netflow.NewAccumulator/NewAnalyzer/Counters` (Task 5), `procreport.Build` (Task 6), `promcollect` (Task 7), `netflowbpf.NewLoader` (Task 8), `mysql.Analyzer.DigestSnapshot/Dropped` (Task 10).
- Produces:
  - `(*PrometheusExporter).RegisterProcessReportSources(cfg *config.ProcessConfig, acc *netflow.Accumulator, networkSource, inboundAccounting string, inv *netinv.Inventory)`
  - `(*PrometheusExporter).RegisterCollectors(cs ...prometheus.Collector)`
  - `/api/diagnose` gains `process_report`; `/metrics` gains `obs_agent_family_*` and `obs_agent_mysql_*`.

- [ ] **Step 1: Exporter — fields and registration**

Add imports `"github.com/manhvu1997/linux-obs-agent/internal/netflow"`, `".../internal/netinv"`, `".../internal/procreport"`.

Add to `PrometheusExporter`:

```go
	// process_report sources – set via RegisterProcessReportSources.
	procCfg     *config.ProcessConfig
	netAcc      *netflow.Accumulator
	netSource   string
	inboundAcct string
	inv         *netinv.Inventory
```

Add methods after `RegisterMySQLAnalyzer`:

```go
// RegisterProcessReportSources wires process_report. acc is nil when
// netflow is disabled or failed to load; networkSource says why.
func (p *PrometheusExporter) RegisterProcessReportSources(
	cfg *config.ProcessConfig,
	acc *netflow.Accumulator,
	networkSource, inboundAccounting string,
	inv *netinv.Inventory,
) {
	p.procCfg = cfg
	p.netAcc = acc
	p.netSource = networkSource
	p.inboundAcct = inboundAccounting
	p.inv = inv
}

// RegisterCollectors registers extra Prometheus collectors on the default
// registry (served by /metrics).
func (p *PrometheusExporter) RegisterCollectors(cs ...prometheus.Collector) {
	for _, c := range cs {
		prometheus.MustRegister(c)
	}
}
```

- [ ] **Step 2: Exporter — build `process_report`**

In `handleDiagnose`, directly after the `report.TopProcesses = p.insp.TopCPU()` block, add:

```go
	// Process report: top processes and families by CPU/memory with their
	// network activity (eBPF netflow) and live connections (/proc inventory).
	if p.insp != nil && p.procCfg != nil {
		in := procreport.Inputs{
			TopCPU:            p.insp.ReportTopCPU(),
			TopMem:            p.insp.ReportTopMem(),
			FamiliesCPU:       p.insp.TopFamiliesCPU(),
			FamiliesMem:       p.insp.TopFamiliesMem(),
			NetworkSource:     p.netSource,
			InboundAccounting: p.inboundAcct,
			MaxConnections:    p.procCfg.MaxConnectionsPerProcess,
		}
		// Assign interfaces only from non-nil pointers: a typed nil stored in
		// an interface is != nil and would be called.
		if p.inv != nil {
			in.Inventory = p.inv
		}
		if p.netAcc != nil {
			in.Net = p.netAcc
			in.WindowSeconds = p.netAcc.WindowSeconds()
		}
		report.ProcessReport = procreport.Build(in, time.Now())
	}
```

- [ ] **Step 3: `main.go` — netflow and collectors**

Add imports:

```go
	netflowbpf "github.com/manhvu1997/linux-obs-agent/internal/ebpf/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/netflow"
	"github.com/manhvu1997/linux-obs-agent/internal/netinv"
	"github.com/manhvu1997/linux-obs-agent/internal/promcollect"
```

Add `"netflow_enabled", cfg.Netflow.Enabled,` to the startup `slog.Info`.

After the `go insp.Run(ctx)` line, add:

```go
	// ── Network flow accounting (always-on, eBPF netflow) ──────────────────
	// Counts TCP bytes/connections per (process, direction, peer, service
	// port) in-kernel; feeds process_report.network and obs_agent_family_net_*.
	inv := netinv.New("/proc")
	var netAcc *netflow.Accumulator
	netSource, inboundAcct := "disabled", ""
	switch {
	case !cfg.Netflow.Enabled:
	case !cfg.EBPF.Enabled:
		netSource = "disabled: ebpf.enabled=false"
	default:
		ld := netflowbpf.NewLoader(cfg.Netflow.IncludeLoopback)
		if err := ld.Start(); err != nil {
			netSource = "unavailable: " + err.Error()
			slog.Warn("netflow: eBPF unavailable; process_report.network omitted", "err", err)
			break
		}
		defer ld.Stop()
		netAcc = netflow.NewAccumulator(netflow.Config{
			Window:             cfg.Netflow.Window,
			MaxFamilies:        cfg.Netflow.MaxFamilies,
			MaxOutboundPeers:   cfg.Netflow.MaxOutboundPeers,
			MaxPeersPerProcess: cfg.Process.MaxPeersPerProcess,
		})
		go netflow.NewAnalyzer(ld, inv, insp, netAcc, cfg.Netflow.PollInterval, cfg.Netflow.ListenRefreshInterval).Run(ctx)
		netSource, inboundAcct = "ebpf", ld.InboundAccounting()
	}
```

Inside the existing `if promExp != nil {` wiring block, after `promExp.RegisterMySQLAnalyzer(mysqlAnalyzer)`, add:

```go
		promExp.RegisterProcessReportSources(&cfg.Process, netAcc, netSource, inboundAcct, inv)
		netCounters := func() (netflow.Counters, bool) {
			if netAcc == nil {
				return netflow.Counters{}, false
			}
			return netAcc.Counters(), true
		}
		promExp.RegisterCollectors(promcollect.NewFamilyCollector(insp.AllFamilies, netCounters, cfg.Netflow.MaxFamilies))
		if cfg.MySQL.Enabled {
			promExp.RegisterCollectors(promcollect.NewMySQLCollector(mysqlAnalyzer.DigestSnapshot, mysqlAnalyzer.Dropped))
		}
```

- [ ] **Step 4: Build and smoke-test on the Linux host**

Run:
```bash
make generate && make build && go vet ./... && go test ./internal/...
sudo ./build/obs-agent -config deploy/config.yaml.example -loglevel debug &
sleep 25
curl -s localhost:9200/api/diagnose | jq '.process_report | {network_source, inbound_accounting, top_cpu: [.top_cpu[] | {pid, comm, family, listening_ports, n_conns: (.connections|length), network}][0:3]}'
curl -s localhost:9200/api/diagnose | jq '.process_report.top_families_cpu[0:3] | map({family, process_count, cpu_percent, root_pid})'
curl -s localhost:9200/metrics | grep -E '^obs_agent_family_(cpu_percent|net_bytes_total)' | head
sudo kill %1
```
Expected: `network_source` is `"ebpf"`, `inbound_accounting` is `"accept"`; `top_cpu` entries have `family` set (e.g. `ssh.service`, `session-N.scope`) and a `network` object; families show `process_count`; `/metrics` contains `obs_agent_family_cpu_percent{family="…"}` and `obs_agent_family_net_bytes_total{…}` lines.

Negative check:
```bash
sudo NETFLOW_ENABLED=false ./build/obs-agent -config deploy/config.yaml.example &
sleep 25
curl -s localhost:9200/api/diagnose | jq '.process_report | {network_source, has_net: (.top_cpu[0] | has("network"))}'
sudo kill %1
```
Expected: `{"network_source":"disabled","has_net":false}`, and the agent does not crash.

- [ ] **Step 5: Commit**

```bash
git add internal/exporter/prometheus.go cmd/agent/main.go
git commit -m "feat(agent): expose process_report and family/MySQL digest metrics

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 6: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): typed-nil interfaces, startup failure paths, defer ordering for eBPF teardown, duplicate Prometheus registration. Report findings only."`
Fix confirmed findings, re-run Step 4, commit `fix(agent): address review`.

---

### Task 12: Alert rules, config example and documentation

**Files:**
- Create: `deploy/prometheus/obs-agent-alerts.yaml`, `deploy/prometheus/obs-agent-alerts_test.yaml`
- Modify: `deploy/config.yaml.example`, `AGENTS.md`, `CLAUDE.md`

**Interfaces:**
- Consumes: metric names from Task 7; config keys from Tasks 3, 5, 10.
- Produces: shippable alert rules and documentation.

- [ ] **Step 1: Write the promtool rule test first**

```yaml
# deploy/prometheus/obs-agent-alerts_test.yaml
rule_files:
  - obs-agent-alerts.yaml

evaluation_interval: 1m

tests:
  - interval: 1m
    input_series:
      # digest aaa burns 0.8 cores, bbb 0.1 cores, total query CPU 0.9 cores
      - series: 'obs_agent_mysql_digest_cpu_seconds_total{instance="db1:9200",digest_id="aaa"}'
        values: '0+48x20'
      - series: 'obs_agent_mysql_digest_cpu_seconds_total{instance="db1:9200",digest_id="bbb"}'
        values: '0+6x20'
      - series: 'obs_agent_mysql_query_cpu_seconds_total{instance="db1:9200",command="query"}'
        values: '0+54x20'
      - series: 'obs_agent_cpu_usage_percent{instance="db1:9200"}'
        values: '95x20'
      # queries spend 40% of their wall time waiting for a CPU
      - series: 'obs_agent_mysql_query_runq_wait_seconds_total{instance="db1:9200",command="query"}'
        values: '0+20x20'
      - series: 'obs_agent_mysql_query_wall_seconds_total{instance="db1:9200",command="query"}'
        values: '0+50x20'
    alert_rule_test:
      - eval_time: 15m
        alertname: MySQLQueryDigestCPUHog
        exp_alerts:
          - exp_labels: { severity: warning, instance: "db1:9200", digest_id: "aaa" }
            exp_annotations:
              summary: "MySQL digest aaa dominates query CPU on db1:9200"
              description: "One query pattern uses more than 30% of mysqld query CPU while the node is above 85% CPU. Look it up in mysql_report.top_digests or obs_agent_mysql_digest_info."
              diagnose: "http://db1:9200/api/diagnose"
      - eval_time: 15m
        alertname: MySQLQueriesStarvedForCPU
        exp_alerts:
          - exp_labels: { severity: warning, instance: "db1:9200" }
            exp_annotations:
              summary: "MySQL queries on db1:9200 spend more than 30% of their time waiting for a CPU"
              description: "Slow queries here are cascade victims of CPU saturation. Fix the culprit digest (role=culprit in mysql_report.top_digests) instead of tuning the slow queries."
              diagnose: "http://db1:9200/api/diagnose"

  - interval: 1m
    input_series:
      - series: 'obs_agent_family_cpu_percent{instance="web1:9200",family="php-fpm.service"}'
        values: '95x20'
      - series: 'obs_agent_family_cpu_percent{instance="web1:9200",family="cron.service"}'
        values: '5x20'
    alert_rule_test:
      - eval_time: 15m
        alertname: ProcessFamilyCPUHigh
        exp_alerts:
          - exp_labels: { severity: warning, instance: "web1:9200", family: "php-fpm.service" }
            exp_annotations:
              summary: "php-fpm.service uses 95% CPU on web1:9200"
              description: "Process family CPU above 80% for 10 minutes. process_report.top_families_cpu lists its top members; open profile_url on a member for its stacks."
              diagnose: "http://web1:9200/api/diagnose"
```

- [ ] **Step 2: Run it to verify it fails**

Run (Linux host):
```bash
curl -sL https://github.com/prometheus/prometheus/releases/download/v2.53.2/prometheus-2.53.2.linux-amd64.tar.gz | tar xz -C /tmp
/tmp/prometheus-2.53.2.linux-amd64/promtool test rules deploy/prometheus/obs-agent-alerts_test.yaml
```
Expected: FAIL — `obs-agent-alerts.yaml: no such file or directory`.

- [ ] **Step 3: Write the alert rules**

```yaml
# deploy/prometheus/obs-agent-alerts.yaml
# Alert rules for obs-agent process-family, network-flow and MySQL digest
# metrics. Thresholds are starting points: tune them against each fleet's
# baseline. Every alert links to /api/diagnose for the full evidence.
groups:
  - name: obs-agent-mysql
    rules:
      - alert: MySQLQueryDigestCPUHog
        expr: |
          (
            sum by (instance, digest_id) (rate(obs_agent_mysql_digest_cpu_seconds_total[5m]))
              / on (instance) group_left
            sum by (instance) (rate(obs_agent_mysql_query_cpu_seconds_total[5m]))
          ) > 0.30
          and on (instance) obs_agent_cpu_usage_percent > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "MySQL digest {{ $labels.digest_id }} dominates query CPU on {{ $labels.instance }}"
          description: "One query pattern uses more than 30% of mysqld query CPU while the node is above 85% CPU. Look it up in mysql_report.top_digests or obs_agent_mysql_digest_info."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

      - alert: MySQLQueriesStarvedForCPU
        expr: |
          sum by (instance) (rate(obs_agent_mysql_query_runq_wait_seconds_total[5m]))
            / sum by (instance) (rate(obs_agent_mysql_query_wall_seconds_total[5m])) > 0.30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "MySQL queries on {{ $labels.instance }} spend more than 30% of their time waiting for a CPU"
          description: "Slow queries here are cascade victims of CPU saturation. Fix the culprit digest (role=culprit in mysql_report.top_digests) instead of tuning the slow queries."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

      - alert: MySQLDigestResultSizeSpike
        expr: |
          (
            rate(obs_agent_mysql_digest_bytes_out_total[10m]) / rate(obs_agent_mysql_digest_calls_total[10m])
          ) > 5 * (
            rate(obs_agent_mysql_digest_bytes_out_total[10m] offset 1d)
              / rate(obs_agent_mysql_digest_calls_total[10m] offset 1d)
          )
          and rate(obs_agent_mysql_digest_bytes_out_total[10m]) > 5e6
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "MySQL digest {{ $labels.digest_id }} returns 5x more data per call than yesterday on {{ $labels.instance }}"
          description: "Result size per execution jumped (missing LIMIT, data growth, or a changed query). See mysql_report.top_digests_by_bytes_out."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

      - alert: ObsAgentMySQLEventsDropped
        expr: rate(obs_agent_mysql_events_dropped_total[5m]) > 0
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "obs-agent is dropping MySQL command events on {{ $labels.instance }}"
          description: "Digest totals undercount. Per-PID kernel totals remain exact. Consider a larger ring buffer or check agent CPU throttling."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

  - name: obs-agent-process
    rules:
      - alert: ProcessFamilyCPUHigh
        expr: obs_agent_family_cpu_percent > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.family }} uses {{ $value | printf \"%.0f\" }}% CPU on {{ $labels.instance }}"
          description: "Process family CPU above 80% for 10 minutes. process_report.top_families_cpu lists its top members; open profile_url on a member for its stacks."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

      - alert: ProcessFamilyMemoryExhaustion
        expr: |
          predict_linear(obs_agent_family_mem_rss_bytes[1h], 4 * 3600)
            > on (instance) group_left obs_agent_mem_total_bytes * 0.9
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.family }} on {{ $labels.instance }} is on track to use 90% of RAM within 4h"
          description: "Linear projection of the family's RSS over the last hour. Check process_report.top_families_mem."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

  - name: obs-agent-network
    rules:
      - alert: OutboundTrafficAnomaly
        expr: |
          sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total[10m]))
            > 3 * sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total[10m] offset 1w))
          and sum by (instance, family, peer_ip, service_port) (rate(obs_agent_family_outbound_peer_bytes_total[10m])) > 10e6
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.family }} on {{ $labels.instance }} sends/receives 3x more to {{ $labels.peer_ip }}:{{ $labels.service_port }} than last week"
          description: "Outbound traffic to this dependency is above 10 MB/s and 3x the same window one week ago."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"

      - alert: ConnectionChurnHigh
        expr: sum by (instance, family, direction) (rate(obs_agent_family_net_connections_opened_total[5m])) > 500
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.family }} on {{ $labels.instance }} opens more than 500 {{ $labels.direction }} connections/s"
          description: "Sustained connection churn usually means a missing or broken connection pool."
          diagnose: "http://{{ $labels.instance }}/api/diagnose"
```

- [ ] **Step 4: Run promtool to verify it passes**

Run:
```bash
/tmp/prometheus-2.53.2.linux-amd64/promtool check rules deploy/prometheus/obs-agent-alerts.yaml
/tmp/prometheus-2.53.2.linux-amd64/promtool test rules deploy/prometheus/obs-agent-alerts_test.yaml
```
Expected: `SUCCESS: 8 rules found` and `SUCCESS` for the tests. If an annotation mismatch is reported, promtool prints the expected and actual strings — make the rule text and the test text identical.

- [ ] **Step 5: Update `deploy/config.yaml.example`**

Under the existing `process:` section add:

```yaml
  # process_report (GET /api/diagnose)
  report_top_n: 10              # processes and families per list
  family_by: systemd_unit       # systemd_unit | cgroup — how forked workers are grouped
  max_connections_per_process: 50
  max_peers_per_process: 20
```

Under the existing `mysql:` section add:

```yaml
  # Query digests: one kernel event per command → per-pattern CPU, run-queue
  # wait, wall time and bytes. Ranks by TOTAL CPU so the query that causes a
  # CPU incident is separated from the queries merely slowed by it.
  emit_all_queries: true        # MYSQL_EMIT_ALL_QUERIES; false = slow-only legacy mode
  digest_window: 60s            # MYSQL_DIGEST_WINDOW
  top_digests: 20
  sticky_digests_max: 50        # digests exported to Prometheus
  sticky_digest_ttl: 1h
  culprit_cpu_share_percent: 20
  victim_runq_ratio: 5
```

Append a new section:

```yaml
# Always-on per-process TCP flow accounting (eBPF). Feeds
# process_report.*.network and obs_agent_family_net_* metrics.
netflow:
  enabled: true                 # NETFLOW_ENABLED
  poll_interval: 5s
  window: 60s
  include_loopback: true        # NETFLOW_INCLUDE_LOOPBACK
  listen_refresh_interval: 30s
  max_families: 50              # Prometheus family label cap (overflow → "other")
  max_outbound_peers: 100       # Prometheus peer_ip label cap per node
```

Run (Linux host): `sudo timeout 5 ./build/obs-agent -config deploy/config.yaml.example 2>&1 | grep -i 'invalid config' || echo CONFIG_OK`
Expected: `CONFIG_OK`.

- [ ] **Step 6: Update `AGENTS.md` and `CLAUDE.md`**

6a. In both files' §2 Project Structure tree add:

```
│   ├── sqldigest/sqldigest.go       ← SQL → normalised digest (DB-agnostic)
│   ├── querystats/querystats.go     ← rolling per-digest CPU/runq/bytes, culprit/victim roles
│   ├── netinv/netinv.go             ← on-demand /proc TCP inventory (listen ports, connections)
│   ├── netflow/                     ← windowed per-process/family flow accounting
│   ├── procreport/procreport.go     ← builds process_report
│   ├── promcollect/                 ← family + MySQL digest Prometheus collectors
│   ├── mysql/cmdmap/cmdmap.go       ← MySQL command → class + digest
```

and under `internal/ebpf/`:

```
│   │   ├── netflow/                 ← always-on TCP flow accounting
│   │   │   ├── netflow.bpf.c        ← inet_sock_set_state, inet_csk_accept,
│   │   │   │                          tcp_sendmsg, tcp_cleanup_rbuf
│   │   │   ├── gen.go
│   │   │   └── loader.go            ← implements netflow.Source
```

6b. In `AGENTS.md` add a TOC line `20. [Process Families, Network Flows & Query Digests](#20-process-families-network-flows--query-digests)` and append the section below at the end. In `CLAUDE.md` insert the same section **before** `## 20. Review output`, renumber that heading to `## 21. Review output`, and add the TOC line.

````markdown
## 20. Process Families, Network Flows & Query Digests

### Why

In a MySQL CPU incident every query's wall time inflates, so the slow-query
list fills with *victims*. This feature separates the query pattern that
**consumes** the CPU from the queries that only **waited** for it, and shows
which services (process families) are heavy and who they talk to.

```
wall = on-CPU  +  run-queue wait  +  blocked (I/O, locks)
       culprit     cascade victim
```

### Components

| Unit | What it does |
|---|---|
| `ebpf/netflow` | Always-on. Counts TCP bytes and connections per {tgid, direction, peer, service port} in an LRU map. Owner is recorded at connect/accept (process context); bytes are charged to the current process at `tcp_sendmsg` / `tcp_cleanup_rbuf`. |
| `ebpf/mysql_query` | Per `dispatch_command`: wall, on-CPU (`se.sum_exec_runtime` Δ), run-queue wait (`sched_info.run_delay` Δ), result bytes (`tcp_sendmsg` / `unix_stream_sendmsg` returns). One ring-buffer event per command. |
| `sqldigest` + `querystats` | Normalise SQL → digest; aggregate over a 60 s window; rank by **total** CPU; label `culprit` (≥ 20 % of mysqld query CPU) or `victim` (run-queue wait > 5 × CPU and slow). |
| `process` | Groups processes into families by systemd unit (`nginx.service`), falling back to `.scope` / cgroup path. |
| `netinv` | On demand only: listening ports and live connections (`src → dst`, client → server) from `/proc/net/tcp*` + `/proc/<pid>/fd`. |

### GET /api/diagnose

- `process_report.top_cpu[]` / `top_mem[]` — top 10 processes with `listening_ports`, `network` (inbound/outbound conns and bytes over the window, `top_peers`), `connections` (≤ 50, `connections_truncated`), `profile_url`.
- `process_report.top_families_cpu[]` / `top_families_mem[]` — top 10 families with `process_count`, `root_pid`, `top_members`, summed `network`.
- `mysql_report.top_digests[]` — top 20 by `cpu_ms_total` with `calls`, `cpu_ms_avg`, `runq_wait_ms_avg`, `wall_ms_avg`, `bytes_out_total`, `cpu_share_percent`, `role`. `top_digests_by_bytes_out[]` ranks by result size.
- `mysql_report.cpu_accounting` = `run_delay_unavailable` when the kernel lacks scheduler stats; victims are then judged on `wall − cpu`.

```bash
curl -s localhost:9200/api/diagnose | jq '.mysql_report.top_digests[] | {digest_text, role, cpu_share_percent, runq_wait_ms_avg}'
curl -s localhost:9200/api/diagnose | jq '.process_report.top_families_cpu[] | {family, process_count, cpu_percent, net: .network.inbound}'
```

### Prometheus

Never labelled by PID, client port or raw SQL. Caps: 50 families, 100 outbound peers, 50 sticky digests; overflow → `"other"`.

| Metric | Labels |
|---|---|
| `obs_agent_family_cpu_percent`, `_mem_rss_bytes`, `_processes` | `family` |
| `obs_agent_family_net_bytes_total` | `family, direction, flow` |
| `obs_agent_family_net_connections_opened_total`, `_active` | `family, direction` |
| `obs_agent_family_inbound_bytes_total` | `family, service_port, flow` |
| `obs_agent_family_outbound_peer_bytes_total` | `family, peer_ip, service_port, flow` |
| `obs_agent_mysql_queries_total`, `_query_cpu_seconds_total`, `_query_runq_wait_seconds_total`, `_query_wall_seconds_total` | `command` |
| `obs_agent_mysql_query_bytes_total` | `command, flow` |
| `obs_agent_mysql_digest_{cpu_seconds,calls,bytes_out,runq_wait_seconds}_total` | `digest_id` |
| `obs_agent_mysql_digest_info` (=1) | `digest_id, digest_text` |
| `obs_agent_mysql_events_dropped_total` | — |

Join digest text in Grafana: `topk(10, rate(obs_agent_mysql_digest_cpu_seconds_total[5m])) * on(instance, digest_id) group_left(digest_text) obs_agent_mysql_digest_info`.

Alert rules: `deploy/prometheus/obs-agent-alerts.yaml` (tests: `promtool test rules deploy/prometheus/obs-agent-alerts_test.yaml`).

### Accuracy and limits

- Per-call CPU is ± one scheduler tick (1–4 ms); per-digest **totals** are accurate. `cpu_ms_avg` is unreliable below 1 ms.
- Query text is captured up to 511 bytes (`truncated: true` beyond).
- `COM_STMT_EXECUTE` (server-side prepared statements) is measured under the placeholder digest `<COM_STMT_EXECUTE: prepared, text unavailable>`.
- Process-level network covers TCP only (no UDP, no unix sockets). Pre-existing idle connections are invisible to eBPF until they carry traffic; the `/proc` `connections` list still shows them.
- Uprobes attach to the mysqld binary inode: a mysqld restart is traced automatically; a package upgrade that replaces the binary needs an agent restart.

### Overhead

| Component | CPU | Memory |
|---|---|---|
| netflow eBPF (~100k hook calls/s) | ~0.4 % | ~6 MB maps |
| mysql per-command events (20k QPS) | ~0.3 % kernel + ~1 % userspace | 4 MB ringbuf + ~5 MB digests |
| family grouping (10 s scan) | ~0.02 % | < 1 MB |
| netinv (per /api/diagnose) | 20–50 ms per call | transient |
````

6c. In both files' §13 Prometheus Metrics table append the rows from the table above, and in §14 Performance Budget append the overhead rows.

- [ ] **Step 7: Commit**

```bash
git add deploy/prometheus/obs-agent-alerts.yaml deploy/prometheus/obs-agent-alerts_test.yaml \
        deploy/config.yaml.example AGENTS.md CLAUDE.md
git commit -m "docs: alert rules, config keys and docs for process/network/digest features

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 8: Codex review (CLAUDE.md §20)**

Run: `codex exec "Review the last commit (git show HEAD): PromQL correctness (vector matching, precedence of and/>), alert label sets, doc accuracy against the code. Report findings only."`
Fix confirmed findings, re-run Step 4, commit `fix(docs): address review`.

---

### Task 13: End-to-end acceptance on a MySQL VM

**Files:** none (verification only; record results in the PR description).

**Interfaces:**
- Consumes: the built agent from Task 11 and the alert rules from Task 12.
- Produces: evidence that the spec's acceptance criteria hold.

Host: x86_64 Linux VM with MySQL 8.0, `sysbench`, `stress-ng`, `jq`, the promtool tarball from Task 12, and the agent built with `make build`.

- [ ] **Step 1: Prepare data and start the agent**

```bash
export MYSQL_ARGS="--mysql-user=root --mysql-password=<pw> --mysql-host=127.0.0.1"
mysql -uroot -p<pw> -e "CREATE DATABASE IF NOT EXISTS sbtest"
sysbench oltp_read_only $MYSQL_ARGS --tables=1 --table-size=2000000 prepare
sudo MYSQL_TRACING_ENABLED=true ./build/obs-agent -config deploy/config.yaml.example -loglevel info &
```

- [ ] **Step 2: Run victims, culprit and CPU pressure together**

```bash
# Victims: text-protocol point selects (--db-ps-mode=disable, otherwise sysbench uses prepared statements)
sysbench oltp_point_select $MYSQL_ARGS --tables=1 --table-size=2000000 --db-ps-mode=disable \
  --threads=16 --time=600 run >/tmp/sysbench.log &
# Culprit: unindexed GROUP BY scanning 2M rows, 4 parallel loops
for i in 1 2 3 4; do
  (while true; do mysql -uroot -p<pw> -h127.0.0.1 -e \
    "SELECT LEFT(pad,3) p, COUNT(*) FROM sbtest.sbtest1 GROUP BY p" >/dev/null; done) &
done
stress-ng --cpu $(nproc) --timeout 600s &
sleep 120
```

- [ ] **Step 3: Verify the culprit and the victims**

```bash
curl -s localhost:9200/api/diagnose | jq '.mysql_report | {cpu_accounting, dropped_events,
  top: [.top_digests[0:3][] | {digest_text, role, cpu_share_percent, cpu_ms_avg, runq_wait_ms_avg, wall_ms_avg}]}'
```
Expected:
- `top[0].digest_text` == `"select left ( pad , ? ) p , count ( * ) from sbtest . sbtest1 group by p"` with `role: "culprit"`.
- The digest `"select c from sbtest1 where id = ?"` appears with `role: "victim"`: `runq_wait_ms_avg` well above `cpu_ms_avg`.
- `cpu_accounting: "ok"`, `dropped_events` 0 or close to it.

- [ ] **Step 4: Verify the large-result ranking**

```bash
(for i in $(seq 1 30); do mysql -uroot -p<pw> -h127.0.0.1 -e "SELECT * FROM sbtest.sbtest1 LIMIT 200000" >/dev/null; done)
curl -s localhost:9200/api/diagnose | jq '.mysql_report.top_digests_by_bytes_out[0] | {digest_text, bytes_out_avg}'
```
Expected: `digest_text` == `"select * from sbtest . sbtest1 limit ?"`, `bytes_out_avg` > 30,000,000.

- [ ] **Step 5: Verify process families and network**

```bash
curl -s localhost:9200/api/diagnose | jq '.process_report.top_families_cpu[] | select(.family=="mysql.service")
  | {process_count, cpu_percent, listening_ports, inbound: .network.inbound, peers: .network.top_peers[0:3]}'
curl -s localhost:9200/api/diagnose | jq '.process_report.top_cpu[] | select(.comm=="mysqld") | {connections: .connections[0:3], connections_truncated}'
```
Expected (the unit is `mysqld.service` on RHEL-family hosts — use `systemctl status mysql mysqld` to see which; adjust the `select`): `mysql.service` listens on 3306; `inbound.conns_active` ≈ 16–20; `inbound.bytes_tx` > 0; connections show `src` = client `127.0.0.1:<ephemeral>` and `dst` = `127.0.0.1:3306`.

- [ ] **Step 6: Verify the alerts fire in a real Prometheus**

```bash
cat >/tmp/prom.yml <<'EOF'
global: { scrape_interval: 15s, evaluation_interval: 15s }
rule_files: [ "REPO/deploy/prometheus/obs-agent-alerts.yaml" ]
scrape_configs:
  - job_name: obs-agent
    static_configs: [ { targets: ["localhost:9200"] } ]
EOF
sed -i "s#REPO#$(pwd)#" /tmp/prom.yml
/tmp/prometheus-2.53.2.linux-amd64/prometheus --config.file=/tmp/prom.yml --storage.tsdb.path=/tmp/promdata --web.listen-address=:9090 &
sleep 660
curl -s localhost:9090/api/v1/alerts | jq '[.data.alerts[] | {alertname: .labels.alertname, state, digest_id: .labels.digest_id}]'
```
Expected: `MySQLQueryDigestCPUHog` firing for the culprit's `digest_id` (match it against `obs_agent_mysql_digest_info`) and `MySQLQueriesStarvedForCPU` firing.

- [ ] **Step 7: Measure overhead**

```bash
pidstat -u -r -p $(pgrep -f build/obs-agent) 10 6 | tail -3
curl -s localhost:9200/api/diagnose | jq '.mysql_report.dropped_events'
```
Expected: agent average `%CPU` < 2 % of one core (sysbench QPS appears in `/tmp/sysbench.log`; it must be close to 20k for this measurement to count — raise `--threads` if lower), `RSS` < 100 MB, `dropped_events` not increasing.

- [ ] **Step 8: Clean up**

```bash
kill %1 %2 %3 %4 %5 %6 %7 %8 2>/dev/null; sudo pkill -f build/obs-agent; pkill prometheus
sysbench oltp_read_only $MYSQL_ARGS --tables=1 cleanup
```

- [ ] **Step 9: Whole-branch review and finish**

Run: `codex exec "Review the whole branch diff (git diff main...HEAD) against docs/superpowers/specs/2026-10-06-process-network-mysql-digest-design.md. Report correctness bugs and spec gaps only."`
Fix confirmed findings (commit `fix: address branch review`), then use superpowers:finishing-a-development-branch.
