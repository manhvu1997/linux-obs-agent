package pgsym

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, path string) (Version, []string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var v Version
	var syms []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "#") || line == "":
		case strings.HasPrefix(line, "version "):
			if v, err = ParseVersion([]byte(strings.TrimPrefix(line, "version "))); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		default:
			syms = append(syms, line)
		}
	}
	return v, syms
}

func TestCompatMatrix(t *testing.T) {
	want := map[string]struct {
		major, minor     int
		pre              string
		running, fastpth uint32
	}{
		"16.15-22.04.syms": {16, 15, "", 2, 4},
		"16.15-24.04.syms": {16, 15, "", 2, 4},
		"17.11.syms":       {17, 11, "", 2, 4},
		"18.6.syms":        {18, 6, "", 3, 5},
		"19beta4.syms":     {19, 0, "beta4", 3, 5},
	}
	files, _ := filepath.Glob("testdata/*.syms")
	if len(files) != len(want) {
		t.Fatalf("fixtures %v, want %d", files, len(want))
	}
	for _, path := range files {
		w := want[filepath.Base(path)]
		v, syms := loadFixture(t, path)
		if v.Major != w.major || v.Minor != w.minor || v.Pre != w.pre {
			t.Errorf("%s: version %+v", path, v)
		}
		h, err := Resolve(v, syms)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if h.States.Running != w.running || h.States.Fastpath != w.fastpth {
			t.Errorf("%s: states %+v", path, h.States)
		}
		for name, got := range map[string]string{SymActivity: h.Activity, SymPortalRun: h.PortalRun,
			SymQueryID: h.QueryID, SymXLogFlush: h.XLogFlush, SymSyncRep: h.SyncRep, SymParallel: h.Parallel} {
			if got != name {
				t.Errorf("%s: hook %s = %q", path, name, got)
			}
		}
		if h.QueryIDErr != nil || h.XLogFlushErr != nil || h.SyncRepErr != nil || h.ParallelErr != nil {
			t.Errorf("%s: optional hook errors %+v", path, h)
		}
	}
}

func TestRefusesUnknownMajors(t *testing.T) {
	for _, s := range []string{
		"PostgreSQL 15.8 (Ubuntu 15.8-1) on x86_64-pc-linux-gnu, compiled by",
		"PostgreSQL 20devel on x86_64-pc-linux-gnu, compiled by",
	} {
		v, err := ParseVersion([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Resolve(v, []string{SymActivity, SymPortalRun}); err == nil {
			t.Errorf("%s: want refusal", v)
		}
	}
}

func TestMissingRequiredAndOptional(t *testing.T) {
	v, _ := ParseVersion([]byte("PostgreSQL 17.2 on x86_64-pc-linux-gnu, compiled by"))
	if _, err := Resolve(v, []string{SymPortalRun}); err == nil {
		t.Fatal("missing pgstat_report_activity must refuse")
	}
	h, err := Resolve(v, []string{SymActivity, SymPortalRun})
	if err != nil {
		t.Fatal(err)
	}
	if h.QueryIDErr == nil || h.XLogFlushErr == nil || h.SyncRepErr == nil || h.ParallelErr == nil {
		t.Fatal("missing optional hooks must carry errors")
	}
	if got := h.Summary(false, false); got != "activity=ok portalrun=ok queryid=off xlogflush=unavailable syncrep=off parallel=unavailable" {
		t.Errorf("summary %q", got)
	}
}

func TestParseVersionSourceBuild(t *testing.T) {
	v, err := ParseVersion([]byte("junk\x00PostgreSQL 18.1 on x86_64-pc-linux-gnu, compiled by gcc\x00"))
	if err != nil || v.Major != 18 || v.Minor != 1 || v.String() != "18.1" {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := ParseVersion([]byte("no banner here")); err == nil {
		t.Fatal("want error")
	}
}
