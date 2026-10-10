package chsink

import (
	"reflect"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/querystats"
)

func fdd(pid uint32, id, cmd string, cpu, disk, wallMax uint64) querystats.DigestDelta {
	return querystats.DigestDelta{PID: pid, DigestID: id, Command: cmd, Text: id, Calls: 1, CPUNs: cpu, WallNs: wallMax, WallMaxNs: wallMax, DiskReadBytes: disk, IOWaitNs: 1}
}

func TestFoldMinorKeepsTotals(t *testing.T) {
	in := []querystats.DigestDelta{
		fdd(1, "big", "query", 1_000_000, 1_000_000, 5),
		fdd(1, "tiny1", "query", 10, 10, 5),
		fdd(1, "tiny2", "query", 20, 0, 7),
		fdd(1, "tiny3", "stmt_execute", 30, 0, 5),
		fdd(2, "tiny4", "query", 40, 0, 5),
	}
	out := foldMinor(in, 0.1, 1_000)
	var cpu, disk, calls, io uint64
	minor := map[string]querystats.DigestDelta{}
	for _, x := range out {
		cpu, disk, calls, io = cpu+x.CPUNs, disk+x.DiskReadBytes, calls+x.Calls, io+x.IOWaitNs
		if x.DigestID == MinorDigestID {
			minor[string(rune('0'+x.PID))+x.Command] = x
		}
	}
	if cpu != 1_000_100 || disk != 1_000_010 || calls != 5 || io != 5 {
		t.Fatalf("totals cpu %d disk %d calls %d io %d changed", cpu, disk, calls, io)
	}
	if len(out) != 4 { // big + <minor> per (pid, command): (1,query) (1,stmt_execute) (2,query)
		t.Fatalf("rows = %d: %+v", len(out), out)
	}
	if m := minor["1query"]; m.Calls != 2 || m.WallMaxNs != 7 || m.Text != MinorDigestText || m.Sample != "" {
		t.Fatalf("minor (1, query) = %+v", m)
	}
}

func TestFoldMinorKeepsSlow(t *testing.T) {
	in := []querystats.DigestDelta{fdd(1, "big", "query", 1_000_000, 0, 5), fdd(1, "cheap-but-slow", "query", 10, 0, 5_000)}
	for _, x := range foldMinor(in, 0.1, 1_000) {
		if x.DigestID == MinorDigestID {
			t.Fatal("a statement with a slow execution must keep its own row")
		}
	}
}

func TestFoldMinorDisabled(t *testing.T) {
	in := []querystats.DigestDelta{fdd(1, "big", "query", 1_000_000, 0, 5), fdd(1, "tiny", "query", 1, 0, 5)}
	if out := foldMinor(in, 0, 1_000); len(out) != 2 {
		t.Fatalf("share 0 must disable folding, got %d rows", len(out))
	}
}

// Every numeric field of DigestDelta is folded into <minor>: summed, except
// WallMaxNs (the max) and PID (the grouping key). The loop walks the struct by
// reflection, so a field added later and not folded fails here.
func TestFoldMinorFoldsEveryField(t *testing.T) {
	const sharePct, slowNs = 0.1, 1_000_000
	big := querystats.DigestDelta{PID: 1, DigestID: "big", Command: "query", Calls: 1, CPUNs: 1e12, DiskReadBytes: 1e12}
	var tiny []querystats.DigestDelta
	for i := 0; i < 3; i++ {
		d := querystats.DigestDelta{PID: 1, DigestID: "tiny" + string(rune('a'+i)), Command: "query"}
		v := reflect.ValueOf(&d).Elem()
		for j := 0; j < v.NumField(); j++ {
			f := v.Field(j)
			name := v.Type().Field(j).Name
			if name == "PID" {
				continue
			}
			x := uint64((i+1)*1000 + (j+1)*10) // distinct per digest and per field, far under the share and slowNs
			switch f.Kind() {
			case reflect.String:
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				f.SetUint(x)
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				f.SetInt(int64(x))
			case reflect.Float32, reflect.Float64:
				f.SetFloat(float64(x))
			default:
				t.Fatalf("field %s has kind %s: teach this test (and foldMinor) how to fold it", name, f.Kind())
			}
		}
		tiny = append(tiny, d)
	}
	out := foldMinor(append([]querystats.DigestDelta{big}, tiny...), sharePct, slowNs)
	var got *querystats.DigestDelta
	for i := range out {
		if out[i].DigestID == MinorDigestID {
			got = &out[i]
		}
	}
	if len(out) != 2 || got == nil {
		t.Fatalf("want big + one <minor> row, got %+v", out)
	}
	gv := reflect.ValueOf(*got)
	for j := 0; j < gv.NumField(); j++ {
		name := gv.Type().Field(j).Name
		if name == "PID" || gv.Field(j).Kind() == reflect.String {
			continue
		}
		var want float64
		for _, d := range tiny {
			x := numeric(reflect.ValueOf(d).Field(j))
			if name == "WallMaxNs" {
				want = max(want, x)
			} else {
				want += x
			}
		}
		if g := numeric(gv.Field(j)); g != want {
			t.Errorf("<minor>.%s = %v, want %v", name, g, want)
		}
	}
}

func numeric(v reflect.Value) float64 {
	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(v.Uint())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int())
	}
	return v.Float()
}
