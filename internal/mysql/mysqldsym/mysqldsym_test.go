package mysqldsym

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	dispatch      = "_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command"
	prepQuery     = "_ZN18Prepared_statement7prepareEPKcm"
	prepTHD       = "_ZN18Prepared_statement7prepareEP3THDPKcmPP10Item_param"
	execTHD       = "_ZN18Prepared_statement12execute_loopEP3THDP6Stringb"
	redo57        = "_Z15log_write_up_tomb"
	redo80        = "_Z15log_write_up_toR5log_tmb"
	xplDispatcher = "_ZN3xpl10dispatcher16dispatch_commandERNS_7SessionERNS_20Crud_command_handlerERNS_17Expectation_stackERN3ngs15Message_requestE"
)

// readFixture loads testdata/<name>.syms: one symbol per line, # comments.
func readFixture(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name+".syms"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCompatMatrix pins every MySQL build whose real symbol table was
// inspected. A new release is added with cmd/symdump (see its doc comment).
func TestCompatMatrix(t *testing.T) {
	cases := []struct {
		fixture string
		prepare string
		layout  PrepareLayout
		exec    string
		redo    string
	}{
		{"5.7.42", prepQuery, QueryFirst, "_ZN18Prepared_statement12execute_loopEbPhS0_", redo57},
		{"8.0.11", prepQuery, QueryFirst, "_ZN18Prepared_statement12execute_loopEP6Stringb", redo80},
		{"8.0.14", "_ZN18Prepared_statement7prepareEPKcmb", QueryFirst, "_ZN18Prepared_statement12execute_loopEP6Stringb", redo80},
		{"8.0.19", prepQuery, QueryFirst, "_ZN18Prepared_statement12execute_loopEP6Stringb", redo80},
		{"8.0.28", "_ZN18Prepared_statement7prepareEPKcmPP10Item_param", QueryFirst, "_ZN18Prepared_statement12execute_loopEP6Stringb", redo80},
		{"8.0.36", prepTHD, THDFirst, execTHD, redo80},
		{"8.0.46", prepTHD, THDFirst, execTHD, redo80},
		{"8.4.11", prepTHD, THDFirst, execTHD, redo80},
		{"9.7.2", prepTHD, THDFirst, execTHD, redo80},
		{"26.7.0", prepTHD, THDFirst, execTHD, redo80},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			h, err := Resolve(readFixture(t, c.fixture))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if h.Dispatch != dispatch {
				t.Errorf("Dispatch = %q", h.Dispatch)
			}
			if h.PreparedErr != nil || h.Prepare != c.prepare || h.PrepareLayout != c.layout || h.ExecuteLoop != c.exec {
				t.Errorf("prepared hooks = %q %v %q (err %v), want %q %v %q",
					h.Prepare, h.PrepareLayout, h.ExecuteLoop, h.PreparedErr, c.prepare, c.layout, c.exec)
			}
			if h.RedoErr != nil || h.Redo != c.redo {
				t.Errorf("Redo = %q (err %v), want %q", h.Redo, h.RedoErr, c.redo)
			}
		})
	}
}

func TestDispatchIsExactSignature(t *testing.T) {
	// 8.0.11 exports the X plugin's dispatcher before the server's
	// dispatch_command; substring matching attached to the wrong function.
	h, err := Resolve([]string{xplDispatcher, dispatch})
	if err != nil || h.Dispatch != dispatch {
		t.Fatalf("got %q, %v", h.Dispatch, err)
	}
	for name, syms := range map[string][]string{
		"only the X plugin dispatcher": {xplDispatcher},
		"MariaDB signature":            {"_Z16dispatch_command19enum_server_commandP3THDPcjb"},
		"split part only":              {dispatch + ".cold"},
		"none":                         nil,
	} {
		if _, err := Resolve(syms); err == nil {
			t.Errorf("%s: want an error, refusing to read the wrong registers", name)
		}
	}
}

func TestPrepareLayouts(t *testing.T) {
	cases := []struct {
		name   string
		sym    string
		layout PrepareLayout // 0 = rejected
	}{
		{"5.7 / early 8.0", prepQuery, QueryFirst},
		{"8.0.14 extra bool", "_ZN18Prepared_statement7prepareEPKcmb", QueryFirst},
		{"8.0.28 param array", "_ZN18Prepared_statement7prepareEPKcmPP10Item_param", QueryFirst},
		{"8.0.36+ THD first", prepTHD, THDFirst},
		{"unknown overload", "_ZN18Prepared_statement7prepareEv", 0},
		{"length not size_t", "_ZN18Prepared_statement7prepareEPKcj", 0},
		{"nested lambda", "_ZZN18Prepared_statement7prepareEP3THDPKcmPP10Item_paramENKUlvE_clEv", 0},
		{"split part", prepTHD + ".cold", 0},
		{"isra clone", prepQuery + ".isra.0", 0},
	}
	for _, c := range cases {
		h, err := Resolve([]string{dispatch, c.sym, execTHD})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.layout == 0 {
			if h.PreparedErr == nil {
				t.Errorf("%s: accepted %q, want rejected", c.name, c.sym)
			}
			continue
		}
		if h.PreparedErr != nil || h.PrepareLayout != c.layout || h.Prepare != c.sym {
			t.Errorf("%s: got %q %v (err %v), want layout %v", c.name, h.Prepare, h.PrepareLayout, h.PreparedErr, c.layout)
		}
	}
}

func TestPreparedNeedsBothHooks(t *testing.T) {
	// LOCAL symbols come first in .symtab: a nested entity must never win.
	nestedExec := "_ZZN18Prepared_statement12execute_loopEP3THDP6StringbENKUlvE_clEv"
	h, _ := Resolve([]string{dispatch, nestedExec, prepTHD, execTHD})
	if h.PreparedErr != nil || h.ExecuteLoop != execTHD {
		t.Fatalf("nested execute_loop listed first: got %q, %v", h.ExecuteLoop, h.PreparedErr)
	}
	for name, syms := range map[string][]string{
		"no execute_loop":         {dispatch, prepTHD},
		"execute_loop split only": {dispatch, prepTHD, execTHD + ".cold"},
		"no prepare":              {dispatch, execTHD},
	} {
		h, err := Resolve(syms)
		if err != nil {
			t.Fatalf("%s: dispatch must still resolve: %v", name, err)
		}
		if h.PreparedErr == nil {
			t.Errorf("%s: want PreparedErr", name)
		}
	}
}

func TestRedo(t *testing.T) {
	h, _ := Resolve([]string{dispatch, redo80})
	if h.RedoErr != nil || h.Redo != redo80 {
		t.Fatalf("got %q, %v", h.Redo, h.RedoErr)
	}
	// Only timing is taken from it, so a future argument list is accepted.
	h, _ = Resolve([]string{dispatch, "_Z15log_write_up_toR5log_tmbb"})
	if h.RedoErr != nil {
		t.Fatalf("future overload rejected: %v", h.RedoErr)
	}
	for _, syms := range [][]string{{dispatch}, {dispatch, redo80 + ".cold"}, {dispatch, "_Z25log_write_up_to_internalv"}} {
		if h, _ := Resolve(syms); h.RedoErr == nil {
			t.Errorf("%v: want RedoErr", syms)
		}
	}
}

func TestSummary(t *testing.T) {
	h, _ := Resolve([]string{dispatch, prepTHD, execTHD, redo80})
	if got := h.Summary(); got != "dispatch=ok prepare=thd_first execute_loop=ok" {
		t.Errorf("Summary() = %q", got)
	}
	h, _ = Resolve([]string{dispatch})
	if got := h.Summary(); got != "dispatch=ok prepare=unavailable execute_loop=unavailable" {
		t.Errorf("Summary() = %q", got)
	}
}
