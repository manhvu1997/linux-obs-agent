//go:build linux

package mysql_query

import "testing"

func TestPrepareArgLayout(t *testing.T) {
	cases := []struct {
		name       string
		mangled    string
		hasTHD, ok bool
	}{
		{"mysql 8.4", "_ZN18Prepared_statement7prepareEP3THDPKcmPP10Item_param", true, true},
		{"mysql 8.0", "_ZN18Prepared_statement7prepareEPKcm", false, true},
		{"execute_loop is not prepare", "_ZN18Prepared_statement12execute_loopEP3THDP6Stringb", false, false},
		{"unknown overload", "_ZN18Prepared_statement7prepareEv", false, false},
		{"empty", "", false, false},
		{"junk", "dispatch_command", false, false},
		// Local entity nested in prepare (a lambda's operator()): same
		// substring, wrong function.
		{"nested lambda", "_ZZN18Prepared_statement7prepareEP3THDPKcmPP10Item_paramENKUlvE_clEv", false, false},
		{"8.0 nested lambda", "_ZZN18Prepared_statement7prepareEPKcmENKUlvE_clEv", false, false},
	}
	for _, c := range cases {
		hasTHD, ok := prepareArgLayout(c.mangled)
		if hasTHD != c.hasTHD || ok != c.ok {
			t.Errorf("%s: prepareArgLayout(%q) = (%v, %v), want (%v, %v)", c.name, c.mangled, hasTHD, ok, c.hasTHD, c.ok)
		}
	}
}

func TestPickPreparedSymbols(t *testing.T) {
	const (
		prep84 = "_ZN18Prepared_statement7prepareEP3THDPKcmPP10Item_param"
		exec84 = "_ZN18Prepared_statement12execute_loopEP3THDP6Stringb"
	)
	// Compiler split parts are skipped; the unknown overload is skipped.
	ps, err := pickPreparedSymbols(
		[]string{prep84 + ".cold", "_ZN18Prepared_statement7prepareEv", prep84},
		[]string{exec84 + ".cold", exec84})
	if err != nil || ps.prepare != prep84 || ps.executeLoop != exec84 || !ps.hasTHD {
		t.Fatalf("got %+v, %v", ps, err)
	}
	// .symtab lists LOCAL symbols first: nested entities must never win.
	ps, err = pickPreparedSymbols(
		[]string{"_ZZN18Prepared_statement7prepareEP3THDPKcmPP10Item_paramENKUlvE_clEv", prep84},
		[]string{"_ZZN18Prepared_statement12execute_loopEP3THDP6StringbENKUlvE_clEv", exec84})
	if err != nil || ps.prepare != prep84 || ps.executeLoop != exec84 {
		t.Fatalf("nested entities listed first: got %+v, %v", ps, err)
	}
	if _, err := pickPreparedSymbols([]string{prep84},
		[]string{"_ZZN18Prepared_statement12execute_loopEP3THDP6StringbENKUlvE_clEv"}); err == nil {
		t.Fatal("execute_loop with only a nested entity must be an error")
	}
	ps, err = pickPreparedSymbols([]string{"_ZN18Prepared_statement7prepareEPKcm"}, []string{exec84})
	if err != nil || ps.hasTHD {
		t.Fatalf("8.0 layout: got %+v, %v", ps, err)
	}
	if _, err := pickPreparedSymbols(nil, []string{exec84}); err == nil {
		t.Fatal("missing prepare must be an error")
	}
	if _, err := pickPreparedSymbols([]string{prep84}, []string{exec84 + ".cold"}); err == nil {
		t.Fatal("execute_loop with only a split part must be an error")
	}
}
