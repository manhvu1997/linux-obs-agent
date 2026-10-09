// Package mysqldsym decides which mysqld functions the MySQL tracer hooks and
// how their arguments are laid out, from the binary's symbol names alone.
//
// Every accepted name is a signature rule checked against real MySQL builds
// (testdata/*.syms: 5.7, 8.0.11 – 8.0.46, 8.4, 9.7, 26.7). A name that matches
// no rule is refused rather than guessed: a uprobe on the wrong function, or
// arguments read from the wrong registers, records garbage silently.
//
// Pure: no eBPF, no I/O except ReadELF, so it is tested on any OS.
package mysqldsym

import (
	"errors"
	"fmt"
	"strings"
)

// DispatchSymbol is dispatch_command(THD*, const COM_DATA*, enum_server_command),
// unchanged from MySQL 5.7 to 26.7. Matched exactly: 8.0.11 also exports
// xpl::dispatcher::dispatch_command, and MariaDB's dispatch_command takes the
// command first.
const DispatchSymbol = "_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command"

// Mangled prefixes of the methods themselves (Itanium ABI nested name). A
// local entity of the method (a lambda's operator()) starts "_ZZN…" instead.
const (
	preparePrefix     = "_ZN18Prepared_statement7prepareE"
	executeLoopPrefix = "_ZN18Prepared_statement12execute_loopE"
	redoPrefix        = "_Z15log_write_up_to"
)

// PrepareLayout is the register layout of Prepared_statement::prepare's
// query text and length (x86-64 SysV; RDI is this).
type PrepareLayout int

const (
	// QueryFirst: prepare(const char*, size_t[, …]) — query RSI, length RDX.
	// MySQL 5.7 and 8.0 up to at least 8.0.28.
	QueryFirst PrepareLayout = iota + 1
	// THDFirst: prepare(THD*, const char*, size_t, Item_param**) — query RDX,
	// length RCX. MySQL 8.0.36+, 8.4, 9.x, 26.x.
	THDFirst
)

func (l PrepareLayout) String() string {
	switch l {
	case QueryFirst:
		return "query_first"
	case THDFirst:
		return "thd_first"
	}
	return "unavailable"
}

// Hooks are the resolved uprobe symbols. Dispatch is always set when Resolve
// succeeds; the optional hooks carry their own error instead.
type Hooks struct {
	Dispatch string

	// Prepared-statement text recovery: both hooks or neither.
	Prepare       string
	PrepareLayout PrepareLayout
	ExecuteLoop   string
	PreparedErr   error

	// Redo (commit) wait. Only entry and return times are taken, so any
	// argument list is accepted.
	Redo    string
	RedoErr error
}

// Resolve picks the hooks from a binary's function symbol names (ReadELF).
// The error is non-nil only when dispatch_command cannot be hooked safely,
// in which case the tracer must not start.
func Resolve(symbols []string) (Hooks, error) {
	var h Hooks
	for _, s := range symbols {
		if s == DispatchSymbol {
			h.Dispatch = s
			break
		}
	}
	if h.Dispatch == "" {
		return h, fmt.Errorf("no supported dispatch_command (want %s; candidates %v): "+
			"unsupported mysqld build — run internal/mysql/mysqldsym/cmd/symdump on it",
			DispatchSymbol, candidates(symbols, "dispatch_command"))
	}
	h.Prepare, h.PrepareLayout, h.ExecuteLoop, h.PreparedErr = resolvePrepared(symbols)
	h.Redo, h.RedoErr = resolveRedo(symbols)
	return h, nil
}

// Summary is the one-line hook status logged at start.
func (h Hooks) Summary() string {
	exec := "unavailable"
	if h.PreparedErr == nil {
		exec = "ok"
	}
	return fmt.Sprintf("dispatch=ok prepare=%s execute_loop=%s", h.PrepareLayout, exec)
}

func resolvePrepared(symbols []string) (prepare string, layout PrepareLayout, exec string, err error) {
	for _, s := range symbols {
		if l := prepareLayout(s); l != 0 {
			prepare, layout = s, l
			break
		}
	}
	if prepare == "" {
		return "", 0, "", fmt.Errorf("no Prepared_statement::prepare with a known argument layout (candidates %v)",
			candidates(symbols, "Prepared_statement7prepare"))
	}
	for _, s := range symbols {
		if strings.HasPrefix(s, executeLoopPrefix) && !isSplitPart(s) {
			exec = s
			break
		}
	}
	if exec == "" {
		return "", 0, "", fmt.Errorf("no Prepared_statement::execute_loop symbol (candidates %v)",
			candidates(symbols, "Prepared_statement12execute_loop"))
	}
	return prepare, layout, exec, nil
}

// prepareLayout returns 0 for anything but the method itself with an
// optional leading THD* followed by (const char*, size_t). Trailing
// parameters do not move the query and length registers.
func prepareLayout(sym string) PrepareLayout {
	params, ok := strings.CutPrefix(sym, preparePrefix)
	if !ok || isSplitPart(sym) {
		return 0
	}
	switch {
	case strings.HasPrefix(params, "P3THDPKcm"):
		return THDFirst
	case strings.HasPrefix(params, "PKcm"):
		return QueryFirst
	}
	return 0
}

func resolveRedo(symbols []string) (string, error) {
	for _, s := range symbols {
		if strings.HasPrefix(s, redoPrefix) && !isSplitPart(s) {
			return s, nil
		}
	}
	return "", errors.New("no log_write_up_to symbol")
}

// isSplitPart reports compiler-generated parts and clones (".cold",
// ".isra.0", ".constprop.0", …): not the function entry, and their arguments
// are not in the ABI registers.
func isSplitPart(sym string) bool { return strings.Contains(sym, ".") }

func candidates(symbols []string, fragment string) []string {
	var out []string
	for _, s := range symbols {
		if strings.Contains(s, fragment) {
			out = append(out, s)
		}
	}
	return out
}
