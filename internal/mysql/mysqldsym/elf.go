package mysqldsym

import (
	"debug/elf"
	"fmt"
	"strings"
)

// fragments select the function symbols Resolve looks at. They are wider
// than the accepted names on purpose: decoys (nested lambdas, split parts,
// other classes' dispatch_command) must reach Resolve so it can reject them,
// and the fixtures in testdata record them.
var fragments = []string{
	"dispatch_command",
	"Prepared_statement7prepare",
	"Prepared_statement12execute_loop",
	"log_write_up_to",
}

// ReadELF returns the function symbols of the mysqld binary at path that
// Resolve needs, in symbol-table order: .symtab first (unstripped builds),
// then .dynsym (always present; MySQL exports its C++ symbols there), without
// duplicates. A binary with neither table yields an error.
func ReadELF(path string) ([]string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elf.Open: %w", err)
	}
	defer f.Close()

	var out []string
	seen := make(map[string]bool)
	collect := func(syms []elf.Symbol) {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || seen[s.Name] || !relevant(s.Name) {
				continue
			}
			seen[s.Name] = true
			out = append(out, s.Name)
		}
	}
	symtab, errS := f.Symbols()
	collect(symtab)
	dynsym, errD := f.DynamicSymbols()
	collect(dynsym)
	if errS != nil && errD != nil {
		return nil, fmt.Errorf("%s has no symbol table (.symtab: %v, .dynsym: %v)", path, errS, errD)
	}
	return out, nil
}

func relevant(name string) bool {
	for _, f := range fragments {
		if strings.Contains(name, f) {
			return true
		}
	}
	return false
}
