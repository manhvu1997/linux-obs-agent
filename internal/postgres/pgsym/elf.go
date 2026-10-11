package pgsym

import (
	"debug/elf"
	"fmt"
)

var hookNames = map[string]bool{SymActivity: true, SymPortalRun: true, SymQueryID: true,
	SymXLogFlush: true, SymSyncRep: true, SymParallel: true}

// ReadELF returns the binary's version (from .rodata) and the hook function
// symbols it has (.symtab first, then .dynsym), without duplicates.
func ReadELF(path string) (Version, []string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return Version{}, nil, fmt.Errorf("elf.Open: %w", err)
	}
	defer f.Close()
	ro := f.Section(".rodata")
	if ro == nil {
		return Version{}, nil, fmt.Errorf("%s has no .rodata", path)
	}
	data, err := ro.Data()
	if err != nil {
		return Version{}, nil, fmt.Errorf("reading .rodata: %w", err)
	}
	v, err := ParseVersion(data)
	if err != nil {
		return Version{}, nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []string
	seen := map[string]bool{}
	collect := func(syms []elf.Symbol) {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && hookNames[s.Name] && !seen[s.Name] {
				seen[s.Name] = true
				out = append(out, s.Name)
			}
		}
	}
	symtab, errS := f.Symbols()
	collect(symtab)
	dynsym, errD := f.DynamicSymbols()
	collect(dynsym)
	if errS != nil && errD != nil {
		return Version{}, nil, fmt.Errorf("%s has no symbol table (.symtab: %v, .dynsym: %v)", path, errS, errD)
	}
	return v, out, nil
}
