// Command pgsymdump prints what the pg_query tracer resolves from a postgres
// binary, in the format of internal/postgres/pgsym/testdata/*.syms. To add a
// release:
//
//	go run ./internal/postgres/pgsym/cmd/pgsymdump -label "19.0 (postgresql-19 19.0-1.pgdg24.04+1 amd64)" \
//	    /usr/lib/postgresql/19/bin/postgres > internal/postgres/pgsym/testdata/19.0.syms
//
// then add the expectations to TestCompatMatrix.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/manhvu1997/linux-obs-agent/internal/postgres/pgsym"
)

func main() {
	label := flag.String("label", "", "version and package recorded in the header comment")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pgsymdump [-label text] /path/to/postgres")
		os.Exit(2)
	}
	v, syms, err := pgsym.ReadELF(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *label != "" {
		fmt.Printf("# postgres %s\n", *label)
	}
	fmt.Printf("version %s\n", v.Full)
	for _, s := range syms {
		fmt.Println(s)
	}
	h, err := pgsym.Resolve(v, syms)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "resolve:", h.Summary(true, true))
}
