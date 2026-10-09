// Command symdump prints the mysqld symbols the MySQL tracer resolves, in the
// format of internal/mysql/mysqldsym/testdata/*.syms, followed by what
// Resolve makes of them. To add a MySQL release to the compatibility matrix:
//
//	go run ./internal/mysql/mysqldsym/cmd/symdump -label "9.8.0 (mysql-community-server-core 9.8.0-1ubuntu22.04 amd64)" \
//	    /path/to/usr/sbin/mysqld > internal/mysql/mysqldsym/testdata/9.8.0.syms
//
// then add the expected hooks to TestCompatMatrix.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/manhvu1997/linux-obs-agent/internal/mysql/mysqldsym"
)

func main() {
	label := flag.String("label", "", "version and package recorded in the header comment")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: symdump [-label text] /path/to/mysqld")
		os.Exit(2)
	}
	syms, err := mysqldsym.ReadELF(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *label != "" {
		fmt.Printf("# mysqld %s\n", *label)
	}
	for _, s := range syms {
		fmt.Println(s)
	}
	h, err := mysqldsym.Resolve(syms)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "resolve:", h.Summary())
}
