package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "parse", "lookup", "serve":
		fmt.Fprintf(os.Stderr, "subcommand %q not yet implemented\n", os.Args[1])
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dns-resolver <parse|lookup|serve> [args]")
}
