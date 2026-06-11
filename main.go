package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/dhruvsolanki0811/dns-resolver/internal/dns"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "lookup":
		if err := runLookup(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "lookup:", err)
			os.Exit(1)
		}
	case "parse", "serve":
		fmt.Fprintf(os.Stderr, "subcommand %q not yet implemented\n", os.Args[1])
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dns-resolver <parse|lookup|serve> [args]")
	fmt.Fprintln(os.Stderr, "  lookup <qname> [-t TYPE] [@server]")
}

// runLookup implements: dns-resolver lookup <qname> [-t TYPE] [@server]
func runLookup(args []string) error {
	fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
	qtypeStr := fs.String("t", "A", "query type (currently A only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("usage: dns-resolver lookup <qname> [-t TYPE] [@server]")
	}
	qname := rest[0]

	// Default to Google DNS; allow @host or @host:port override.
	server := "8.8.8.8:53"
	for _, a := range rest[1:] {
		if strings.HasPrefix(a, "@") {
			s := strings.TrimPrefix(a, "@")
			if !strings.Contains(s, ":") {
				s = s + ":53"
			}
			server = s
		}
	}
	addr, err := netip.ParseAddrPort(server)
	if err != nil {
		return fmt.Errorf("bad server %q: %w", server, err)
	}

	qt := typeFromString(*qtypeStr)
	pkt, err := dns.Lookup(qname, qt, addr)
	if err != nil {
		return err
	}

	// Pretty-print the response sections.
	fmt.Printf("Header: %+v\n", pkt.Header)
	for _, q := range pkt.Questions {
		fmt.Println("Q:    ", q.Name, q.Qtype)
	}
	for _, r := range pkt.Answers {
		fmt.Println("A:    ", r)
	}
	for _, r := range pkt.Authorities {
		fmt.Println("AUTH: ", r)
	}
	for _, r := range pkt.Resources {
		fmt.Println("ADD:  ", r)
	}
	return nil
}

// typeFromString maps a CLI string ("A") to a QueryType.
func typeFromString(s string) dns.QueryType {
	switch strings.ToUpper(s) {
	case "A":
		return dns.TypeA
	case "NS":
		return dns.TypeNS
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "AAAA":
		return dns.TypeAAAA
	default:
		return dns.TypeUnknown
	}
}
