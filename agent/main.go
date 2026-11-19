// seclab-agent: static multi-tool for lab nodes (no libc, runs FROM scratch).
//
//	seclab-agent vulnweb [flags]          vulnerable intranet web app with difficulty levels
//	seclab-agent probe host:port ...      parallel TCP reachability probe
//	seclab-agent attack -target URL       run the training exploit catalogue against your own lab site
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: seclab-agent vulnweb|probe|attack [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "vulnweb":
		os.Exit(runVulnweb(os.Args[2:]))
	case "probe":
		os.Exit(runProbe(os.Args[2:]))
	case "attack":
		os.Exit(runAttack(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
