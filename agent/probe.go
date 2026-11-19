package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// runProbe: "seclab-agent probe [-timeout 2s] host:port ..." -> one "host:port open|closed" line per
// target, in input order. Connects in parallel, so a batch costs one timeout, not one per target.
func runProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 2*time.Second, "per-connection timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	targets := fs.Args()
	res := make([]bool, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i, t := range targets {
		if _, _, err := net.SplitHostPort(t); err != nil {
			fmt.Fprintf(os.Stderr, "bad target %q\n", t)
			return 2
		}
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c, err := net.DialTimeout("tcp", t, *timeout)
			if err == nil {
				c.Close()
				res[i] = true
			}
		}(i, t)
	}
	wg.Wait()
	for i, t := range targets {
		state := "closed"
		if res[i] {
			state = "open"
		}
		fmt.Printf("%s %s\n", t, state)
	}
	return 0
}
