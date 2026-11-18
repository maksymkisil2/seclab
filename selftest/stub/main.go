// Offline stand-in for nginx:alpine + alpine when no registry is reachable.
// argv[0] dispatch:
//   nginx -> HTTP on :8080, HTTPS on :8443 (if /etc/nginx/tls/server.crt is mounted); nginx args ignored
//   nc    -> "nc -z -w N host port" TCP reachability probe (busybox-compatible subset)
// It does NOT emulate nginx config semantics: TLS/header checks are skipped in stub mode.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	if filepath.Base(os.Args[0]) == "nc" {
		os.Exit(nc(os.Args[1:]))
	}
	serve()
}

func nc(args []string) int {
	timeout := 2 * time.Second
	var pos []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-z":
		case "-w":
			i++
			if i < len(args) {
				if n, err := strconv.Atoi(args[i]); err == nil {
					timeout = time.Duration(n) * time.Second
				}
			}
		default:
			pos = append(pos, args[i])
		}
	}
	if len(pos) != 2 {
		fmt.Fprintln(os.Stderr, "usage: nc -z [-w sec] host port")
		return 2
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(pos[0], pos[1]), timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c.Close()
	return 0
}

func serve() {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("seclab stub\n"))
	})
	go func() { log.Fatal(http.ListenAndServe(":8080", h)) }()
	crt, key := "/etc/nginx/tls/server.crt", "/etc/nginx/tls/server.key"
	if _, err := os.Stat(crt); err == nil {
		go func() { log.Fatal(http.ListenAndServeTLS(":8443", crt, key, h)) }()
	}
	select {}
}
