// Offline multi-call stand-in for the real lab images when no registry is reachable.
// Dispatch on argv[0]; each applet implements only the CLI subset seclab uses:
//
//	nginx  -> HTTP :8080, HTTPS :8443 if /etc/nginx/tls/server.crt exists (nginx args ignored)
//	nc     -> nc -z [-w sec] host port               (reachability probe)
//	ip     -> ip route add|replace default|CIDR via GW (netlink)
//	socat  -> socat TCP-LISTEN:PORT[,opts] ANY       (accepts, writes banner, closes)
//	tail   -> tail -f /dev/null                      (idle forever)
//
// nft is copied from the host into the image. nginx/sshd semantics are NOT emulated.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	switch filepath.Base(os.Args[0]) {
	case "nc":
		os.Exit(nc(os.Args[1:]))
	case "ip":
		os.Exit(ipRoute(os.Args[1:]))
	case "socat":
		os.Exit(socat(os.Args[1:]))
	case "tail":
		for {
			time.Sleep(time.Hour)
		}
	default:
		serve()
	}
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
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("seclab stub\n")) })
	go func() { log.Fatal(http.ListenAndServe(":8080", h)) }()
	crt, key := "/etc/nginx/tls/server.crt", "/etc/nginx/tls/server.key"
	if _, err := os.Stat(crt); err == nil {
		go func() { log.Fatal(http.ListenAndServeTLS(":8443", crt, key, h)) }()
	}
	select {}
}

func socat(args []string) int {
	if len(args) < 1 || !strings.HasPrefix(args[0], "TCP-LISTEN:") {
		fmt.Fprintln(os.Stderr, "usage: socat TCP-LISTEN:PORT[,opts] ADDR")
		return 2
	}
	port := strings.SplitN(strings.TrimPrefix(args[0], "TCP-LISTEN:"), ",", 2)[0]
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		c.Write([]byte("seclab\n"))
		c.Close()
	}
}

func rta(t uint16, v []byte) []byte {
	l := 4 + len(v)
	b := make([]byte, (l+3)&^3)
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], t)
	copy(b[4:], v)
	return b
}

func ipRoute(args []string) int {
	if len(args) != 5 || args[0] != "route" || (args[1] != "add" && args[1] != "replace") || args[3] != "via" {
		fmt.Fprintln(os.Stderr, "usage: ip route add|replace default|CIDR via GW")
		return 2
	}
	var dst net.IP
	plen := 0
	if args[2] != "default" {
		_, n, err := net.ParseCIDR(args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		dst = n.IP.To4()
		plen, _ = n.Mask.Size()
	}
	gw := net.ParseIP(args[4]).To4()
	if gw == nil {
		fmt.Fprintln(os.Stderr, "bad gateway")
		return 2
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE)
	if args[1] == "replace" {
		flags |= syscall.NLM_F_REPLACE
	} else {
		flags |= syscall.NLM_F_EXCL
	}
	body := []byte{syscall.AF_INET, byte(plen), 0, 0, syscall.RT_TABLE_MAIN, syscall.RTPROT_BOOT,
		syscall.RT_SCOPE_UNIVERSE, syscall.RTN_UNICAST, 0, 0, 0, 0}
	if plen > 0 {
		body = append(body, rta(syscall.RTA_DST, dst)...)
	}
	body = append(body, rta(syscall.RTA_GATEWAY, gw)...)
	msg := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint16(msg[4:], syscall.RTM_NEWROUTE)
	binary.LittleEndian.PutUint16(msg[6:], flags)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			if e := int32(binary.LittleEndian.Uint32(m.Data[0:4])); e != 0 {
				fmt.Fprintln(os.Stderr, "RTNETLINK:", syscall.Errno(-e))
				return 1
			}
		}
	}
	return 0
}
