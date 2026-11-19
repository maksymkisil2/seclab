package main

import (
	"net"
	"testing"
)

func TestProbeOpenAndClosed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	closed.Close()
	if rc := runProbe([]string{"-timeout", "1s", l.Addr().String(), addr}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if rc := runProbe([]string{"nonsense"}); rc != 2 {
		t.Fatalf("bad target accepted")
	}
}
