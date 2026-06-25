//go:build !windows

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixSocketListenerAcceptsSameUIDPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secretsbroker.sock")
	ln, cleanup, err := listenForTransport(serveTransportBinding{Kind: "unix-socket", Address: path})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", got)
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		_ = conn.Close()
		accepted <- nil
	}()

	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for same-UID unix socket peer")
	}
}
