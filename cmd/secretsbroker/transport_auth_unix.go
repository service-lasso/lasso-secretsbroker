//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
)

type unixPeerCredentialListener struct {
	net.Listener
	allowedUID int
}

func authenticatedUnixSocketListener(ln net.Listener) (net.Listener, error) {
	if _, ok := ln.(*net.UnixListener); !ok {
		return nil, fmt.Errorf("unix-socket transport listener is %T, want *net.UnixListener", ln)
	}
	if !unixPeerCredentialChecksAvailable() {
		return nil, errUnixSocketRequiresPeerCredentials()
	}
	return &unixPeerCredentialListener{Listener: ln, allowedUID: os.Getuid()}, nil
}

func (l *unixPeerCredentialListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := authorizeUnixPeerConn(conn, l.allowedUID); err != nil {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func authorizeUnixPeerConn(conn net.Conn, allowedUID int) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unix-socket transport connection is %T, want *net.UnixConn", conn)
	}
	uid, _, _, err := unixPeerCredentials(unixConn)
	if err != nil {
		return err
	}
	if !unixPeerUIDAuthorized(uid, allowedUID) {
		return fmt.Errorf("unix-socket transport rejected local peer uid %d", uid)
	}
	return nil
}
