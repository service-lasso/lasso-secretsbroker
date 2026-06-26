//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
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
		identity, err := authorizeUnixPeerConn(conn, l.allowedUID)
		if err != nil {
			_ = conn.Close()
			continue
		}
		return withTransportPeerIdentityConn(conn, identity), nil
	}
}

func authorizeUnixPeerConn(conn net.Conn, allowedUID int) (transportPeerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return transportPeerIdentity{}, fmt.Errorf("unix-socket transport connection is %T, want *net.UnixConn", conn)
	}
	uid, _, _, err := unixPeerCredentials(unixConn)
	if err != nil {
		return transportPeerIdentity{}, err
	}
	if !unixPeerUIDAuthorized(uid, allowedUID) {
		return transportPeerIdentity{}, fmt.Errorf("unix-socket transport rejected local peer uid %d", uid)
	}
	return transportPeerIdentity{Kind: "unix-uid", Subject: strconv.Itoa(uid)}, nil
}
