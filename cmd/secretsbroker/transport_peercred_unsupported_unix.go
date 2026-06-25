//go:build !windows && !linux && !darwin && !freebsd

package main

import (
	"fmt"
	"net"
)

func unixPeerCredentialChecksAvailable() bool {
	return false
}

func unixPeerCredentials(conn *net.UnixConn) (uid int, gid int, pid int, err error) {
	return -1, -1, -1, fmt.Errorf("unix peer credential checks are not implemented for this platform")
}
