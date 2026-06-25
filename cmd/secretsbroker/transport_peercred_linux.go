//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

func unixPeerCredentialChecksAvailable() bool {
	return true
}

func unixPeerCredentials(conn *net.UnixConn) (uid int, gid int, pid int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, -1, -1, err
	}
	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, -1, -1, err
	}
	if controlErr != nil {
		return -1, -1, -1, controlErr
	}
	return int(cred.Uid), int(cred.Gid), int(cred.Pid), nil
}
