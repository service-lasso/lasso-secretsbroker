//go:build darwin || freebsd

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
	var cred *unix.Xucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return -1, -1, -1, err
	}
	if controlErr != nil {
		return -1, -1, -1, controlErr
	}
	gid = -1
	if cred.Ngroups > 0 {
		gid = int(cred.Groups[0])
	}
	return int(cred.Uid), gid, -1, nil
}
