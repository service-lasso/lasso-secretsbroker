//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func lockAuditFile(file *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		if time.Now().After(deadline) {
			return errAuditLockTimeout
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func unlockAuditFile(file *os.File) {
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
