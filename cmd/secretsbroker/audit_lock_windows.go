//go:build windows

package main

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func lockAuditFile(file *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	overlapped := &windows.Overlapped{}
	for {
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		if time.Now().After(deadline) {
			return errAuditLockTimeout
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func unlockAuditFile(file *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}
