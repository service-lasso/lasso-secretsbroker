package main

import (
	"os"
	"path/filepath"
	"time"
)

const auditLockTimeout = 10 * time.Second

func withAuditFileLock(auditPath string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(auditPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := lockAuditFile(lockFile, auditLockTimeout); err != nil {
		return err
	}
	defer unlockAuditFile(lockFile)
	return fn()
}
