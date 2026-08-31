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
	if err := secureOwnerOnlyPath(filepath.Dir(auditPath), true); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(auditPath+".lock", os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- lock path is deterministically derived from immutable startup auditPath.
	if err != nil {
		return err
	}
	if err := secureOwnerOnlyPath(auditPath+".lock", false); err != nil {
		_ = lockFile.Close()
		return err
	}
	defer lockFile.Close()
	if err := lockAuditFile(lockFile, auditLockTimeout); err != nil {
		return err
	}
	defer unlockAuditFile(lockFile)
	return fn()
}
