package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
)

// openValidatedRegularFile centralizes the no-follow, same-file, size, and
// owner-only checks for all caller-selected persistent inputs.
func openValidatedRegularFile(path string, maxSize int64, requirePrivate bool) (*os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("file path is required")
	}
	before, err := os.Lstat(path) // #nosec G703 -- the local operator selects the path; identity and type are verified before use.
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || pathHasSymlinkOrReparseComponent(path) || (maxSize > 0 && (before.Size() < 0 || before.Size() > maxSize)) {
		return nil, errors.New("path must be a bounded regular file without symlink or reparse indirection")
	}
	if requirePrivate && runtime.GOOS == "windows" {
		if err := secureOwnerOnlyPath(path, false); err != nil {
			return nil, err
		}
		before, err = os.Lstat(path) // #nosec G703 -- re-read binds the post-ACL-convergence file identity.
		if err != nil {
			return nil, err
		}
	}
	if !before.Mode().IsRegular() || pathHasSymlinkOrReparseComponent(path) || (maxSize > 0 && (before.Size() < 0 || before.Size() > maxSize)) {
		return nil, errors.New("path must be a bounded regular file without symlink or reparse indirection")
	}
	if requirePrivate && runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file permissions must be owner-only")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- Lstat above rejects links; SameFile below closes the replacement race before any read.
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || (maxSize > 0 && (after.Size() < 0 || after.Size() > maxSize)) {
		_ = file.Close()
		return nil, errors.New("file identity changed during validation")
	}
	return file, nil
}
