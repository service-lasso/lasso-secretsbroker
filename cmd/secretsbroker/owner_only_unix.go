//go:build !windows

package main

import (
	"errors"
	"os"
)

func secureOwnerOnlyPath(path string, directory bool) error {
	if pathHasSymlinkOrReparseComponent(path) {
		return errors.New("owner-only path contains symlink indirection")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return errors.New("owner-only path has an unsafe type")
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if err := os.Chmod(path, want); err != nil {
		return err
	}
	verified, err := os.Lstat(path)
	if err != nil || verified.Mode().Perm() != want {
		return errors.New("owner-only path permissions could not be verified")
	}
	return nil
}
