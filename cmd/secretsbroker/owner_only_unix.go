//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func secureOwnerOnlyPath(path string, directory bool) error {
	if pathHasSymlinkOrReparseComponent(path) {
		return errors.New("owner-only path contains symlink indirection")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(abs)
	info, err := root.Lstat(name)
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
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("owner-only path identity changed during open")
	}
	if err := file.Chmod(want); err != nil {
		return err
	}
	verified, err := file.Stat()
	if err != nil || verified.Mode().Perm() != want {
		return errors.New("owner-only path permissions could not be verified")
	}
	return nil
}
