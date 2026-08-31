//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func replaceFileAtomically(source, target string) error {
	return renamePrivateFile(source, target)
}

func renamePrivateFile(source, target string) error {
	absSource, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	parent := filepath.Dir(absSource)
	if parent != filepath.Dir(absTarget) || pathHasSymlinkOrReparseComponent(parent) {
		return errors.New("atomic replacement paths must share one real parent directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	sourceName := filepath.Base(absSource)
	targetName := filepath.Base(absTarget)
	sourceInfo, err := root.Lstat(sourceName)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("atomic replacement source must be a regular file")
	}
	if targetInfo, targetErr := root.Lstat(targetName); targetErr == nil {
		if !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("atomic replacement target must be a regular file")
		}
	} else if !errors.Is(targetErr, os.ErrNotExist) {
		return targetErr
	}
	return root.Rename(sourceName, targetName)
}
