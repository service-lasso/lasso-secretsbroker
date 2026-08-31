//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
)

func pathHasSymlinkOrReparseComponent(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	root, err := os.OpenRoot(string(os.PathSeparator))
	if err != nil {
		return true
	}
	defer root.Close()
	current := ""
	for _, part := range strings.FieldsFunc(abs, func(r rune) bool { return r == '/' }) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}
