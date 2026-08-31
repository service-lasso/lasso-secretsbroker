//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func canonicalUnixSecurityPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "darwin" {
		for alias, target := range map[string]string{
			"/tmp": "/private/tmp",
			"/var": "/private/var",
		} {
			if abs != alias && !strings.HasPrefix(abs, alias+string(os.PathSeparator)) {
				continue
			}
			resolved, resolveErr := filepath.EvalSymlinks(alias)
			if resolveErr != nil || filepath.Clean(resolved) != target {
				return "", os.ErrPermission
			}
			abs = filepath.Join(target, strings.TrimPrefix(abs, alias))
			break
		}
	}
	return abs, nil
}

func pathHasSymlinkOrReparseComponent(path string) bool {
	abs, err := canonicalUnixSecurityPath(path)
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
