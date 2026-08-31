//go:build windows

package main

func pathHasSymlinkOrReparseComponent(path string) bool {
	return rejectWindowsReparseTraversal(path) != nil
}
