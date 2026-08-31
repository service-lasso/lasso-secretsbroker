//go:build !windows

package main

func atomicReplacePrivateFile(from, to string) error {
	return renamePrivateFile(from, to)
}
