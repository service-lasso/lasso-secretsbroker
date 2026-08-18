//go:build !windows

package main

import "os"

func atomicReplacePrivateFile(from, to string) error {
	return os.Rename(from, to)
}
