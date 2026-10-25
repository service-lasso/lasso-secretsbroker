//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// A scanner, indexer, or another process can briefly hold the freshly written
// temporary file or the destination, which MoveFileEx reports as an access or
// sharing denial. Those denials are transient; a bounded retry preserves the
// single atomic replacement instead of failing the audit write.
func transientReplaceError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func replaceFileAtomically(source, target string) error {
	sourcePtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPtr, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePtr, targetPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
