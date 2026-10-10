package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A protection failure after replacement must not be mistaken for an unchanged
// destination. Recovery callers must retain the key/wrapper for published bytes.
type privateFilePublishedError struct{ err error }

func (e *privateFilePublishedError) Error() string { return e.err.Error() }
func (e *privateFilePublishedError) Unwrap() error { return e.err }

func privateFileWasPublished(err error) bool {
	var published *privateFilePublishedError
	return errors.As(err, &published)
}

func writePrivateFileAtomically(path string, content []byte) error {
	return writePrivateFileAtomicallyWithProtection(path, content, secureOwnerOnlyPath)
}

func writePrivateFileAtomicallyWithProtection(path string, content []byte, protect func(string, bool) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // #nosec G703 -- callers authorize the destination; all writes use private temporary files and atomic replacement.
		return err
	}
	if err := protect(filepath.Dir(path), true); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".secretsbroker-atomic-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err := protect(tempPath, false); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceFileAtomically(tempPath, path); err != nil {
		return err
	}
	if err := protect(path, false); err != nil {
		return &privateFilePublishedError{err: err}
	}
	return nil
}

func writePrivateFileExclusive(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // #nosec G703 -- caller authorizes the destination and publication is exclusive.
		return err
	}
	if err := secureOwnerOnlyPath(filepath.Dir(path), true); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".secretsbroker-publish-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err := secureOwnerOnlyPath(tempPath, false); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("target already exists: %w", errLifecycleConflict)
		}
		return err
	}
	return secureOwnerOnlyPath(path, false)
}
