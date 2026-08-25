//go:build !windows

package main

import (
	"errors"
	"testing"
)

func TestUnsupportedKeyWrapperProviderRemainsFailClosed(t *testing.T) {
	provider := platformKeyWrapperProvider()
	if _, err := provider.Protect([]byte("portable-key-placeholder")); !errors.Is(err, errUnsupportedOSWrapper) {
		t.Fatalf("protect error = %v", err)
	}
	if _, err := provider.Unprotect([]byte("protected-placeholder")); !errors.Is(err, errUnsupportedOSWrapper) {
		t.Fatalf("unprotect error = %v", err)
	}
	if err := provider.SecurePath("wrapper.json", false); !errors.Is(err, errUnsupportedOSWrapper) {
		t.Fatalf("secure path error = %v", err)
	}
	if err := provider.ValidatePath("wrapper.json", false); !errors.Is(err, errUnsupportedOSWrapper) {
		t.Fatalf("validate path error = %v", err)
	}
}
