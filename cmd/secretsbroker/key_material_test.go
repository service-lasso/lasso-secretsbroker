package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyStatusLockedAndReady(t *testing.T) {
	locked := keyStatus(keyMaterial{})
	if locked.Available || locked.State != "locked" || locked.KeyID != "" {
		t.Fatalf("locked status = %#v", locked)
	}

	ready := keyStatus(keyMaterial{Value: "portable-key", Source: "env"})
	if !ready.Available || ready.State != "ready" || ready.KeyVersion != masterKeyVersion || ready.KeyID == "" {
		t.Fatalf("ready status = %#v", ready)
	}
}

func TestLoadKeyMaterialFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master-key.txt")
	if err := os.WriteFile(path, []byte("file-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	material, err := loadKeyMaterial("", path)
	if err != nil {
		t.Fatal(err)
	}
	if material.Value != "file-key" || material.Source != "file" {
		t.Fatalf("material = %#v", material)
	}
}

func TestGeneratePortableMasterKey(t *testing.T) {
	key, err := generatePortableMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == "" {
		t.Fatalf("empty key")
	}
	if masterKeyID(key) == "" {
		t.Fatalf("empty key id")
	}
}
