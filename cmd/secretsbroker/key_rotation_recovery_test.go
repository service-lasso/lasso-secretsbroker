package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateAtomicWriterReportsActualPublicationBoundary(t *testing.T) {
	for _, failureCall := range []int{1, 2, 3} {
		t.Run(string(rune('0'+failureCall)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := writePrivateFileAtomically(path, []byte("original")); err != nil {
				t.Fatal(err)
			}
			calls := 0
			injected := errors.New("synthetic protection failure")
			err := writePrivateFileAtomicallyWithProtection(path, []byte("replacement"), func(path string, directory bool) error {
				calls++
				if calls == failureCall {
					return injected
				}
				return secureOwnerOnlyPath(path, directory)
			})
			if !errors.Is(err, injected) || privateFileWasPublished(err) != (failureCall == 3) {
				t.Fatalf("incorrect publication classification: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			expected := "original"
			if failureCall == 3 {
				expected = "replacement"
			}
			if string(data) != expected {
				t.Fatalf("destination = %q, want %q", data, expected)
			}
		})
	}
}

func TestMasterKeyRotationMigratesAllSurvivingPayloadFamilies(t *testing.T) {
	b := testBackend(t)
	makePayload := func(value string) secretPayload {
		t.Helper()
		payload, err := b.encrypt(value)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	entry := secretEntry{Ref: "services/api/runtime/KEY", Payload: makePayload("current"), KV: &kvSecretState{Current: 2, Versions: []kvVersionRecord{
		{Version: 1, Payload: makePayload(`{"value":"historical"}`)},
		{Version: 2, Payload: makePayload(`{"value":"current"}`)},
		{Version: 3, Destroyed: true},
	}}}
	store, err := b.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	store.Secrets[entry.Ref] = entry
	store.Tombstones = map[string]localSecretTombstone{"removed": {Ref: "removed", Entry: secretEntry{Payload: makePayload("deleted"), KV: &kvSecretState{Versions: []kvVersionRecord{{Version: 1, Payload: makePayload("deleted-history")}}}}}}
	store.Rotations = map[string]rotationLedger{"orphaned-ledger": {
		Staged:   map[string]rotationStoredVersion{"staged": {Payload: makePayload("staged")}},
		Retained: map[string]rotationStoredVersion{"retained": {Payload: makePayload("retained")}},
	}}
	if err := b.saveStore(store); err != nil {
		t.Fatal(err)
	}
	if _, err := b.rotateMasterKey("new-master-key"); err != nil {
		t.Fatal(err)
	}
	rotated, err := b.loadStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.verifyStoreDecryptable(rotated); err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := visitStorePayloads(&rotated, func(payload secretPayload) (secretPayload, error) {
		count++
		if payload.KeyID != masterKeyID("new-master-key") {
			t.Fatal("old-key ciphertext survived")
		}
		return payload, nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 7 {
		t.Fatalf("visited %d payloads, want 7", count)
	}
	for version, expected := range map[int]string{1: "historical", 2: "current"} {
		_, fields, err := b.localKVVersion(rotated.Secrets[entry.Ref], version)
		if err != nil || fields["value"] != expected {
			t.Fatalf("version %d failed: %v %v", version, fields, err)
		}
	}
	if rotated.Secrets[entry.Ref].KV.Versions[2].Payload != (secretPayload{}) {
		t.Fatal("destroyed version resurrected")
	}
	for _, payload := range []secretPayload{rotated.Tombstones["removed"].Entry.Payload, rotated.Tombstones["removed"].Entry.KV.Versions[0].Payload, rotated.Rotations["orphaned-ledger"].Staged["staged"].Payload, rotated.Rotations["orphaned-ledger"].Retained["retained"].Payload} {
		value, err := b.decrypt(payload)
		if err != nil || value == "" {
			t.Fatalf("retained payload lost: %v", err)
		}
	}
}

func TestManagedRotationPreservesKeyAndWrapperAtPublicationBoundary(t *testing.T) {
	for _, published := range []bool{false, true} {
		name := "before-publication"
		if published {
			name = "after-publication"
		}
		t.Run(name, func(t *testing.T) {
			b := managementLifecycleBackend(t)
			oldKey := b.masterKey
			original, err := os.ReadFile(b.storePath)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("synthetic storage protection failure")
			_, err = b.rotateManagedMasterKeyWithStoreWriter(lifecycleOperationRequest{RequestID: "req-boundary", ServiceID: "@serviceadmin", OperationID: "op-boundary", Reason: "boundary regression", ExpectedKeyID: masterKeyID(oldKey), Confirm: true}, func(store localStoreFile) error {
				if b.masterKey != oldKey {
					t.Fatal("live key changed before publication")
				}
				if published {
					if err := b.saveStore(store); err != nil {
						t.Fatal(err)
					}
					return &privateFilePublishedError{err: injected}
				}
				return injected
			})
			if !errors.Is(err, errBackendDegraded) || !errors.Is(err, injected) || privateFileWasPublished(err) != published {
				t.Fatalf("lost original failure/publication state: %v", err)
			}
			pending := rotationPendingWrapperPath(b.wrapperPath)
			if published {
				if b.masterKey == oldKey {
					t.Fatal("published store retained stale live key")
				}
				if _, err := os.Stat(pending); err != nil {
					t.Fatal("published store lost recovery wrapper")
				}
				recovered, err := loadKeyMaterialForStoreWithProvider("", "", b.wrapperPath, b.storePath, b.lifecycleWrapperProvider(), b.lifecycleWrapperContext())
				if err != nil || recovered.Value != b.masterKey {
					t.Fatalf("published rotation could not recover: %v", err)
				}
			} else {
				if b.masterKey != oldKey {
					t.Fatal("unpublished rotation changed live key")
				}
				after, err := os.ReadFile(b.storePath)
				if err != nil || !bytes.Equal(original, after) {
					t.Fatal("unpublished rotation changed store")
				}
				if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unpublished pending wrapper remained: %v", err)
				}
			}
			store, err := b.loadStore()
			if err != nil || b.verifyStoreDecryptable(store) != nil {
				t.Fatalf("original store no longer decryptable: %v", err)
			}
		})
	}
}

func TestMasterKeyRotationRejectsCorruptRetainedPayloadBeforePublication(t *testing.T) {
	for _, family := range []string{"kv-history", "tombstone-history", "staged", "retained"} {
		t.Run(family, func(t *testing.T) {
			b := testBackend(t)
			oldKey := b.masterKey
			payload, err := b.encrypt("original")
			if err != nil {
				t.Fatal(err)
			}
			store, err := b.loadStore()
			if err != nil {
				t.Fatal(err)
			}
			entry := secretEntry{Ref: "services/api/KEY", Payload: payload, KV: &kvSecretState{Versions: []kvVersionRecord{{Version: 1, Payload: secretPayload{Alg: "invalid"}}}}}
			switch family {
			case "kv-history":
				store.Secrets[entry.Ref] = entry
			case "tombstone-history":
				store.Tombstones = map[string]localSecretTombstone{entry.Ref: {Entry: entry}}
			case "staged":
				store.Rotations = map[string]rotationLedger{"orphan": {Staged: map[string]rotationStoredVersion{"bad": {Payload: secretPayload{Alg: "invalid"}}}}}
			case "retained":
				store.Rotations = map[string]rotationLedger{"orphan": {Retained: map[string]rotationStoredVersion{"bad": {Payload: secretPayload{Alg: "invalid"}}}}}
			}
			if err := b.saveStore(store); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(b.storePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.verifyStoreDecryptable(store); err == nil {
				t.Fatal("verification ignored corrupt retained payload")
			}
			_, err = b.rotateMasterKeyAndSave("new-master-key", nil, func(localStoreFile) error { t.Fatal("corrupt payload reached publication"); return nil })
			if !errors.Is(err, errInvalidBackupKey) || b.masterKey != oldKey {
				t.Fatalf("corrupt payload changed live key: %v", err)
			}
			after, err := os.ReadFile(b.storePath)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("corrupt payload changed store")
			}
		})
	}
}
