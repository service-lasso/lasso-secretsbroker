package main

import (
	"strings"
	"time"
)

// localStoreMigrationExecutor copies values inside the Broker process. Write and
// Verify use the encrypted local store only and never return secret material.
type localStoreMigrationExecutor struct {
	backend *localBackend
}

func (b *localBackend) registerLocalStoreMigrationExecutor() {
	if b == nil {
		return
	}
	executor := &localStoreMigrationExecutor{backend: b}
	b.registerProviderMigrationExecutor("local", executor)
	b.registerProviderMigrationExecutor("local-encrypted-store", executor)
}

func (e *localStoreMigrationExecutor) Write(req providerMigrationWriteRequest) providerMigrationExecutorResult {
	if e == nil || e.backend == nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	if e.backend.locked() {
		return providerMigrationExecutorResult{Outcome: "locked"}
	}
	ref := strings.TrimSpace(req.Ref)
	if !validSecretRef(ref) || req.Value == "" {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	store, err := e.backend.loadStore()
	if err != nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	now := e.backend.now()
	if store.KeyID == "" {
		store.KeyID = masterKeyID(e.backend.masterKey)
	}
	if store.KeyVersion == "" {
		store.KeyVersion = masterKeyVersion
	}
	payload, err := e.backend.encrypt(req.Value)
	if err != nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	metadata := SecretMetadata{
		SourceID:  localStoreSource,
		Version:   now.Format(time.RFC3339Nano),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if existing, ok := store.Secrets[ref]; ok {
		metadata.CreatedAt = existing.Metadata.CreatedAt
	}
	store.Secrets[ref] = secretEntry{Ref: ref, Metadata: metadata, Payload: payload}
	store.UpdatedAt = now
	if err := e.backend.saveStore(store); err != nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	return providerMigrationExecutorResult{Outcome: "applied"}
}

func (e *localStoreMigrationExecutor) Verify(req providerMigrationVerifyRequest) providerMigrationExecutorResult {
	if e == nil || e.backend == nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	store, err := e.backend.loadStore()
	if err != nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	entry, ok := store.Secrets[strings.TrimSpace(req.Ref)]
	if !ok {
		return providerMigrationExecutorResult{Outcome: "verification_failed"}
	}
	value, err := e.backend.decrypt(entry.Payload)
	if err != nil {
		return providerMigrationExecutorResult{Outcome: "degraded"}
	}
	if value != req.ExpectedValue {
		return providerMigrationExecutorResult{Outcome: "verification_failed"}
	}
	return providerMigrationExecutorResult{Outcome: "verified"}
}
