package main

import (
	"errors"
	"sort"
	"strings"
	"time"
)

var errMigrationPlanConflict = errors.New("migration operation plan conflict")

// providerMigrationExecutor is an explicit, in-process seam. Registering an
// executor is the only way a remote migration target becomes executable; the
// provider family capability remains planned when no executor is registered.
// Implementations return typed outcomes only and must not return provider
// response bodies or credential material.
type providerMigrationExecutor interface {
	Write(providerMigrationWriteRequest) providerMigrationExecutorResult
	Verify(providerMigrationVerifyRequest) providerMigrationExecutorResult
}

type providerMigrationWriteRequest struct {
	OperationID      string
	IdempotencyKey   string
	TargetProviderID string
	Ref              string
	Value            string
}

type providerMigrationVerifyRequest struct {
	OperationID      string
	IdempotencyKey   string
	TargetProviderID string
	Ref              string
	ExpectedValue    string
}

type providerMigrationExecutorResult struct {
	Outcome string
}

type providerMigrationOperation struct {
	OperationID      string                                    `json:"operationId"`
	PlanFingerprint  string                                    `json:"planFingerprint"`
	SourceProviderID string                                    `json:"sourceProviderId"`
	TargetProviderID string                                    `json:"targetProviderId"`
	Outcome          string                                    `json:"outcome"`
	Items            map[string]providerMigrationOperationItem `json:"items"`
	CreatedAt        time.Time                                 `json:"createdAt"`
	UpdatedAt        time.Time                                 `json:"updatedAt"`
}

type providerMigrationOperationItem struct {
	Ref                  string    `json:"ref"`
	State                string    `json:"state"`
	Outcome              string    `json:"outcome"`
	WriteApplied         bool      `json:"writeApplied"`
	Verified             bool      `json:"verified"`
	Attempts             int       `json:"attempts"`
	VerificationAttempts int       `json:"verificationAttempts"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

func (b *localBackend) registerProviderMigrationExecutor(providerID string, executor providerMigrationExecutor) {
	providerID = strings.TrimSpace(providerID)
	if b == nil || providerID == "" || executor == nil {
		return
	}
	b.providerExecutorMu.Lock()
	defer b.providerExecutorMu.Unlock()
	if b.providerExecutors == nil {
		b.providerExecutors = map[string]providerMigrationExecutor{}
	}
	b.providerExecutors[providerID] = executor
}

func (b *localBackend) providerMigrationExecutor(providerID string) (providerMigrationExecutor, bool) {
	if b == nil {
		return nil, false
	}
	b.providerExecutorMu.RLock()
	defer b.providerExecutorMu.RUnlock()
	executor, ok := b.providerExecutors[strings.TrimSpace(providerID)]
	return executor, ok && executor != nil
}

func (b *localBackend) connectionProviderOperations(providerID string, lifecycle SourceLifecycle, auditStatus string, operations []OperationCapability) []OperationCapability {
	if _, ok := b.providerMigrationExecutor(providerID); !ok || lifecycle.Outcome != "ready" || auditStatus != "audit_available" {
		return operations
	}
	for index := range operations {
		if operations[index].Path != "/v1/providers/migration/apply" {
			continue
		}
		operations[index].Maturity = OperationMaturityValidated
		operations[index].ReasonCode, operations[index].NextAction = maturityCodes(OperationMaturityValidated)
		operations[index].LimitationCode = ""
	}
	return operations
}

func (b *localBackend) providerMigrationPlanConflicts(req migrationPlanRequest) (bool, error) {
	store, err := b.loadStore()
	if err != nil {
		return false, err
	}
	operation, exists := store.Migrations[strings.TrimSpace(req.OperationID)]
	return exists && operation.PlanFingerprint != providerMigrationPlanFingerprint(req), nil
}

func (b *localBackend) executeProviderMigration(req migrationPlanRequest, target providerConfigStatus, executor providerMigrationExecutor, res migrationPlanResponse) (migrationPlanResponse, error) {
	b.providerMigrationMu.Lock()
	defer b.providerMigrationMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	refs := safeList(req.Refs)
	sort.Strings(refs)
	req.Refs = refs
	res.Results = b.migrationItems(req, target, false, "")
	fingerprint := providerMigrationPlanFingerprint(req)
	operationID := strings.TrimSpace(req.OperationID)
	now := b.now()

	store, err := b.loadStore()
	if err != nil {
		return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
	}
	operation, exists := store.Migrations[operationID]
	if exists && operation.PlanFingerprint != fingerprint {
		res.Outcome = "conflict"
		res.NextAction = "create_new_operation_id_for_changed_plan"
		res.Applied = false
		for index := range res.Results {
			res.Results[index].State = "failed"
			res.Results[index].Outcome = "conflict"
			res.Results[index].PolicyResult = "denied"
		}
		return res, errMigrationPlanConflict
	}
	if !exists {
		operation = providerMigrationOperation{
			OperationID:      operationID,
			PlanFingerprint:  fingerprint,
			SourceProviderID: firstNonEmpty(req.SourceProviderID, "local"),
			TargetProviderID: strings.TrimSpace(req.TargetProviderID),
			Outcome:          "in_progress",
			Items:            map[string]providerMigrationOperationItem{},
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		store.Migrations[operationID] = operation
		store.UpdatedAt = now
		if err := b.saveStore(store); err != nil {
			return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
		}
	}
	if operation.Items == nil {
		operation.Items = map[string]providerMigrationOperationItem{}
	}

	for index := range res.Results {
		status := &res.Results[index]
		if status.Outcome != "dry_run_ready" {
			continue
		}
		persisted := operation.Items[status.Ref]
		if persisted.Verified {
			applyPersistedMigrationStatus(status, persisted)
			continue
		}
		value, sourceOutcome := b.localMigrationSourceValue(store, operation.SourceProviderID, status.Ref)
		if sourceOutcome != "ready" {
			persisted = failedMigrationOperationItem(persisted, status.Ref, sourceOutcome, now)
			operation.Items[status.Ref] = persisted
			applyPersistedMigrationStatus(status, persisted)
			if err := b.persistProviderMigrationOperation(&store, &operation); err != nil {
				return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
			}
			continue
		}

		idempotencyKey := providerMigrationItemIdempotencyKey(operationID, operation.TargetProviderID, status.Ref)
		if !persisted.WriteApplied {
			writeResult := executor.Write(providerMigrationWriteRequest{OperationID: operationID, IdempotencyKey: idempotencyKey, TargetProviderID: operation.TargetProviderID, Ref: status.Ref, Value: value})
			persisted.Ref = status.Ref
			persisted.Attempts++
			persisted.UpdatedAt = b.now()
			if normalizeProviderExecutorWriteOutcome(writeResult.Outcome) != "applied" {
				persisted.State = "failed"
				persisted.Outcome = normalizeProviderExecutorWriteOutcome(writeResult.Outcome)
				operation.Items[status.Ref] = persisted
				applyPersistedMigrationStatus(status, persisted)
				if err := b.persistProviderMigrationOperation(&store, &operation); err != nil {
					return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
				}
				continue
			}
			persisted.WriteApplied = true
			persisted.State = "verifying"
			persisted.Outcome = "verification_pending"
			operation.Items[status.Ref] = persisted
			if err := b.persistProviderMigrationOperation(&store, &operation); err != nil {
				return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
			}
		}

		verifyResult := executor.Verify(providerMigrationVerifyRequest{OperationID: operationID, IdempotencyKey: idempotencyKey, TargetProviderID: operation.TargetProviderID, Ref: status.Ref, ExpectedValue: value})
		persisted.VerificationAttempts++
		persisted.UpdatedAt = b.now()
		verifyOutcome := normalizeProviderExecutorVerifyOutcome(verifyResult.Outcome)
		if verifyOutcome == "verified" {
			persisted.Verified = true
			persisted.State = "migrated"
			persisted.Outcome = "migrated"
		} else {
			persisted.State = "failed"
			persisted.Outcome = verifyOutcome
		}
		operation.Items[status.Ref] = persisted
		applyPersistedMigrationStatus(status, persisted)
		if err := b.persistProviderMigrationOperation(&store, &operation); err != nil {
			return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
		}
	}

	res.Outcome = providerMigrationApplyOutcome(res.Results)
	res.Applied = res.Outcome == "applied"
	res.RequiresConfirmation = false
	if !res.Applied {
		res.NextAction = "retry_failed_refs_after_fix"
	}
	if operation.Outcome != res.Outcome {
		operation.Outcome = res.Outcome
		if err := b.persistProviderMigrationOperation(&store, &operation); err != nil {
			return migrationExecutionFailure(res, "degraded", "retry_or_inspect_source"), errBackendDegraded
		}
	}
	return res, nil
}

func (b *localBackend) persistProviderMigrationOperation(store *localStoreFile, operation *providerMigrationOperation) error {
	current, err := b.loadStore()
	if err != nil {
		return err
	}
	operation.UpdatedAt = b.now()
	if current.Migrations == nil {
		current.Migrations = map[string]providerMigrationOperation{}
	}
	current.Migrations[operation.OperationID] = *operation
	current.UpdatedAt = operation.UpdatedAt
	*store = current
	return b.saveStore(current)
}

func (b *localBackend) localMigrationSourceValue(store localStoreFile, sourceProviderID, ref string) (string, string) {
	sourceProviderID = firstNonEmpty(strings.TrimSpace(sourceProviderID), "local")
	if sourceProviderID != "local" && sourceProviderID != "local-encrypted-store" {
		return "", "unsupported"
	}
	entry, ok := store.Secrets[ref]
	if !ok {
		return "", "missing_ref"
	}
	value, err := b.decrypt(entry.Payload)
	if err != nil {
		return "", "degraded"
	}
	return value, "ready"
}

func providerMigrationPlanFingerprint(req migrationPlanRequest) string {
	refs := safeList(req.Refs)
	sort.Strings(refs)
	return hashAuditRef(strings.Join([]string{firstNonEmpty(req.SourceProviderID, "local"), strings.TrimSpace(req.TargetProviderID), strings.Join(refs, "\n")}, "\n"))
}

func providerMigrationItemIdempotencyKey(operationID, targetProviderID, ref string) string {
	return hashAuditRef(strings.Join([]string{strings.TrimSpace(operationID), strings.TrimSpace(targetProviderID), strings.TrimSpace(ref)}, "\n"))
}

func failedMigrationOperationItem(item providerMigrationOperationItem, ref, outcome string, now time.Time) providerMigrationOperationItem {
	item.Ref = ref
	item.State = "failed"
	item.Outcome = outcome
	item.UpdatedAt = now
	return item
}

func applyPersistedMigrationStatus(status *migrationItemStatus, item providerMigrationOperationItem) {
	status.State = item.State
	status.Outcome = item.Outcome
	status.Verified = item.Verified
	status.Attempts = item.Attempts
	if item.Verified {
		status.ExpectedAction = "none"
		status.Recovery = "source_retained_after_target_verification"
	} else {
		status.ExpectedAction = providerMigrationRetryAction(item.Outcome)
	}
}

func providerMigrationRetryAction(outcome string) string {
	switch outcome {
	case "source_auth_required":
		return "refresh_provider_auth_and_retry"
	case "rate_limited":
		return "retry_after_provider_backoff"
	case "verification_failed", "verification_pending":
		return "retry_target_verification"
	case "conflict":
		return "refresh_target_version_and_retry"
	case "invalid_ref":
		return "fix_target_mapping"
	case "source_unavailable", "degraded":
		return "restore_provider_availability_and_retry"
	case "unsupported":
		return "implement_provider_operation_executor"
	default:
		return "review_failed_ref_and_retry"
	}
}

func normalizeProviderExecutorWriteOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "applied":
		return "applied"
	case "source_auth_required", "rate_limited", "source_unavailable", "policy_denied", "conflict", "invalid_ref", "degraded":
		return strings.TrimSpace(outcome)
	default:
		return "degraded"
	}
}

func normalizeProviderExecutorVerifyOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "verified":
		return "verified"
	case "source_auth_required", "rate_limited", "source_unavailable", "policy_denied", "degraded", "verification_failed":
		return strings.TrimSpace(outcome)
	default:
		return "verification_failed"
	}
}

func providerMigrationApplyOutcome(items []migrationItemStatus) string {
	if len(items) == 0 {
		return "applied"
	}
	for _, item := range items {
		if item.Outcome != "migrated" || !item.Verified {
			return "partial_failure"
		}
	}
	return "applied"
}

func migrationExecutionFailure(res migrationPlanResponse, outcome, nextAction string) migrationPlanResponse {
	res.Outcome = outcome
	res.Applied = false
	res.NextAction = nextAction
	return res
}
