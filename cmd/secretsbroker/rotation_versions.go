package main

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const defaultRotationRetentionLimit = 1

var errRotationAuditUnavailable = errors.New("rotation audit unavailable")

type rotationLedger struct {
	ActiveVersionID         string                           `json:"activeVersionId,omitempty"`
	PreviousVersionID       string                           `json:"previousVersionId,omitempty"`
	LastRollbackOperationID string                           `json:"lastRollbackOperationId,omitempty"`
	LastRollbackVersionID   string                           `json:"lastRollbackVersionId,omitempty"`
	Staged                  map[string]rotationStoredVersion `json:"staged,omitempty"`
	Retained                map[string]rotationStoredVersion `json:"retained,omitempty"`
	UpdatedAt               time.Time                        `json:"updatedAt,omitempty"`
}

type rotationStoredVersion struct {
	VersionID   string         `json:"versionId"`
	OperationID string         `json:"operationId,omitempty"`
	RequestID   string         `json:"requestId,omitempty"`
	Metadata    SecretMetadata `json:"metadata"`
	Payload     secretPayload  `json:"payload"`
	StagedAt    time.Time      `json:"stagedAt,omitempty"`
	ActivatedAt time.Time      `json:"activatedAt,omitempty"`
	RetainedAt  time.Time      `json:"retainedAt,omitempty"`
}

type rotationVersionRequest struct {
	RequestID              string `json:"requestId,omitempty"`
	ServiceID              string `json:"serviceId,omitempty"`
	Ref                    string `json:"ref"`
	OperationID            string `json:"operationId,omitempty"`
	VersionID              string `json:"versionId,omitempty"`
	ExpectedCurrentVersion string `json:"expectedCurrentVersion,omitempty"`
	Reason                 string `json:"reason,omitempty"`
	Confirm                bool   `json:"confirm,omitempty"`
	Value                  string `json:"value,omitempty"`
	RetentionLimit         int    `json:"retentionLimit,omitempty"`
}

type rotationVersionResponse struct {
	ServiceID              string                    `json:"serviceId"`
	APIVersion             string                    `json:"apiVersion"`
	RequestID              string                    `json:"requestId,omitempty"`
	Ref                    string                    `json:"ref"`
	Operation              string                    `json:"operation"`
	Mode                   string                    `json:"mode"`
	Outcome                string                    `json:"outcome"`
	Applied                bool                      `json:"applied"`
	RequiresConfirmation   bool                      `json:"requiresConfirmation"`
	AuditStatus            string                    `json:"auditStatus"`
	PolicyResult           string                    `json:"policyResult"`
	NextAction             string                    `json:"nextAction,omitempty"`
	ActiveVersionID        string                    `json:"activeVersionId,omitempty"`
	PreviousVersionID      string                    `json:"previousVersionId,omitempty"`
	ExpectedCurrentVersion string                    `json:"expectedCurrentVersion,omitempty"`
	CurrentVersion         *rotationVersionMetadata  `json:"currentVersion,omitempty"`
	StagedVersion          *rotationVersionMetadata  `json:"stagedVersion,omitempty"`
	PreviousVersion        *rotationVersionMetadata  `json:"previousVersion,omitempty"`
	Versions               []rotationVersionMetadata `json:"versions"`
	AffectedRefs           []string                  `json:"affectedRefs"`
	AffectedServices       []string                  `json:"affectedServices"`
}

type rotationVersionMetadata struct {
	VersionID    string    `json:"versionId"`
	SourceID     string    `json:"sourceId"`
	State        string    `json:"state"`
	Fingerprint  string    `json:"fingerprint"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	StagedAt     time.Time `json:"stagedAt,omitempty"`
	ActivatedAt  time.Time `json:"activatedAt,omitempty"`
	RetainedAt   time.Time `json:"retainedAt,omitempty"`
	OperationID  string    `json:"operationId,omitempty"`
	AuditStatus  string    `json:"auditStatus"`
	PolicyResult string    `json:"policyResult"`
}

func (b *localBackend) rotationStatus(req rotationVersionRequest) (rotationVersionResponse, error) {
	ref := strings.TrimSpace(req.Ref)
	res := baseRotationVersionResponse(req, "rotation_status", "status")
	if !validSecretRef(ref) {
		res.Outcome = "invalid_ref"
		res.NextAction = "fix_ref"
		_ = b.audit("rotation_status", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errInvalidRef
	}
	if b.locked() {
		res.Outcome = "locked"
		res.NextAction = "unlock_broker"
		_ = b.audit("rotation_status", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		res.Outcome = "degraded"
		res.NextAction = "retry_or_inspect_source"
		_ = b.audit("rotation_status", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	entry, ok := store.Secrets[ref]
	if !ok {
		res.Outcome = "missing_ref"
		res.NextAction = "check_ref"
		_ = b.audit("rotation_status", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errMissingRef
	}
	ledger := normalizedRotationLedger(store.Rotations[ref])
	res = enrichRotationResponse(res, ref, entry, ledger)
	res.Outcome = "ready"
	res.AuditStatus = "audit_available"
	_ = b.audit("rotation_status", ref, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) stageRotationVersion(req rotationVersionRequest) (rotationVersionResponse, error) {
	b.rotationMu.Lock()
	defer b.rotationMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	ref := strings.TrimSpace(req.Ref)
	res := baseRotationVersionResponse(req, "rotation_stage", "stage")
	res.RequiresConfirmation = true
	if !req.Confirm {
		res.Outcome = "policy_denied"
		res.NextAction = "confirm_with_audit_reason_and_candidate_value"
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errPolicyDenied
	}
	if err := validateRotationSecretBearingRequest(req, true); err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	store, current, ledger, err := b.loadRotationTarget(ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	if expected := strings.TrimSpace(req.ExpectedCurrentVersion); expected != "" && current.Metadata.Version != expected {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "conflict"
		res.ExpectedCurrentVersion = expected
		res.NextAction = "refresh_current_version_and_retry"
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errRotationConflict
	}

	now := b.now()
	versionID := rotationVersionID(req)
	if staged, ok := ledger.Staged[versionID]; ok {
		res = enrichRotationResponse(res, ref, current, ledger)
		metadata := rotationMetadataFromStored(staged, "staged")
		res.StagedVersion = &metadata
		res.Outcome = "staged"
		res.AuditStatus = "audit_recorded"
		res.NextAction = "activate_with_expected_current_version_after_consumer_preflight"
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, nil
	}
	if err := b.requireRotationMutationAudit("rotation_stage", req); err != nil {
		return rotationAuditUnavailableResponse(res, ref, current, ledger), err
	}
	payload, err := b.encrypt(req.Value)
	if err != nil {
		res.Outcome = "degraded"
		res.NextAction = "retry_or_inspect_source"
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	staged := rotationStoredVersion{
		VersionID:   versionID,
		OperationID: rotationOperationToken(req),
		RequestID:   strings.TrimSpace(req.RequestID),
		Metadata: SecretMetadata{
			SourceID:  "rotation:staged:" + firstNonEmpty(req.ServiceID, ownerFromRef(ref)),
			Version:   versionID,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Payload:  payload,
		StagedAt: now,
	}
	ledger.ActiveVersionID = firstNonEmpty(ledger.ActiveVersionID, current.Metadata.Version)
	ledger.Staged[versionID] = staged
	ledger.UpdatedAt = now
	store.Rotations[ref] = ledger
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		res.Outcome = "degraded"
		res.NextAction = "retry_or_inspect_source"
		_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	res = enrichRotationResponse(res, ref, current, ledger)
	metadata := rotationMetadataFromStored(staged, "staged")
	res.StagedVersion = &metadata
	res.Outcome = "staged"
	res.AuditStatus = "audit_recorded"
	res.NextAction = "activate_with_expected_current_version_after_consumer_preflight"
	_ = b.audit("rotation_stage", ref, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) activateRotationVersion(req rotationVersionRequest) (rotationVersionResponse, error) {
	b.rotationMu.Lock()
	defer b.rotationMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	ref := strings.TrimSpace(req.Ref)
	res := baseRotationVersionResponse(req, "rotation_activate", "activate")
	if err := validateRotationConfirmation(req, true); err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = "confirm_with_audit_reason_expected_current_version_and_staged_version"
		_ = b.audit("rotation_activate", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	store, current, ledger, err := b.loadRotationTarget(ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		_ = b.audit("rotation_activate", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	if strings.TrimSpace(req.ExpectedCurrentVersion) == "" || current.Metadata.Version != strings.TrimSpace(req.ExpectedCurrentVersion) {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "conflict"
		res.ExpectedCurrentVersion = strings.TrimSpace(req.ExpectedCurrentVersion)
		res.NextAction = "refresh_current_version_and_retry"
		_ = b.audit("rotation_activate", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errRotationConflict
	}
	versionID := strings.TrimSpace(req.VersionID)
	if versionID == "" {
		versionID = rotationVersionID(req)
	}
	staged, ok := ledger.Staged[versionID]
	if !ok {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "missing_ref"
		res.NextAction = "stage_candidate_version_first"
		_ = b.audit("rotation_activate", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errMissingRef
	}
	if err := b.requireRotationMutationAudit("rotation_activate", req); err != nil {
		return rotationAuditUnavailableResponse(res, ref, current, ledger), err
	}

	now := b.now()
	previous := rotationStoredVersion{
		VersionID:   current.Metadata.Version,
		OperationID: ledger.ActiveVersionID,
		RequestID:   strings.TrimSpace(req.RequestID),
		Metadata:    current.Metadata,
		Payload:     current.Payload,
		RetainedAt:  now,
	}
	staged.Metadata.SourceID = firstNonEmpty(staged.Metadata.SourceID, "rotation:active:"+firstNonEmpty(req.ServiceID, ownerFromRef(ref)))
	staged.Metadata.UpdatedAt = now
	staged.ActivatedAt = now
	store.Secrets[ref] = secretEntry{Ref: ref, Metadata: staged.Metadata, Payload: staged.Payload}
	ledger.Retained[previous.VersionID] = previous
	delete(ledger.Staged, versionID)
	ledger.PreviousVersionID = previous.VersionID
	ledger.ActiveVersionID = staged.VersionID
	ledger.UpdatedAt = now
	store.Rotations[ref] = ledger
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		res.Outcome = "degraded"
		res.NextAction = "retry_or_inspect_source"
		_ = b.audit("rotation_activate", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	res = enrichRotationResponse(res, ref, store.Secrets[ref], ledger)
	res.Outcome = "applied"
	res.Applied = true
	res.AuditStatus = "audit_recorded"
	res.NextAction = "record_consumer_convergence_or_rollback"
	_ = b.audit("rotation_activate", ref, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) rollbackRotationVersion(req rotationVersionRequest) (rotationVersionResponse, error) {
	b.rotationMu.Lock()
	defer b.rotationMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	ref := strings.TrimSpace(req.Ref)
	res := baseRotationVersionResponse(req, "rotation_rollback", "rollback")
	if err := validateRotationConfirmation(req, false); err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = "confirm_with_audit_reason"
		_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	store, current, ledger, err := b.loadRotationTarget(ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	versionID := strings.TrimSpace(req.VersionID)
	operationID := rotationOperationToken(req)
	if operationID == ledger.LastRollbackOperationID && current.Metadata.Version == ledger.LastRollbackVersionID {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "conflict"
		res.NextAction = "already_active"
		_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errRotationConflict
	}
	if versionID == "" {
		versionID = ledger.PreviousVersionID
	}
	if versionID == current.Metadata.Version {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "conflict"
		res.NextAction = "already_active"
		_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errRotationConflict
	}
	previous, ok := ledger.Retained[versionID]
	if !ok {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "missing_ref"
		res.NextAction = "inspect_rotation_status"
		_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errMissingRef
	}
	if err := b.requireRotationMutationAudit("rotation_rollback", req); err != nil {
		return rotationAuditUnavailableResponse(res, ref, current, ledger), err
	}
	now := b.now()
	retainedCurrent := rotationStoredVersion{
		VersionID:   current.Metadata.Version,
		OperationID: ledger.ActiveVersionID,
		RequestID:   strings.TrimSpace(req.RequestID),
		Metadata:    current.Metadata,
		Payload:     current.Payload,
		RetainedAt:  now,
	}
	previous.Metadata.UpdatedAt = now
	previous.ActivatedAt = now
	store.Secrets[ref] = secretEntry{Ref: ref, Metadata: previous.Metadata, Payload: previous.Payload}
	delete(ledger.Retained, versionID)
	ledger.Retained[retainedCurrent.VersionID] = retainedCurrent
	ledger.ActiveVersionID = previous.VersionID
	ledger.PreviousVersionID = retainedCurrent.VersionID
	ledger.LastRollbackOperationID = operationID
	ledger.LastRollbackVersionID = previous.VersionID
	ledger.UpdatedAt = now
	store.Rotations[ref] = ledger
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		res.Outcome = "degraded"
		res.NextAction = "retry_or_inspect_source"
		_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	res = enrichRotationResponse(res, ref, store.Secrets[ref], ledger)
	res.Outcome = "rolled_back"
	res.Applied = true
	res.AuditStatus = "audit_recorded"
	res.NextAction = "inspect_or_retire_superseded_version_after_convergence"
	_ = b.audit("rotation_rollback", ref, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

func (b *localBackend) retireRotationVersion(req rotationVersionRequest) (rotationVersionResponse, error) {
	b.rotationMu.Lock()
	defer b.rotationMu.Unlock()
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()

	ref := strings.TrimSpace(req.Ref)
	res := baseRotationVersionResponse(req, "rotation_retire", "retire")
	if err := validateRotationConfirmation(req, false); err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = "confirm_with_audit_reason"
		_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	store, current, ledger, err := b.loadRotationTarget(ref)
	if err != nil {
		res.Outcome = outcomeForError(err)
		res.NextAction = nextActionForManagedOutcome(res.Outcome)
		_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, err
	}
	retired := false
	if versionID := strings.TrimSpace(req.VersionID); versionID != "" {
		if versionID == current.Metadata.Version {
			res = enrichRotationResponse(res, ref, current, ledger)
			res.Outcome = "conflict"
			res.NextAction = "cannot_retire_active_version"
			_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
			return res, errRotationConflict
		}
		if _, ok := ledger.Retained[versionID]; !ok {
			res = enrichRotationResponse(res, ref, current, ledger)
			res.Outcome = "retired"
			res.AuditStatus = "audit_recorded"
			res.NextAction = "inspect_rotation_status"
			_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
			return res, nil
		}
	} else if !retentionPruningRequired(ledger, req.RetentionLimit) {
		res = enrichRotationResponse(res, ref, current, ledger)
		res.Outcome = "retired"
		res.AuditStatus = "audit_recorded"
		res.NextAction = "inspect_rotation_status"
		_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, nil
	}
	if err := b.requireRotationMutationAudit("rotation_retire", req); err != nil {
		return rotationAuditUnavailableResponse(res, ref, current, ledger), err
	}
	if versionID := strings.TrimSpace(req.VersionID); versionID != "" {
		delete(ledger.Retained, versionID)
		if ledger.PreviousVersionID == versionID {
			ledger.PreviousVersionID = newestRetainedVersionID(ledger)
		}
		retired = true
	} else {
		retired = trimRetainedVersions(&ledger, req.RetentionLimit)
	}
	ledger.UpdatedAt = b.now()
	store.Rotations[ref] = ledger
	store.UpdatedAt = ledger.UpdatedAt
	if err := b.saveStore(store); err != nil {
		res.Outcome = "degraded"
		res.NextAction = "retry_or_inspect_source"
		_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
		return res, errBackendDegraded
	}
	res = enrichRotationResponse(res, ref, current, ledger)
	res.Outcome = "retired"
	res.Applied = retired
	res.AuditStatus = "audit_recorded"
	res.NextAction = "inspect_rotation_status"
	_ = b.audit("rotation_retire", ref, res.Outcome, req.ServiceID, req.RequestID)
	return res, nil
}

// requireRotationMutationAudit records a durable, metadata-only authorization
// event before changing encrypted rotation state. The success event written
// after the store update remains useful outcome evidence, while this preflight
// ensures an unavailable audit/event sink fails the mutation closed.
func (b *localBackend) requireRotationMutationAudit(operation string, req rotationVersionRequest) error {
	if b == nil || strings.TrimSpace(b.auditPath) == "" {
		return errRotationAuditUnavailable
	}
	if err := b.audit(operation, req.Ref, "ready", req.ServiceID, req.RequestID); err != nil {
		return fmt.Errorf("%w: %v", errRotationAuditUnavailable, err)
	}
	return nil
}

func rotationAuditUnavailableResponse(res rotationVersionResponse, ref string, current secretEntry, ledger rotationLedger) rotationVersionResponse {
	res = enrichRotationResponse(res, ref, current, ledger)
	res.Outcome = "audit_unavailable"
	res.Applied = false
	res.AuditStatus = "audit_unavailable"
	res.NextAction = "restore_audit_and_retry"
	return res
}

func (b *localBackend) loadRotationTarget(ref string) (localStoreFile, secretEntry, rotationLedger, error) {
	if !validSecretRef(ref) {
		return localStoreFile{}, secretEntry{}, rotationLedger{}, errInvalidRef
	}
	if b.locked() {
		return localStoreFile{}, secretEntry{}, rotationLedger{}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		return store, secretEntry{}, rotationLedger{}, errBackendDegraded
	}
	current, ok := store.Secrets[ref]
	if !ok {
		return store, secretEntry{}, rotationLedger{}, errMissingRef
	}
	if strings.TrimSpace(current.Metadata.Version) == "" {
		current.Metadata.Version = current.Metadata.UpdatedAt.Format(time.RFC3339Nano)
	}
	if store.Rotations == nil {
		store.Rotations = map[string]rotationLedger{}
	}
	ledger := normalizedRotationLedger(store.Rotations[ref])
	ledger.ActiveVersionID = firstNonEmpty(ledger.ActiveVersionID, current.Metadata.Version)
	return store, current, ledger, nil
}

func normalizedRotationLedger(ledger rotationLedger) rotationLedger {
	if ledger.Staged == nil {
		ledger.Staged = map[string]rotationStoredVersion{}
	}
	if ledger.Retained == nil {
		ledger.Retained = map[string]rotationStoredVersion{}
	}
	return ledger
}

func baseRotationVersionResponse(req rotationVersionRequest, operation, mode string) rotationVersionResponse {
	ref := strings.TrimSpace(req.Ref)
	return rotationVersionResponse{
		ServiceID:              serviceID,
		APIVersion:             apiVersion,
		RequestID:              strings.TrimSpace(req.RequestID),
		Ref:                    ref,
		Operation:              operation,
		Mode:                   mode,
		Outcome:                "pending",
		RequiresConfirmation:   mode != "status",
		AuditStatus:            "audit_pending",
		PolicyResult:           "allowed",
		ExpectedCurrentVersion: strings.TrimSpace(req.ExpectedCurrentVersion),
		Versions:               []rotationVersionMetadata{},
		AffectedRefs:           safeList([]string{ref}),
		AffectedServices:       safeList([]string{firstNonEmpty(req.ServiceID, ownerFromRef(ref))}),
	}
}

func enrichRotationResponse(res rotationVersionResponse, ref string, current secretEntry, ledger rotationLedger) rotationVersionResponse {
	activeVersionID := firstNonEmpty(ledger.ActiveVersionID, current.Metadata.Version)
	res.ActiveVersionID = activeVersionID
	res.PreviousVersionID = ledger.PreviousVersionID
	currentMeta := rotationMetadataFromEntry(current, "active")
	currentMeta.VersionID = activeVersionID
	res.CurrentVersion = &currentMeta
	if previous, ok := ledger.Retained[ledger.PreviousVersionID]; ok {
		metadata := rotationMetadataFromStored(previous, "previous")
		res.PreviousVersion = &metadata
	}
	for _, staged := range sortedStoredVersions(ledger.Staged) {
		res.Versions = append(res.Versions, rotationMetadataFromStored(staged, "staged"))
	}
	for _, retained := range sortedStoredVersions(ledger.Retained) {
		state := "retained"
		if retained.VersionID == ledger.PreviousVersionID {
			state = "previous"
		}
		res.Versions = append(res.Versions, rotationMetadataFromStored(retained, state))
	}
	return res
}

func rotationMetadataFromEntry(entry secretEntry, state string) rotationVersionMetadata {
	return rotationVersionMetadata{
		VersionID:    entry.Metadata.Version,
		SourceID:     firstNonEmpty(entry.Metadata.SourceID, localStoreSource),
		State:        state,
		Fingerprint:  rotationFingerprint(entry.Metadata.Version, entry.Payload),
		CreatedAt:    entry.Metadata.CreatedAt,
		UpdatedAt:    entry.Metadata.UpdatedAt,
		AuditStatus:  "audit_available",
		PolicyResult: "allowed",
	}
}

func rotationMetadataFromStored(stored rotationStoredVersion, state string) rotationVersionMetadata {
	return rotationVersionMetadata{
		VersionID:    stored.VersionID,
		SourceID:     firstNonEmpty(stored.Metadata.SourceID, localStoreSource),
		State:        state,
		Fingerprint:  rotationFingerprint(stored.VersionID, stored.Payload),
		CreatedAt:    stored.Metadata.CreatedAt,
		UpdatedAt:    stored.Metadata.UpdatedAt,
		StagedAt:     stored.StagedAt,
		ActivatedAt:  stored.ActivatedAt,
		RetainedAt:   stored.RetainedAt,
		OperationID:  stored.OperationID,
		AuditStatus:  "audit_available",
		PolicyResult: "allowed",
	}
}

func sortedStoredVersions(versions map[string]rotationStoredVersion) []rotationStoredVersion {
	result := make([]rotationStoredVersion, 0, len(versions))
	for _, version := range versions {
		result = append(result, version)
	}
	sort.Slice(result, func(i, j int) bool {
		left := firstNonZeroTime(result[i].RetainedAt, result[i].StagedAt, result[i].Metadata.UpdatedAt)
		right := firstNonZeroTime(result[j].RetainedAt, result[j].StagedAt, result[j].Metadata.UpdatedAt)
		if left.Equal(right) {
			return result[i].VersionID < result[j].VersionID
		}
		return left.Before(right)
	})
	return result
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func rotationFingerprint(versionID string, payload secretPayload) string {
	return hashAuditRef(strings.Join([]string{strings.TrimSpace(versionID), payload.Alg, payload.KeyID, payload.KeyVersion, payload.Nonce, payload.Ciphertext}, ":"))
}

func validateRotationSecretBearingRequest(req rotationVersionRequest, requireValue bool) error {
	if !validSecretRef(req.Ref) {
		return errInvalidRef
	}
	if strings.TrimSpace(req.Reason) == "" {
		return errPolicyDenied
	}
	if requireValue && strings.TrimSpace(req.Value) == "" {
		return errPolicyDenied
	}
	if strings.TrimSpace(rotationOperationToken(req)) == "" {
		return errInvalidRef
	}
	return nil
}

func validateRotationConfirmation(req rotationVersionRequest, requireExpectedCurrent bool) error {
	if err := validateRotationSecretBearingRequest(rotationVersionRequest{Ref: req.Ref, OperationID: firstNonEmpty(req.OperationID, req.RequestID), Reason: req.Reason, Value: "metadata-only"}, false); err != nil {
		return err
	}
	if !req.Confirm {
		return errPolicyDenied
	}
	if requireExpectedCurrent && strings.TrimSpace(req.ExpectedCurrentVersion) == "" {
		return errRotationConflict
	}
	return nil
}

func rotationOperationToken(req rotationVersionRequest) string {
	return safeOperationToken(firstNonEmpty(req.OperationID, req.RequestID))
}

func rotationVersionID(req rotationVersionRequest) string {
	if versionID := safeOperationToken(req.VersionID); versionID != "" {
		return versionID
	}
	token := rotationOperationToken(req)
	if token == "" {
		return ""
	}
	return "rv-" + token
}

func newestRetainedVersionID(ledger rotationLedger) string {
	newestID := ""
	var newestAt time.Time
	for versionID, retained := range ledger.Retained {
		at := firstNonZeroTime(retained.RetainedAt, retained.Metadata.UpdatedAt, retained.Metadata.CreatedAt)
		if newestID == "" || at.After(newestAt) || (at.Equal(newestAt) && versionID > newestID) {
			newestID = versionID
			newestAt = at
		}
	}
	return newestID
}

func trimRetainedVersions(ledger *rotationLedger, limit int) bool {
	if ledger == nil || len(ledger.Retained) == 0 {
		return false
	}
	if limit < 0 {
		limit = 0
	}
	if limit == 0 {
		limit = defaultRotationRetentionLimit
	}
	versions := sortedStoredVersions(ledger.Retained)
	retired := false
	for len(versions) > limit {
		version := versions[0]
		delete(ledger.Retained, version.VersionID)
		if ledger.PreviousVersionID == version.VersionID {
			ledger.PreviousVersionID = newestRetainedVersionID(*ledger)
		}
		versions = versions[1:]
		retired = true
	}
	return retired
}

func retentionPruningRequired(ledger rotationLedger, limit int) bool {
	if limit < 0 {
		limit = 0
	}
	if limit == 0 {
		limit = defaultRotationRetentionLimit
	}
	return len(ledger.Retained) > limit
}

func registerRotationVersionHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	registerRotationVersionAction(mux, security, "/v1/management/secrets/rotation/status", backend.rotationStatus)
	registerRotationVersionAction(mux, security, "/v1/management/secrets/rotation/stage", backend.stageRotationVersion)
	registerRotationVersionAction(mux, security, "/v1/management/secrets/rotation/activate", backend.activateRotationVersion)
	registerRotationVersionAction(mux, security, "/v1/management/secrets/rotation/rollback", backend.rollbackRotationVersion)
	registerRotationVersionAction(mux, security, "/v1/management/secrets/rotation/retire", backend.retireRotationVersion)
}

func registerRotationVersionAction(mux *http.ServeMux, security localAPISecurity, path string, handler func(rotationVersionRequest) (rotationVersionResponse, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST "+path+".", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req rotationVersionRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := handler(req)
		if err != nil {
			writeRotationVersionError(w, err, res)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

func writeRotationVersionError(w http.ResponseWriter, err error, res rotationVersionResponse) {
	status := http.StatusServiceUnavailable
	switch {
	case errors.Is(err, errInvalidRef):
		status = http.StatusBadRequest
	case errors.Is(err, errMissingRef):
		status = http.StatusNotFound
	case errors.Is(err, errPolicyDenied):
		status = http.StatusForbidden
	case errors.Is(err, errRotationConflict):
		status = http.StatusConflict
	case errors.Is(err, errRotationAuditUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, errLocked):
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, res)
}
