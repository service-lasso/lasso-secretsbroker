package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	localStoreVersion            = 1
	localStoreSource             = "local"
	maxSecretBearingRequestBytes = 1 << 20
)

var (
	errLocked             = errors.New("secrets broker store is locked")
	errMissingRef         = errors.New("secret ref was not found")
	errInvalidRef         = errors.New("invalid secret ref")
	errPolicyDenied       = errors.New("write-back policy denied")
	errLockoutActive      = errors.New("lockout active")
	errIdentityExpired    = errors.New("launch identity expired")
	errIdentityInvalid    = errors.New("launch identity invalid")
	errIdentityReplayed   = errors.New("launch identity replayed")
	errSourceAuthRequired = errors.New("source authentication required")
	errBackendDegraded    = errors.New("backend degraded")
)

type localBackend struct {
	storePath                string
	auditPath                string
	eventPath                string
	masterKey                string
	auditHashChain           bool
	sources                  sourceConfigFile
	now                      func() time.Time
	lockouts                 *lockoutStore
	campaigns                map[string]bulkCampaignResponse
	launchIdentitySigningKey string
	launchLeaseMu            sync.Mutex
	seenLaunchLeaseJTI       map[string]time.Time
}

type localStoreFile struct {
	Version    int                     `json:"version"`
	ServiceID  string                  `json:"serviceId"`
	KeyID      string                  `json:"keyId,omitempty"`
	KeyVersion string                  `json:"keyVersion,omitempty"`
	CreatedAt  time.Time               `json:"createdAt"`
	UpdatedAt  time.Time               `json:"updatedAt"`
	Secrets    map[string]secretEntry  `json:"secrets"`
	Recovery   *recoveryPolicyMetadata `json:"recoveryPolicy,omitempty"`
}

type secretEntry struct {
	Ref      string         `json:"ref"`
	Metadata SecretMetadata `json:"metadata"`
	Payload  secretPayload  `json:"payload"`
}

type SecretMetadata struct {
	SourceID  string    `json:"sourceId"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type secretPayload struct {
	Alg        string `json:"alg"`
	KeyID      string `json:"keyId"`
	KeyVersion string `json:"keyVersion"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type writeSecretRequest struct {
	Ref      string            `json:"ref"`
	Value    string            `json:"value"`
	Metadata map[string]string `json:"metadata"`
}

type writeSecretResponse struct {
	ServiceID  string         `json:"serviceId"`
	APIVersion string         `json:"apiVersion"`
	Ref        string         `json:"ref"`
	Outcome    string         `json:"outcome"`
	Metadata   SecretMetadata `json:"metadata"`
}

type writebackPolicy struct {
	AllowedNamespaces []string `json:"allowedNamespaces"`
	AllowedOperations []string `json:"allowedOperations"`
}

type writebackIdentity struct {
	ServiceID string `json:"serviceId"`
	ExpiresAt string `json:"expiresAt"`
}

type launchIdentityLease struct {
	Issuer            string                  `json:"issuer"`
	ServiceID         string                  `json:"serviceId"`
	WorkspaceID       string                  `json:"workspaceId,omitempty"`
	AllowedRefs       []string                `json:"allowedRefs,omitempty"`
	AllowedNamespaces []string                `json:"allowedNamespaces,omitempty"`
	AllowedOperations []string                `json:"allowedOperations,omitempty"`
	IssuedAt          string                  `json:"issuedAt"`
	ExpiresAt         string                  `json:"expiresAt"`
	JTI               string                  `json:"jti"`
	Signature         string                  `json:"signature"`
	TransportBinding  *launchTransportBinding `json:"transportBinding,omitempty"`
}

type launchIdentityLeasePayload struct {
	Issuer            string                  `json:"issuer"`
	ServiceID         string                  `json:"serviceId"`
	WorkspaceID       string                  `json:"workspaceId,omitempty"`
	AllowedRefs       []string                `json:"allowedRefs,omitempty"`
	AllowedNamespaces []string                `json:"allowedNamespaces,omitempty"`
	AllowedOperations []string                `json:"allowedOperations,omitempty"`
	IssuedAt          string                  `json:"issuedAt"`
	ExpiresAt         string                  `json:"expiresAt"`
	JTI               string                  `json:"jti"`
	TransportBinding  *launchTransportBinding `json:"transportBinding,omitempty"`
}

type launchTransportBinding struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
}

type generatedSecretCaptureRequest struct {
	RequestID          string                `json:"requestId"`
	Identity           writebackIdentity     `json:"identity"`
	IdentityLease      *launchIdentityLease  `json:"identityLease,omitempty"`
	Policy             writebackPolicy       `json:"policy"`
	Secrets            *serviceSecretsPolicy `json:"secrets,omitempty"`
	Operation          string                `json:"operation"`
	Namespace          string                `json:"namespace"`
	Ref                string                `json:"ref"`
	Value              string                `json:"value"`
	Metadata           map[string]string     `json:"metadata"`
	RefreshRequired    bool                  `json:"refreshRequired"`
	ReconnectRequired  bool                  `json:"reconnectRequired"`
	InvalidateRefs     []string              `json:"invalidateRefs"`
	SourceAuthRequired bool                  `json:"sourceAuthRequired"`
}

type generatedSecretCaptureResponse struct {
	ServiceID         string         `json:"serviceId"`
	APIVersion        string         `json:"apiVersion"`
	RequestID         string         `json:"requestId,omitempty"`
	OwnerServiceID    string         `json:"ownerServiceId"`
	Operation         string         `json:"operation"`
	Namespace         string         `json:"namespace"`
	Ref               string         `json:"ref"`
	Outcome           string         `json:"outcome"`
	RefreshRequired   bool           `json:"refreshRequired"`
	ReconnectRequired bool           `json:"reconnectRequired"`
	InvalidatedRefs   []string       `json:"invalidatedRefs"`
	Metadata          SecretMetadata `json:"metadata,omitempty"`
	LockoutActive     bool           `json:"lockoutActive,omitempty"`
	LockoutScope      string         `json:"lockoutScope,omitempty"`
	RetryAfterSeconds int            `json:"retryAfterSeconds,omitempty"`
}

type resolveRequest struct {
	RequestID     string                `json:"requestId"`
	WorkspaceID   string                `json:"workspaceId"`
	ServiceID     string                `json:"serviceId"`
	IdentityLease *launchIdentityLease  `json:"identityLease,omitempty"`
	Purpose       string                `json:"purpose"`
	Secrets       *serviceSecretsPolicy `json:"secrets,omitempty"`
	Refs          []string              `json:"refs"`
}

type resolveResponse struct {
	ServiceID  string          `json:"serviceId"`
	APIVersion string          `json:"apiVersion"`
	RequestID  string          `json:"requestId,omitempty"`
	Results    []resolveResult `json:"results"`
}

type resolveResult struct {
	Ref          string          `json:"ref"`
	Outcome      string          `json:"outcome"`
	Value        string          `json:"value,omitempty"`
	Metadata     *SecretMetadata `json:"metadata,omitempty"`
	Message      string          `json:"message,omitempty"`
	PolicyResult string          `json:"policyResult,omitempty"`
	NextAction   string          `json:"nextAction,omitempty"`
	ReasonCode   string          `json:"reasonCode,omitempty"`
}

type auditEvent struct {
	TS           time.Time `json:"ts"`
	RequestID    string    `json:"requestId,omitempty"`
	Operation    string    `json:"operation"`
	ServiceID    string    `json:"serviceId,omitempty"`
	ActorKind    string    `json:"actorKind"`
	Ref          string    `json:"ref,omitempty"`
	RefHash      string    `json:"refHash,omitempty"`
	ProviderID   string    `json:"providerId,omitempty"`
	SourceID     string    `json:"sourceId,omitempty"`
	PolicyID     string    `json:"policyId,omitempty"`
	KeyID        string    `json:"keyId,omitempty"`
	Outcome      string    `json:"outcome"`
	ReasonCode   string    `json:"reasonCode"`
	State        string    `json:"state,omitempty"`
	AuditStatus  string    `json:"auditStatus"`
	PreviousHash string    `json:"previousHash,omitempty"`
	EventHash    string    `json:"eventHash,omitempty"`
	ChainStatus  string    `json:"chainStatus,omitempty"`
}

func newLocalBackend(storePath, auditPath, masterKey string) *localBackend {
	backend := &localBackend{storePath: storePath, auditPath: auditPath, eventPath: defaultEventsPath(auditPath), masterKey: masterKey, now: func() time.Time { return time.Now().UTC() }, campaigns: map[string]bulkCampaignResponse{}, seenLaunchLeaseJTI: map[string]time.Time{}}
	backend.lockouts = newLockoutStore(func() time.Time {
		if backend.now == nil {
			return time.Now().UTC()
		}
		return backend.now()
	})
	return backend
}

func defaultStorePath() string { return filepath.Join("data", "secretsbroker-store.json") }
func defaultAuditPath() string { return filepath.Join("data", "secretsbroker-audit.jsonl") }
func defaultEventsPath(auditPath string) string {
	auditPath = strings.TrimSpace(auditPath)
	if auditPath == "" {
		return ""
	}
	if filepath.Clean(auditPath) == filepath.Clean(defaultAuditPath()) {
		return filepath.Join("data", "secretsbroker-events.jsonl")
	}
	ext := filepath.Ext(auditPath)
	if ext == "" {
		return auditPath + "-events"
	}
	return strings.TrimSuffix(auditPath, ext) + "-events" + ext
}

func (b *localBackend) locked() bool { return strings.TrimSpace(b.masterKey) == "" }

func validSecretRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") || strings.Contains(ref, "..") {
		return false
	}
	if strings.ContainsAny(ref, " \t\r\n") {
		return false
	}
	parts := strings.Split(ref, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (b *localBackend) writeSecret(req writeSecretRequest) (writeSecretResponse, error) {
	ref := strings.TrimSpace(req.Ref)
	if !validSecretRef(ref) {
		_ = b.audit("write", ref, "invalid_ref", "", "")
		return writeSecretResponse{}, errInvalidRef
	}
	if b.locked() {
		_ = b.audit("write", ref, "locked", "", "")
		return writeSecretResponse{}, errLocked
	}

	store, err := b.loadStore()
	if err != nil {
		return writeSecretResponse{}, err
	}
	now := b.now()
	if store.KeyID == "" {
		store.KeyID = masterKeyID(b.masterKey)
	}
	if store.KeyVersion == "" {
		store.KeyVersion = masterKeyVersion
	}
	version := now.Format(time.RFC3339Nano)
	metadata := SecretMetadata{
		SourceID:  firstNonEmpty(req.Metadata["sourceId"], localStoreSource),
		Version:   version,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if existing, ok := store.Secrets[ref]; ok {
		metadata.CreatedAt = existing.Metadata.CreatedAt
	}
	payload, err := b.encrypt(req.Value)
	if err != nil {
		return writeSecretResponse{}, err
	}
	store.Secrets[ref] = secretEntry{Ref: ref, Metadata: metadata, Payload: payload}
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		return writeSecretResponse{}, err
	}
	_ = b.audit("write", ref, "ready", "", "")
	return writeSecretResponse{ServiceID: serviceID, APIVersion: apiVersion, Ref: ref, Outcome: "ready", Metadata: metadata}, nil
}

func normalizeWritebackOperation(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return "create"
	}
	return operation
}

func validWritebackOperation(operation string) bool {
	switch operation {
	case "create", "update", "rotate", "delete":
		return true
	default:
		return false
	}
}

func namespaceAllowed(namespace string, allowed []string) bool {
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == namespace {
			return true
		}
	}
	return false
}

func operationAllowed(operation string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.TrimSpace(candidate) == operation {
			return true
		}
	}
	return false
}

func signLaunchIdentityLease(lease launchIdentityLease, key string) (launchIdentityLease, error) {
	input, err := launchIdentitySignatureInput(lease)
	if err != nil {
		return lease, err
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(input)
	lease.Signature = "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return lease, nil
}

func launchIdentitySignatureInput(lease launchIdentityLease) ([]byte, error) {
	payload := launchIdentityLeasePayload{
		Issuer:            strings.TrimSpace(lease.Issuer),
		ServiceID:         strings.TrimSpace(lease.ServiceID),
		WorkspaceID:       strings.TrimSpace(lease.WorkspaceID),
		AllowedRefs:       safeList(lease.AllowedRefs),
		AllowedNamespaces: safeList(lease.AllowedNamespaces),
		AllowedOperations: safeList(lease.AllowedOperations),
		IssuedAt:          strings.TrimSpace(lease.IssuedAt),
		ExpiresAt:         strings.TrimSpace(lease.ExpiresAt),
		JTI:               strings.TrimSpace(lease.JTI),
		TransportBinding:  normalizeLaunchTransportBinding(lease.TransportBinding),
	}
	return json.Marshal(payload)
}

func (b *localBackend) authorizeWritebackLaunchLease(req *generatedSecretCaptureRequest, signingKey string, peer transportPeerIdentity) error {
	if req == nil {
		return errIdentityInvalid
	}
	operation := normalizeWritebackOperation(req.Operation)
	namespace := strings.Trim(strings.TrimSpace(req.Namespace), "/")
	ref := strings.Trim(strings.TrimSpace(req.Ref), "/")
	fullRef := strings.Trim(namespace+"/"+ref, "/")
	if err := b.verifyLaunchIdentityLease(req.IdentityLease, signingKey, strings.TrimSpace(req.Identity.ServiceID), "", operation, []string{fullRef}, []string{namespace}, peer); err != nil {
		_ = b.audit("launch_identity", fullRef, launchIdentityOutcome(err), strings.TrimSpace(req.Identity.ServiceID), req.RequestID)
		return err
	}
	req.Identity.ServiceID = strings.TrimSpace(req.IdentityLease.ServiceID)
	req.Identity.ExpiresAt = strings.TrimSpace(req.IdentityLease.ExpiresAt)
	if len(req.Policy.AllowedNamespaces) == 0 && len(req.IdentityLease.AllowedNamespaces) > 0 {
		req.Policy.AllowedNamespaces = safeList(req.IdentityLease.AllowedNamespaces)
	}
	if len(req.Policy.AllowedOperations) == 0 && len(req.IdentityLease.AllowedOperations) > 0 {
		req.Policy.AllowedOperations = safeList(req.IdentityLease.AllowedOperations)
	}
	_ = b.audit("launch_identity", fullRef, "allowed", req.Identity.ServiceID, req.RequestID)
	return nil
}

func (b *localBackend) authorizeResolveLaunchLease(req *resolveRequest, signingKey string, peer transportPeerIdentity) error {
	if req == nil {
		return errIdentityInvalid
	}
	if err := b.verifyLaunchIdentityLease(req.IdentityLease, signingKey, strings.TrimSpace(req.ServiceID), strings.TrimSpace(req.WorkspaceID), "resolve", req.Refs, nil, peer); err != nil {
		_ = b.audit("launch_identity", "", launchIdentityOutcome(err), strings.TrimSpace(req.ServiceID), req.RequestID)
		return err
	}
	req.ServiceID = strings.TrimSpace(req.IdentityLease.ServiceID)
	if strings.TrimSpace(req.WorkspaceID) == "" {
		req.WorkspaceID = strings.TrimSpace(req.IdentityLease.WorkspaceID)
	}
	if req.Secrets == nil && len(req.IdentityLease.AllowedRefs) > 0 {
		req.Secrets = &serviceSecretsPolicy{Resolve: safeList(req.IdentityLease.AllowedRefs)}
	}
	_ = b.audit("launch_identity", "", "allowed", req.ServiceID, req.RequestID)
	return nil
}

func (b *localBackend) verifyLaunchIdentityLease(lease *launchIdentityLease, signingKey, expectedServiceID, expectedWorkspaceID, operation string, refs, namespaces []string, peer transportPeerIdentity) error {
	if lease == nil || strings.TrimSpace(signingKey) == "" || strings.TrimSpace(lease.Signature) == "" || strings.TrimSpace(lease.ServiceID) == "" || strings.TrimSpace(lease.Issuer) == "" || strings.TrimSpace(lease.JTI) == "" {
		return errIdentityInvalid
	}
	binding := normalizeLaunchTransportBinding(lease.TransportBinding)
	if lease.TransportBinding != nil && binding == nil {
		return errIdentityInvalid
	}
	if expectedServiceID != "" && strings.TrimSpace(lease.ServiceID) != expectedServiceID {
		return errPolicyDenied
	}
	if expectedWorkspaceID != "" && strings.TrimSpace(lease.WorkspaceID) != "" && strings.TrimSpace(lease.WorkspaceID) != expectedWorkspaceID {
		return errPolicyDenied
	}
	now := b.now()
	issuedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(lease.IssuedAt))
	if err != nil || issuedAt.After(now.Add(5*time.Minute)) {
		return errIdentityInvalid
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(lease.ExpiresAt))
	if err != nil {
		return errIdentityInvalid
	}
	if !expiresAt.After(now) {
		return errIdentityExpired
	}
	if !launchLeaseOperationAllowed(operation, lease.AllowedOperations) {
		return errPolicyDenied
	}
	if !launchLeaseRefsAllowed(refs, namespaces, lease.AllowedRefs, lease.AllowedNamespaces) {
		return errPolicyDenied
	}
	input, err := launchIdentitySignatureInput(*lease)
	if err != nil {
		return errIdentityInvalid
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	_, _ = mac.Write(input)
	want := "hmac-sha256:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !constantTimeTokenEqual(lease.Signature, want) {
		return errIdentityInvalid
	}
	if binding != nil && !launchTransportBindingMatchesPeer(binding, peer) {
		return errPolicyDenied
	}
	if !b.rememberLaunchLeaseJTI(*lease, expiresAt, now) {
		return errIdentityReplayed
	}
	return nil
}

func normalizeLaunchTransportBinding(binding *launchTransportBinding) *launchTransportBinding {
	if binding == nil {
		return nil
	}
	normalized := &launchTransportBinding{
		Kind:    strings.ToLower(strings.TrimSpace(binding.Kind)),
		Subject: strings.TrimSpace(binding.Subject),
	}
	if normalized.Kind == "" || normalized.Subject == "" {
		return nil
	}
	return normalized
}

func launchTransportBindingMatchesPeer(binding *launchTransportBinding, peer transportPeerIdentity) bool {
	if binding == nil {
		return true
	}
	peer = normalizeTransportPeerIdentity(peer)
	if peer.Kind == "" || peer.Subject == "" {
		return false
	}
	return strings.EqualFold(binding.Kind, peer.Kind) && strings.EqualFold(binding.Subject, peer.Subject)
}

func launchLeaseOperationAllowed(operation string, allowed []string) bool {
	operation = strings.TrimSpace(operation)
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == operation || (operation != "resolve" && candidate == "writeback") {
			return true
		}
	}
	return false
}

func launchLeaseRefsAllowed(refs, namespaces, allowedRefs, allowedNamespaces []string) bool {
	allowedRefs = safeList(allowedRefs)
	allowedNamespaces = safeList(allowedNamespaces)
	if len(allowedRefs) == 0 && len(allowedNamespaces) == 0 {
		return false
	}
	for _, ref := range refs {
		ref = strings.Trim(strings.TrimSpace(ref), "/")
		if ref == "" || !validSecretRef(ref) {
			continue
		}
		if !launchLeaseRefAllowed(ref, allowedRefs, allowedNamespaces) {
			return false
		}
	}
	for _, namespace := range namespaces {
		namespace = strings.Trim(strings.TrimSpace(namespace), "/")
		if namespace == "" || !validSecretRef(namespace) {
			continue
		}
		if !launchLeaseNamespaceAllowed(namespace, allowedNamespaces) {
			return false
		}
	}
	return true
}

func launchLeaseRefAllowed(ref string, allowedRefs, allowedNamespaces []string) bool {
	for _, pattern := range allowedRefs {
		if secretPolicyPatternMatches(ref, pattern) {
			return true
		}
	}
	for _, namespace := range allowedNamespaces {
		namespace = strings.Trim(strings.TrimSpace(namespace), "/")
		if namespace == "*" || ref == namespace || strings.HasPrefix(ref, namespace+"/") {
			return true
		}
	}
	return false
}

func launchLeaseNamespaceAllowed(namespace string, allowedNamespaces []string) bool {
	for _, pattern := range allowedNamespaces {
		if secretPolicyPatternMatches(namespace, pattern) {
			return true
		}
	}
	return false
}

func (b *localBackend) rememberLaunchLeaseJTI(lease launchIdentityLease, expiresAt, now time.Time) bool {
	if b == nil {
		return true
	}
	key := strings.TrimSpace(lease.Issuer) + ":" + strings.TrimSpace(lease.JTI)
	b.launchLeaseMu.Lock()
	defer b.launchLeaseMu.Unlock()
	if b.seenLaunchLeaseJTI == nil {
		b.seenLaunchLeaseJTI = map[string]time.Time{}
	}
	for jti, expiry := range b.seenLaunchLeaseJTI {
		if !expiry.After(now) {
			delete(b.seenLaunchLeaseJTI, jti)
		}
	}
	if expiry, ok := b.seenLaunchLeaseJTI[key]; ok && expiry.After(now) {
		return false
	}
	b.seenLaunchLeaseJTI[key] = expiresAt
	return true
}

func launchIdentityOutcome(err error) string {
	switch {
	case errors.Is(err, errIdentityExpired):
		return "identity_expired"
	case errors.Is(err, errIdentityReplayed):
		return "identity_replayed"
	case errors.Is(err, errPolicyDenied):
		return "policy_denied"
	default:
		return "identity_invalid"
	}
}

func (b *localBackend) captureGeneratedSecret(req generatedSecretCaptureRequest) (generatedSecretCaptureResponse, error) {
	operation := normalizeWritebackOperation(req.Operation)
	namespace := strings.TrimSpace(req.Namespace)
	ref := strings.Trim(strings.TrimSpace(req.Ref), "/")
	fullRef := strings.Trim(namespace+"/"+ref, "/")
	service := strings.TrimSpace(req.Identity.ServiceID)
	response := generatedSecretCaptureResponse{
		ServiceID:         serviceID,
		APIVersion:        apiVersion,
		RequestID:         req.RequestID,
		OwnerServiceID:    service,
		Operation:         operation,
		Namespace:         namespace,
		Ref:               fullRef,
		RefreshRequired:   req.RefreshRequired,
		ReconnectRequired: req.ReconnectRequired,
		InvalidatedRefs:   safeList(req.InvalidateRefs),
	}

	if namespace == "" || !validSecretRef(namespace) || ref == "" || !validSecretRef(fullRef) || !validWritebackOperation(operation) {
		_ = b.audit("writeback_capture", fullRef, "invalid_ref", service, req.RequestID)
		response.Outcome = "invalid_ref"
		return response, errInvalidRef
	}
	if decision := b.activeWritebackLockout(writebackLockoutScope("identity", service, operation, fullRef)); decision.Active {
		_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
		response.Outcome = "lockout_active"
		applyWritebackLockout(&response, decision)
		return response, errLockoutActive
	}
	if service == "" {
		_ = b.audit("writeback_capture", fullRef, "identity_expired", service, req.RequestID)
		if decision, started := b.recordWritebackLockoutFailure(writebackLockoutScope("identity", service, operation, fullRef)); started {
			_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
			response.Outcome = "lockout_active"
			applyWritebackLockout(&response, decision)
			return response, errLockoutActive
		}
		response.Outcome = "identity_expired"
		return response, errIdentityExpired
	}
	if strings.TrimSpace(req.Identity.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(req.Identity.ExpiresAt))
		if err != nil || !expiresAt.After(b.now()) {
			_ = b.audit("writeback_capture", fullRef, "identity_expired", service, req.RequestID)
			if decision, started := b.recordWritebackLockoutFailure(writebackLockoutScope("identity", service, operation, fullRef)); started {
				_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
				response.Outcome = "lockout_active"
				applyWritebackLockout(&response, decision)
				return response, errLockoutActive
			}
			response.Outcome = "identity_expired"
			return response, errIdentityExpired
		}
	}
	if decision := b.activeWritebackLockout(writebackLockoutScope("policy", service, operation, fullRef)); decision.Active {
		_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
		response.Outcome = "lockout_active"
		applyWritebackLockout(&response, decision)
		return response, errLockoutActive
	}
	if req.Secrets != nil {
		decision := evaluateServiceSecretsPolicy(service, "writeback", fullRef, req.Secrets)
		_ = b.audit("policy_decision", fullRef, decision.Outcome, service, req.RequestID)
		if decision.Outcome != "allowed" {
			_ = b.audit("writeback_capture", fullRef, "policy_denied", service, req.RequestID)
			if decision, started := b.recordWritebackLockoutFailure(writebackLockoutScope("policy", service, operation, fullRef)); started {
				_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
				response.Outcome = "lockout_active"
				applyWritebackLockout(&response, decision)
				return response, errLockoutActive
			} else if decision.Active {
				_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
				response.Outcome = "lockout_active"
				applyWritebackLockout(&response, decision)
				return response, errLockoutActive
			}
			response.Outcome = "policy_denied"
			return response, errPolicyDenied
		}
	}
	if !namespaceAllowed(namespace, req.Policy.AllowedNamespaces) || !operationAllowed(operation, req.Policy.AllowedOperations) {
		_ = b.audit("writeback_capture", fullRef, "policy_denied", service, req.RequestID)
		if decision, started := b.recordWritebackLockoutFailure(writebackLockoutScope("policy", service, operation, fullRef)); started {
			_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
			response.Outcome = "lockout_active"
			applyWritebackLockout(&response, decision)
			return response, errLockoutActive
		} else if decision.Active {
			_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
			response.Outcome = "lockout_active"
			applyWritebackLockout(&response, decision)
			return response, errLockoutActive
		}
		response.Outcome = "policy_denied"
		return response, errPolicyDenied
	}
	if decision := b.activeWritebackLockout(writebackLockoutScope("source_auth", service, operation, fullRef)); decision.Active {
		_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
		response.Outcome = "lockout_active"
		applyWritebackLockout(&response, decision)
		return response, errLockoutActive
	}
	if req.SourceAuthRequired {
		_ = b.audit("writeback_capture", fullRef, "source_auth_required", service, req.RequestID)
		if decision, started := b.recordWritebackLockoutFailure(writebackLockoutScope("source_auth", service, operation, fullRef)); started {
			_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
			response.Outcome = "lockout_active"
			applyWritebackLockout(&response, decision)
			return response, errLockoutActive
		} else if decision.Active {
			_ = b.audit("writeback_lockout", fullRef, "lockout_active", service, req.RequestID)
			response.Outcome = "lockout_active"
			applyWritebackLockout(&response, decision)
			return response, errLockoutActive
		}
		response.Outcome = "source_auth_required"
		return response, errSourceAuthRequired
	}
	if b.locked() {
		_ = b.audit("writeback_capture", fullRef, "locked", service, req.RequestID)
		response.Outcome = "locked"
		return response, errLocked
	}
	if operation == "delete" {
		store, err := b.loadStore()
		if err != nil {
			_ = b.audit("writeback_capture", fullRef, "degraded", service, req.RequestID)
			response.Outcome = "degraded"
			return response, errBackendDegraded
		}
		delete(store.Secrets, fullRef)
		store.UpdatedAt = b.now()
		if err := b.saveStore(store); err != nil {
			_ = b.audit("writeback_capture", fullRef, "degraded", service, req.RequestID)
			response.Outcome = "degraded"
			return response, errBackendDegraded
		}
		_ = b.audit("writeback_capture", fullRef, "ready", service, req.RequestID)
		response.Outcome = "ready"
		return response, nil
	}

	metadata := map[string]string{"sourceId": firstNonEmpty(req.Metadata["sourceId"], "generated:"+service)}
	written, err := b.writeSecret(writeSecretRequest{Ref: fullRef, Value: req.Value, Metadata: metadata})
	if err != nil {
		if errors.Is(err, errLocked) {
			response.Outcome = "locked"
			return response, err
		}
		if errors.Is(err, errInvalidRef) {
			response.Outcome = "invalid_ref"
			return response, err
		}
		_ = b.audit("writeback_capture", fullRef, "degraded", service, req.RequestID)
		response.Outcome = "degraded"
		return response, errBackendDegraded
	}
	_ = b.audit("writeback_capture", fullRef, "ready", service, req.RequestID)
	response.Outcome = "ready"
	response.Metadata = written.Metadata
	b.recordWritebackLockoutSuccess(writebackLockoutScope("identity", service, operation, fullRef))
	b.recordWritebackLockoutSuccess(writebackLockoutScope("policy", service, operation, fullRef))
	b.recordWritebackLockoutSuccess(writebackLockoutScope("source_auth", service, operation, fullRef))
	return response, nil
}

func writebackLockoutScope(family, service, operation, ref string) string {
	service = strings.TrimSpace(service)
	if service == "" {
		service = "unknown"
	}
	return strings.Join([]string{"writeback", strings.TrimSpace(family), strings.TrimSpace(operation), service, strings.Trim(strings.TrimSpace(ref), "/")}, ":")
}

func (b *localBackend) activeWritebackLockout(scope string) lockoutDecision {
	if b == nil || b.lockouts == nil {
		return lockoutDecision{Scope: scope}
	}
	return b.lockouts.active(scope)
}

func (b *localBackend) recordWritebackLockoutFailure(scope string) (lockoutDecision, bool) {
	if b == nil || b.lockouts == nil {
		return lockoutDecision{Scope: scope}, false
	}
	return b.lockouts.recordFailure(scope)
}

func (b *localBackend) recordWritebackLockoutSuccess(scope string) {
	if b == nil || b.lockouts == nil {
		return
	}
	b.lockouts.recordSuccess(scope)
}

func applyWritebackLockout(res *generatedSecretCaptureResponse, decision lockoutDecision) {
	res.LockoutActive = true
	res.LockoutScope = decision.Scope
	res.RetryAfterSeconds = decision.RetryAfterSeconds
}

func (b *localBackend) resolve(req resolveRequest) resolveResponse {
	results := make([]resolveResult, 0, len(req.Refs))
	if len(req.Refs) == 0 {
		return resolveResponse{ServiceID: serviceID, APIVersion: apiVersion, RequestID: req.RequestID, Results: []resolveResult{}}
	}

	var store localStoreFile
	var storeErr error
	if !b.locked() {
		store, storeErr = b.loadStore()
	}

	for _, rawRef := range req.Refs {
		ref := strings.TrimSpace(rawRef)
		result := resolveResult{Ref: ref}
		switch {
		case !validSecretRef(ref):
			result.Outcome = "invalid_ref"
			result.Message = "Secret ref is invalid."
		case req.Secrets != nil && evaluateServiceSecretsPolicy(req.ServiceID, "resolve", ref, req.Secrets).Outcome != "allowed":
			decision := evaluateServiceSecretsPolicy(req.ServiceID, "resolve", ref, req.Secrets)
			_ = b.auditPolicyDecision(ref, decision, req.RequestID)
			result.Outcome = "policy_denied"
			result.Message = "Service secret policy denied resolve."
			result.PolicyResult = decision.Outcome
			result.NextAction = decision.NextAction
			result.ReasonCode = decision.ReasonCode
		case b.locked():
			result.Outcome = "locked"
			result.Message = "Secrets Broker local store is locked."
		case storeErr != nil:
			result.Outcome = "degraded"
			result.Message = "Local store could not be read."
		default:
			entry, ok := store.Secrets[ref]
			if !ok {
				sourceResult := b.sources.resolve(ref)
				if sourceResult.Found {
					result.Outcome = sourceResult.Outcome
					result.Message = sourceResult.Message
					_ = b.auditSourceLifecycle(ref, sourceResult, req.ServiceID, req.RequestID)
					if sourceResult.Outcome == "ready" {
						result.Value = sourceResult.Value
						result.Metadata = &SecretMetadata{SourceID: sourceResult.SourceID, Version: "source"}
					}
				} else {
					result.Outcome = "missing_ref"
					result.Message = "Secret ref was not found."
				}
			} else if value, err := b.decrypt(entry.Payload); err != nil {
				result.Outcome = "degraded"
				result.Message = "Secret payload could not be decrypted."
			} else {
				metadata := entry.Metadata
				result.Outcome = "ready"
				result.Value = value
				result.Metadata = &metadata
			}
		}
		_ = b.audit("resolve", ref, result.Outcome, req.ServiceID, req.RequestID)
		results = append(results, result)
	}
	return resolveResponse{ServiceID: serviceID, APIVersion: apiVersion, RequestID: req.RequestID, Results: results}
}

func (b *localBackend) loadStore() (localStoreFile, error) {
	now := b.now()
	store := localStoreFile{Version: localStoreVersion, ServiceID: serviceID, CreatedAt: now, UpdatedAt: now, Secrets: map[string]secretEntry{}}
	bytes, err := os.ReadFile(b.storePath)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return store, err
	}
	if len(bytes) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(bytes, &store); err != nil {
		return store, err
	}
	if store.Secrets == nil {
		store.Secrets = map[string]secretEntry{}
	}
	return store, nil
}

func (b *localBackend) saveStore(store localStoreFile) error {
	if err := os.MkdirAll(filepath.Dir(b.storePath), 0o700); err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.storePath, bytes, 0o600)
}

func (b *localBackend) audit(operation, ref, outcome, requestServiceID, requestID string) error {
	return b.writeAuditEvent(auditEvent{TS: b.now(), Operation: operation, Ref: ref, Outcome: outcome, ServiceID: requestServiceID, RequestID: requestID})
}

func (b *localBackend) auditPolicyDecision(ref string, decision secretPolicyDecision, requestID string) error {
	return b.writeAuditEvent(auditEvent{TS: b.now(), Operation: "policy_decision", Ref: ref, Outcome: decision.Outcome, ServiceID: decision.ServiceID, RequestID: requestID, ReasonCode: decision.ReasonCode})
}

func (b *localBackend) auditSourceLifecycle(ref string, result sourceResolveResult, requestServiceID, requestID string) error {
	return b.writeAuditEvent(auditEvent{TS: b.now(), Operation: "source_lifecycle", Ref: ref, Outcome: result.Outcome, State: result.Lifecycle.State, SourceID: result.SourceID, ServiceID: requestServiceID, RequestID: requestID})
}

func (b *localBackend) writeAuditEvent(event auditEvent) error {
	if strings.TrimSpace(b.auditPath) == "" {
		return nil
	}
	event = normalizeAuditEvent(event)
	if b.auditHashChain {
		event = b.prepareChainedAuditEvent(event)
	}
	if err := os.MkdirAll(filepath.Dir(b.auditPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(b.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(event); err != nil {
		return err
	}
	return b.writeOperationalEvent(event)
}

func normalizeAuditEvent(event auditEvent) auditEvent {
	event.Operation = scrubAuditField(event.Operation)
	event.Ref = scrubAuditField(event.Ref)
	event.Outcome = scrubAuditField(event.Outcome)
	event.State = scrubAuditField(event.State)
	event.SourceID = scrubAuditField(event.SourceID)
	event.PolicyID = scrubAuditField(event.PolicyID)
	event.KeyID = scrubAuditField(event.KeyID)
	event.ServiceID = scrubAuditField(event.ServiceID)
	event.RequestID = scrubAuditField(event.RequestID)
	event.ProviderID = scrubAuditField(event.ProviderID)
	event.ReasonCode = scrubAuditField(event.ReasonCode)
	event.ActorKind = scrubAuditField(event.ActorKind)
	event.AuditStatus = scrubAuditField(event.AuditStatus)
	event.PreviousHash = scrubAuditField(event.PreviousHash)
	event.EventHash = scrubAuditField(event.EventHash)
	event.ChainStatus = scrubAuditField(event.ChainStatus)
	if event.Operation == "" {
		event.Operation = "unknown"
	}
	if event.Outcome == "" {
		event.Outcome = "degraded"
	}
	if event.ReasonCode == "" {
		event.ReasonCode = event.Outcome
	}
	if event.ActorKind == "" {
		event.ActorKind = actorKindForAudit(event.ServiceID)
	}
	if event.AuditStatus == "" {
		event.AuditStatus = "audit_recorded"
	}
	if event.Ref != "" && event.RefHash == "" {
		event.RefHash = hashAuditRef(event.Ref)
	}
	if event.ProviderID == "" && strings.HasPrefix(event.Operation, "provider_") && event.Ref != "" {
		event.ProviderID = event.Ref
	}
	return event
}

func scrubAuditField(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > 256 {
		return value[:256]
	}
	return strings.Join(strings.Fields(value), " ")
}

func hashAuditRef(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func actorKindForAudit(serviceID string) string {
	switch strings.TrimSpace(serviceID) {
	case "":
		return "system"
	case "@operator":
		return "operator"
	default:
		return "service"
	}
}

func (b *localBackend) encrypt(value string) (secretPayload, error) {
	block, err := aes.NewCipher(b.key())
	if err != nil {
		return secretPayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return secretPayload{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return secretPayload{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	return secretPayload{Alg: "AES-256-GCM", KeyID: masterKeyID(b.masterKey), KeyVersion: masterKeyVersion, Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}, nil
}

func (b *localBackend) decrypt(payload secretPayload) (string, error) {
	if payload.Alg != "AES-256-GCM" {
		return "", fmt.Errorf("unsupported payload algorithm %q", payload.Alg)
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(b.key())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (b *localBackend) key() []byte {
	sum := sha256.Sum256([]byte(b.masterKey))
	return sum[:]
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func registerLocalStoreHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/secrets.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req writeSecretRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		res, err := backend.writeSecret(req)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, res)
		case errors.Is(err, errInvalidRef):
			writeAPIError(w, http.StatusBadRequest, "invalid_ref", "Secret ref is invalid.", "invalid_ref", "")
		case errors.Is(err, errLocked):
			writeAPIError(w, http.StatusServiceUnavailable, "locked", "Secrets Broker local store is locked.", "locked", "unlock_broker")
		default:
			writeAPIError(w, http.StatusInternalServerError, "store_error", "Local store write failed.", "degraded", "inspect_sources")
		}
	})

	mux.HandleFunc("/v1/writeback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/writeback.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req generatedSecretCaptureRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		peer := transportPeerIdentityFromContext(r.Context())
		if err := backend.authorizeWritebackLaunchLease(&req, firstNonEmpty(backend.launchIdentitySigningKey, security.token), peer); err != nil {
			writeLaunchIdentityAPIError(w, err)
			return
		}
		res, err := backend.captureGeneratedSecret(req)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, res)
		case errors.Is(err, errInvalidRef):
			writeAPIError(w, http.StatusBadRequest, "invalid_ref", "Generated secret write-back ref is invalid.", "invalid_ref", "")
		case errors.Is(err, errIdentityExpired):
			writeAPIError(w, http.StatusUnauthorized, "identity_expired", "Launch identity is missing, invalid, or expired.", "identity_expired", "renew_launch_identity")
		case errors.Is(err, errPolicyDenied):
			writeAPIError(w, http.StatusForbidden, "policy_denied", "Write-back policy denied this generated secret capture.", "policy_denied", "review_policy")
		case errors.Is(err, errSourceAuthRequired):
			writeAPIError(w, http.StatusFailedDependency, "source_auth_required", "Source authentication is required before write-back can proceed.", "source_auth_required", "reconnect_source")
		case errors.Is(err, errLockoutActive):
			writeScopedLockoutAPIError(w, res.LockoutScope, res.RetryAfterSeconds, "Write-back is temporarily locked for this scope.")
		case errors.Is(err, errLocked):
			writeAPIError(w, http.StatusServiceUnavailable, "locked", "Secrets Broker local store is locked.", "locked", "unlock_broker")
		default:
			writeAPIError(w, http.StatusServiceUnavailable, "degraded", "Write-back backend is degraded.", "degraded", "inspect_sources")
		}
	})

	mux.HandleFunc("/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/resolve.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req resolveRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		peer := transportPeerIdentityFromContext(r.Context())
		if err := backend.authorizeResolveLaunchLease(&req, firstNonEmpty(backend.launchIdentitySigningKey, security.token), peer); err != nil {
			writeLaunchIdentityAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, backend.resolve(req))
	})
}

func decodeSecretBearingJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretBearingRequestBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request body exceeds the local API size limit.", "policy_denied", "reduce_request_size")
		return
	}
	writeAPIError(w, http.StatusBadRequest, "invalid_request", "Request body is not valid JSON.", "invalid_ref", "")
}

func writeAPIError(w http.ResponseWriter, status int, code, message, outcome, nextAction string) {
	writeJSON(w, status, ErrorEnvelope{Error: APIError{Code: code, Message: message, Outcome: outcome, NextAction: nextAction, AffectedRefs: []string{}, AffectedServices: []string{}}})
}

func writeLaunchIdentityAPIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errIdentityExpired):
		writeAPIError(w, http.StatusUnauthorized, "identity_expired", "Launch identity lease is expired.", "identity_expired", "renew_launch_identity")
	case errors.Is(err, errIdentityReplayed):
		writeAPIError(w, http.StatusUnauthorized, "identity_replayed", "Launch identity lease has already been used.", "identity_replayed", "renew_launch_identity")
	case errors.Is(err, errPolicyDenied):
		writeAPIError(w, http.StatusForbidden, "policy_denied", "Launch identity lease does not allow this request.", "policy_denied", "renew_launch_identity")
	default:
		writeAPIError(w, http.StatusUnauthorized, "identity_invalid", "Launch identity lease is missing or invalid.", "identity_invalid", "renew_launch_identity")
	}
}
