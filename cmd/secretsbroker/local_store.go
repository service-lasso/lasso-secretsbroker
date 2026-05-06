package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	localStoreVersion = 1
	localStoreSource  = "local"
)

var (
	errLocked     = errors.New("secrets broker store is locked")
	errMissingRef = errors.New("secret ref was not found")
	errInvalidRef = errors.New("invalid secret ref")
)

type localBackend struct {
	storePath string
	auditPath string
	masterKey string
	now       func() time.Time
}

type localStoreFile struct {
	Version   int                    `json:"version"`
	ServiceID string                 `json:"serviceId"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
	Secrets   map[string]secretEntry `json:"secrets"`
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

type resolveRequest struct {
	RequestID   string   `json:"requestId"`
	WorkspaceID string   `json:"workspaceId"`
	ServiceID   string   `json:"serviceId"`
	Purpose     string   `json:"purpose"`
	Refs        []string `json:"refs"`
}

type resolveResponse struct {
	ServiceID  string          `json:"serviceId"`
	APIVersion string          `json:"apiVersion"`
	RequestID  string          `json:"requestId,omitempty"`
	Results    []resolveResult `json:"results"`
}

type resolveResult struct {
	Ref      string          `json:"ref"`
	Outcome  string          `json:"outcome"`
	Value    string          `json:"value,omitempty"`
	Metadata *SecretMetadata `json:"metadata,omitempty"`
	Message  string          `json:"message,omitempty"`
}

type auditEvent struct {
	TS        time.Time `json:"ts"`
	Operation string    `json:"operation"`
	Ref       string    `json:"ref,omitempty"`
	Outcome   string    `json:"outcome"`
	ServiceID string    `json:"serviceId,omitempty"`
	RequestID string    `json:"requestId,omitempty"`
}

func newLocalBackend(storePath, auditPath, masterKey string) *localBackend {
	return &localBackend{storePath: storePath, auditPath: auditPath, masterKey: masterKey, now: func() time.Time { return time.Now().UTC() }}
}

func defaultStorePath() string { return filepath.Join("data", "secretsbroker-store.json") }
func defaultAuditPath() string { return filepath.Join("data", "secretsbroker-audit.jsonl") }

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
		case b.locked():
			result.Outcome = "locked"
			result.Message = "Secrets Broker local store is locked."
		case storeErr != nil:
			result.Outcome = "degraded"
			result.Message = "Local store could not be read."
		default:
			entry, ok := store.Secrets[ref]
			if !ok {
				result.Outcome = "missing_ref"
				result.Message = "Secret ref was not found."
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
	if strings.TrimSpace(b.auditPath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.auditPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(b.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(auditEvent{TS: b.now(), Operation: operation, Ref: ref, Outcome: outcome, ServiceID: requestServiceID, RequestID: requestID})
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

func registerLocalStoreHandlers(mux *http.ServeMux, backend *localBackend) {
	mux.HandleFunc("/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/secrets.", "invalid_ref", "")
			return
		}
		var req writeSecretRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_request", "Request body is not valid JSON.", "invalid_ref", "")
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

	mux.HandleFunc("/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST /v1/resolve.", "invalid_ref", "")
			return
		}
		var req resolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_request", "Request body is not valid JSON.", "invalid_ref", "")
			return
		}
		writeJSON(w, http.StatusOK, backend.resolve(req))
	})
}

func writeAPIError(w http.ResponseWriter, status int, code, message, outcome, nextAction string) {
	writeJSON(w, status, ErrorEnvelope{Error: APIError{Code: code, Message: message, Outcome: outcome, NextAction: nextAction, AffectedRefs: []string{}, AffectedServices: []string{}}})
}
