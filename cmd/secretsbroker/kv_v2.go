package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	kvV2MaxVersions     = 10
	kvV2DefaultMount    = "secret"
	kvV2MaxPathBytes    = 2048
	kvV2MaxRequestBytes = 64 * 1024
	kvV2ProxyTimeout    = 8 * time.Second
)

var (
	errKVConflict = errors.New("kv check-and-set parameter did not match the current version")
	errKVDeleted  = errors.New("kv version is deleted")
	errKVNotFound = errors.New("kv path was not found")
)

type kvSecretState struct {
	Current  int               `json:"current"`
	Versions []kvVersionRecord `json:"versions"`
}

type kvVersionRecord struct {
	Version      int           `json:"version"`
	CreatedTime  time.Time     `json:"createdTime"`
	DeletionTime string        `json:"deletionTime,omitempty"`
	Destroyed    bool          `json:"destroyed"`
	Payload      secretPayload `json:"payload"`
}

type kvWriteEnvelope struct {
	Data    map[string]any  `json:"data"`
	Options *kvWriteOptions `json:"options"`
}

type kvWriteOptions struct {
	CAS *int `json:"cas"`
}

type kvVersionSelectRequest struct {
	Versions []int `json:"versions"`
}

type kvDataResponse struct {
	Data kvDataBody `json:"data"`
}

type kvDataBody struct {
	Data     map[string]string `json:"data"`
	Metadata kvVersionMetadata `json:"metadata"`
}

type kvVersionMetadata struct {
	CreatedTime    string `json:"created_time"`
	DeletionTime   string `json:"deletion_time"`
	Destroyed      bool   `json:"destroyed"`
	Version        int    `json:"version"`
	CustomMetadata any    `json:"custom_metadata"`
}

type kvWriteResponse struct {
	Data kvVersionMetadata `json:"data"`
}

type kvMetadataResponse struct {
	Data kvMetadataBody `json:"data"`
}

type kvMetadataBody struct {
	CASRequired        bool                       `json:"cas_required"`
	CreatedTime        string                     `json:"created_time"`
	CurrentVersion     int                        `json:"current_version"`
	DeleteVersionAfter string                     `json:"delete_version_after"`
	MaxVersions        int                        `json:"max_versions"`
	OldestVersion      int                        `json:"oldest_version"`
	UpdatedTime        string                     `json:"updated_time"`
	CustomMetadata     any                        `json:"custom_metadata"`
	Versions           map[string]kvListedVersion `json:"versions"`
}

type kvListedVersion struct {
	CreatedTime  string `json:"created_time"`
	DeletionTime string `json:"deletion_time"`
	Destroyed    bool   `json:"destroyed"`
}

type kvListResponse struct {
	Data kvListBody `json:"data"`
}

type kvListBody struct {
	Keys []string `json:"keys"`
}

type kvErrorResponse struct {
	Errors []string `json:"errors"`
}

type kvNoContentResponse struct{}

func registerKVHandlers(mux *http.ServeMux, backend *localBackend, security localAPISecurity) {
	mux.HandleFunc("/v1/kv/data/", func(w http.ResponseWriter, r *http.Request) {
		backend.serveKVData(w, r, security)
	})
	mux.HandleFunc("/v1/kv/metadata/", func(w http.ResponseWriter, r *http.Request) {
		backend.serveKVMetadata(w, r, security)
	})
	mux.HandleFunc("/v1/kv/metadata", func(w http.ResponseWriter, r *http.Request) {
		backend.serveKVMetadata(w, r, security)
	})
	mux.HandleFunc("/v1/kv/delete/", func(w http.ResponseWriter, r *http.Request) {
		backend.serveKVDelete(w, r, security, false)
	})
	mux.HandleFunc("/v1/kv/undelete/", func(w http.ResponseWriter, r *http.Request) {
		backend.serveKVDelete(w, r, security, true)
	})
}

func (b *localBackend) serveKVData(w http.ResponseWriter, r *http.Request, security localAPISecurity) {
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPatch:
	default:
		writeKVErrors(w, http.StatusMethodNotAllowed, "Use GET, POST, or PATCH /v1/kv/data/{path}.")
		return
	}
	if !security.require(w, r) {
		return
	}
	path, sourceID, mount, err := parseKVRequest(r, "/v1/kv/data/")
	if err != nil {
		writeKVErrors(w, http.StatusBadRequest, err.Error())
		return
	}
	if path == "" {
		writeKVErrors(w, http.StatusBadRequest, "kv data path is required")
		return
	}
	if handled := b.proxyRemoteKV(w, r, sourceID, mount, "data", path); handled {
		return
	}
	switch r.Method {
	case http.MethodGet:
		version := kvQueryVersion(r)
		body, err := b.readLocalKVData(path, version)
		if err != nil {
			writeKVStoreError(w, err)
			return
		}
		_ = b.audit("kv-read", path, "ready", "", "")
		writeJSON(w, http.StatusOK, body)
	case http.MethodPost, http.MethodPatch:
		var req kvWriteEnvelope
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		if req.Data == nil {
			writeKVErrors(w, http.StatusBadRequest, "missing data")
			return
		}
		fields := kvStringMap(req.Data)
		var cas *int
		if req.Options != nil {
			cas = req.Options.CAS
		}
		meta, err := b.writeLocalKVData(path, fields, cas, r.Method == http.MethodPatch)
		if err != nil {
			writeKVStoreError(w, err)
			return
		}
		operation := "kv-write"
		if r.Method == http.MethodPatch {
			operation = "kv-patch"
		}
		_ = b.audit(operation, path, "ready", "", "")
		writeJSON(w, http.StatusOK, kvWriteResponse{Data: meta})
	}
}

func (b *localBackend) serveKVMetadata(w http.ResponseWriter, r *http.Request, security localAPISecurity) {
	if r.Method != http.MethodGet && !strings.EqualFold(r.Method, "LIST") {
		writeKVErrors(w, http.StatusMethodNotAllowed, "Use GET or LIST /v1/kv/metadata/{path}.")
		return
	}
	if !security.require(w, r) {
		return
	}
	path, sourceID, mount, err := parseKVRequest(r, "/v1/kv/metadata/")
	if err != nil {
		writeKVErrors(w, http.StatusBadRequest, err.Error())
		return
	}
	if handled := b.proxyRemoteKV(w, r, sourceID, mount, "metadata", path); handled {
		return
	}
	if kvWantsList(r) {
		keys, err := b.listLocalKVKeys(path)
		if err != nil {
			writeKVStoreError(w, err)
			return
		}
		if len(keys) == 0 {
			writeKVErrors(w, http.StatusNotFound, "no keys found")
			return
		}
		_ = b.audit("kv-list", path, "ready", "", "")
		writeJSON(w, http.StatusOK, kvListResponse{Data: kvListBody{Keys: keys}})
		return
	}
	if path == "" {
		writeKVErrors(w, http.StatusBadRequest, "kv metadata path is required")
		return
	}
	body, err := b.readLocalKVMetadata(path)
	if err != nil {
		writeKVStoreError(w, err)
		return
	}
	_ = b.audit("kv-metadata", path, "ready", "", "")
	writeJSON(w, http.StatusOK, body)
}

func (b *localBackend) serveKVDelete(w http.ResponseWriter, r *http.Request, security localAPISecurity, undelete bool) {
	if r.Method != http.MethodPost {
		action := "/v1/kv/delete/{path}"
		if undelete {
			action = "/v1/kv/undelete/{path}"
		}
		writeKVErrors(w, http.StatusMethodNotAllowed, "Use POST "+action+".")
		return
	}
	if !security.require(w, r) {
		return
	}
	prefix := "/v1/kv/delete/"
	op := "delete"
	auditName := "kv-delete"
	if undelete {
		prefix = "/v1/kv/undelete/"
		op = "undelete"
		auditName = "kv-undelete"
	}
	path, sourceID, mount, err := parseKVRequest(r, prefix)
	if err != nil {
		writeKVErrors(w, http.StatusBadRequest, err.Error())
		return
	}
	if path == "" {
		writeKVErrors(w, http.StatusBadRequest, "kv path is required")
		return
	}
	if handled := b.proxyRemoteKV(w, r, sourceID, mount, op, path); handled {
		return
	}
	var req kvVersionSelectRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
	}
	if err := b.mutateLocalKVVersions(path, req.Versions, undelete); err != nil {
		writeKVStoreError(w, err)
		return
	}
	_ = b.audit(auditName, path, "ready", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (b *localBackend) proxyRemoteKV(w http.ResponseWriter, r *http.Request, sourceID, mount, op, path string) bool {
	if sourceID == "local" {
		return false
	}
	source, ok := b.kvRemoteSource(sourceID)
	if !ok {
		writeKVErrors(w, http.StatusBadRequest, "unknown kv source")
		return true
	}
	kind := strings.ToLower(strings.TrimSpace(source.Kind))
	if kind != "vault" && kind != "openbao" {
		writeKVErrors(w, http.StatusBadRequest, "kv source is not Vault or OpenBao")
		return true
	}
	if !source.Enabled {
		writeKVErrors(w, http.StatusBadRequest, "kv source is disabled")
		return true
	}
	status, body, err := b.forwardOpenBaoKV(source, r.Method, mount, op, path, r)
	if err != nil {
		writeKVStoreError(w, err)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !json.Valid(body) {
		writeKVStoreError(w, errBackendDegraded)
		return true
	}
	w.WriteHeader(status)
	_, _ = w.Write(body) // #nosec G705 -- the body is valid JSON and is served with nosniff immediately above.
	return true
}

func (b *localBackend) kvRemoteSource(sourceID string) (sourceConfig, bool) {
	for _, source := range b.sources.Sources {
		if source.SourceID == sourceID {
			return source, true
		}
	}
	return sourceConfig{}, false
}

func (b *localBackend) forwardOpenBaoKV(source sourceConfig, method, mount, op, path string, incoming *http.Request) (int, []byte, error) {
	baseURL, err := validatedVaultKVBaseURL(source.Address)
	if err != nil {
		return 0, nil, errInvalidRef
	}
	token := strings.TrimSpace(firstNonEmpty(source.Token, os.Getenv(source.TokenEnv)))
	if token == "" {
		return 0, nil, errSourceAuthRequired
	}
	if strings.TrimSpace(source.Mount) != "" && mount == kvV2DefaultMount {
		mount = strings.TrimSpace(source.Mount)
	}
	if !validKVMount(mount) {
		return 0, nil, errInvalidRef
	}
	endpoint := baseURL
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "LIST" {
		method = http.MethodGet
	}
	trimmedPath := strings.Trim(path, "/")
	if trimmedPath == "" {
		endpoint.Path = "/v1/" + mount + "/" + op
	} else {
		endpoint.Path = "/v1/" + mount + "/" + op + "/" + trimmedPath
	}
	query := endpoint.Query()
	if incoming != nil {
		if version := strings.TrimSpace(incoming.URL.Query().Get("version")); version != "" {
			query.Set("version", version)
		}
		if kvWantsList(incoming) {
			query.Set("list", "true")
		}
	}
	endpoint.RawQuery = query.Encode()
	var bodyReader io.Reader
	if incoming != nil && incoming.Body != nil && (method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut) {
		limited, err := io.ReadAll(io.LimitReader(incoming.Body, kvV2MaxRequestBytes+1))
		if err != nil {
			return 0, nil, errInvalidRef
		}
		if len(limited) > kvV2MaxRequestBytes {
			return 0, nil, errInvalidRef
		}
		bodyReader = bytes.NewReader(limited)
	}
	ctx, cancel := context.WithTimeout(context.Background(), kvV2ProxyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bodyReader)
	if err != nil {
		return 0, nil, errInvalidRef
	}
	req.Header.Set("X-Vault-Token", token)
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client, err := newSourceHTTPClient(kvV2ProxyTimeout, source.Production, rejectCredentialRedirect)
	if err != nil {
		return 0, nil, errInvalidRef
	}
	res, err := client.Do(req) // #nosec G704 -- validatedVaultKVBaseURL restricts the protected provider endpoint and redirects are disabled.
	if err != nil {
		return 0, nil, errBackendDegraded
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, kvV2MaxRequestBytes+1))
	if err != nil || len(body) > kvV2MaxRequestBytes {
		return 0, nil, errBackendDegraded
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	return res.StatusCode, body, nil
}

func (b *localBackend) readLocalKVData(path string, version int) (kvDataResponse, error) {
	if b.locked() {
		return kvDataResponse{}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		return kvDataResponse{}, err
	}
	entry, ok := store.Secrets[path]
	if !ok {
		return kvDataResponse{}, errKVNotFound
	}
	record, data, err := b.localKVVersion(entry, version)
	if err != nil {
		return kvDataResponse{}, err
	}
	if strings.TrimSpace(record.DeletionTime) != "" || record.Destroyed {
		return kvDataResponse{}, errKVDeleted
	}
	return kvDataResponse{Data: kvDataBody{Data: data, Metadata: kvMetadataFromRecord(record)}}, nil
}

func (b *localBackend) readLocalKVMetadata(path string) (kvMetadataResponse, error) {
	if b.locked() {
		return kvMetadataResponse{}, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		return kvMetadataResponse{}, err
	}
	entry, ok := store.Secrets[path]
	if !ok {
		return kvMetadataResponse{}, errKVNotFound
	}
	state := localKVState(entry)
	versions := map[string]kvListedVersion{}
	oldest := 0
	for _, record := range state.Versions {
		if oldest == 0 || record.Version < oldest {
			oldest = record.Version
		}
		versions[strconv.Itoa(record.Version)] = kvListedVersion{
			CreatedTime:  record.CreatedTime.UTC().Format(time.RFC3339Nano),
			DeletionTime: record.DeletionTime,
			Destroyed:    record.Destroyed,
		}
	}
	return kvMetadataResponse{Data: kvMetadataBody{
		CreatedTime:        entry.Metadata.CreatedAt.UTC().Format(time.RFC3339Nano),
		CurrentVersion:     state.Current,
		DeleteVersionAfter: "0s",
		MaxVersions:        kvV2MaxVersions,
		OldestVersion:      oldest,
		UpdatedTime:        entry.Metadata.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Versions:           versions,
	}}, nil
}

func (b *localBackend) listLocalKVKeys(prefix string) ([]string, error) {
	if b.locked() {
		return nil, errLocked
	}
	store, err := b.loadStore()
	if err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(store.Secrets))
	for ref := range store.Secrets {
		refs = append(refs, ref)
	}
	return kvChildKeys(refs, prefix), nil
}

func (b *localBackend) writeLocalKVData(path string, data map[string]string, cas *int, patch bool) (kvVersionMetadata, error) {
	if b.locked() {
		return kvVersionMetadata{}, errLocked
	}
	if !validSecretRef(path) {
		return kvVersionMetadata{}, errInvalidRef
	}
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	store, err := b.loadStore()
	if err != nil {
		return kvVersionMetadata{}, err
	}
	now := b.now()
	existing, exists := store.Secrets[path]
	fields := data
	if patch {
		if !exists {
			return kvVersionMetadata{}, errKVNotFound
		}
		current, currentData, err := b.localKVVersion(existing, 0)
		if err != nil {
			return kvVersionMetadata{}, err
		}
		if strings.TrimSpace(current.DeletionTime) != "" || current.Destroyed {
			return kvVersionMetadata{}, errKVDeleted
		}
		merged := map[string]string{}
		for key, value := range currentData {
			merged[key] = value
		}
		for key, value := range data {
			merged[key] = value
		}
		fields = merged
	}
	plaintext, err := kvPayloadPlaintext(fields)
	if err != nil {
		return kvVersionMetadata{}, errInvalidRef
	}
	payload, err := b.encrypt(plaintext)
	if err != nil {
		return kvVersionMetadata{}, err
	}
	kv, err := b.appendLocalKVVersion(existing, fields, payload, now, cas)
	if err != nil {
		return kvVersionMetadata{}, err
	}
	metadata := SecretMetadata{SourceID: localStoreSource, Version: now.Format(time.RFC3339Nano), CreatedAt: now, UpdatedAt: now}
	if exists {
		metadata.CreatedAt = existing.Metadata.CreatedAt
	}
	store.Secrets[path] = secretEntry{Ref: path, Metadata: metadata, Payload: payload, KV: kv}
	store.UpdatedAt = now
	if err := b.saveStore(store); err != nil {
		return kvVersionMetadata{}, err
	}
	return kvMetadataFromRecord(kv.Versions[len(kv.Versions)-1]), nil
}

func (b *localBackend) mutateLocalKVVersions(path string, versions []int, undelete bool) error {
	if b.locked() {
		return errLocked
	}
	if !validSecretRef(path) {
		return errInvalidRef
	}
	b.storeMutationMu.Lock()
	defer b.storeMutationMu.Unlock()
	store, err := b.loadStore()
	if err != nil {
		return err
	}
	entry, ok := store.Secrets[path]
	if !ok {
		return errKVNotFound
	}
	state := localKVState(entry)
	if len(versions) == 0 {
		versions = []int{state.Current}
	}
	now := b.now()
	selected := map[int]bool{}
	for _, version := range versions {
		selected[version] = true
	}
	found := 0
	for index, record := range state.Versions {
		if !selected[record.Version] {
			continue
		}
		found++
		if undelete {
			state.Versions[index].DeletionTime = ""
			continue
		}
		if strings.TrimSpace(record.DeletionTime) == "" {
			state.Versions[index].DeletionTime = now.UTC().Format(time.RFC3339Nano)
		}
	}
	if found == 0 {
		return errKVNotFound
	}
	entry.KV = &state
	entry.Metadata.UpdatedAt = now
	store.Secrets[path] = entry
	store.UpdatedAt = now
	return b.saveStore(store)
}

func (b *localBackend) appendLocalKVVersion(existing secretEntry, _ map[string]string, payload secretPayload, now time.Time, cas *int) (*kvSecretState, error) {
	state := localKVState(existing)
	if existing.Ref == "" && existing.Payload.Ciphertext == "" && state.Current == 0 {
		if cas != nil && *cas != 0 {
			return nil, errKVConflict
		}
		record := kvVersionRecord{Version: 1, CreatedTime: now, Payload: payload}
		return &kvSecretState{Current: 1, Versions: []kvVersionRecord{record}}, nil
	}
	if cas != nil && *cas != state.Current {
		return nil, errKVConflict
	}
	next := state.Current + 1
	if next == 1 && existing.Payload.Ciphertext != "" && len(state.Versions) == 0 {
		state.Versions = []kvVersionRecord{{
			Version:     1,
			CreatedTime: existing.Metadata.CreatedAt,
			Payload:     existing.Payload,
		}}
		state.Current = 1
		next = 2
		if cas != nil && *cas != 1 && *cas != 0 {
			return nil, errKVConflict
		}
		if cas != nil && *cas == 0 {
			return nil, errKVConflict
		}
	}
	state.Current = next
	state.Versions = append(state.Versions, kvVersionRecord{Version: next, CreatedTime: now, Payload: payload})
	if len(state.Versions) > kvV2MaxVersions {
		state.Versions = state.Versions[len(state.Versions)-kvV2MaxVersions:]
	}
	return &state, nil
}

func (b *localBackend) localKVVersion(entry secretEntry, version int) (kvVersionRecord, map[string]string, error) {
	state := localKVState(entry)
	if version <= 0 {
		version = state.Current
	}
	for _, record := range state.Versions {
		if record.Version != version {
			continue
		}
		plaintext, err := b.decrypt(record.Payload)
		if err != nil {
			return kvVersionRecord{}, nil, err
		}
		return record, kvDataFromPlaintext(plaintext), nil
	}
	if version == 1 || (version == 0 && state.Current <= 1) {
		plaintext, err := b.decrypt(entry.Payload)
		if err != nil {
			return kvVersionRecord{}, nil, err
		}
		record := kvVersionRecord{Version: 1, CreatedTime: entry.Metadata.CreatedAt, Payload: entry.Payload}
		return record, kvDataFromPlaintext(plaintext), nil
	}
	return kvVersionRecord{}, nil, errKVNotFound
}

func localKVState(entry secretEntry) kvSecretState {
	if entry.KV != nil && len(entry.KV.Versions) > 0 {
		return *entry.KV
	}
	if entry.Payload.Ciphertext == "" {
		return kvSecretState{}
	}
	version := 1
	return kvSecretState{
		Current: version,
		Versions: []kvVersionRecord{{
			Version:     version,
			CreatedTime: entry.Metadata.CreatedAt,
			Payload:     entry.Payload,
		}},
	}
}

func kvMetadataFromRecord(record kvVersionRecord) kvVersionMetadata {
	return kvVersionMetadata{
		CreatedTime:  record.CreatedTime.UTC().Format(time.RFC3339Nano),
		DeletionTime: record.DeletionTime,
		Destroyed:    record.Destroyed,
		Version:      record.Version,
	}
}

func parseKVRequest(r *http.Request, prefix string) (path, sourceID, mount string, err error) {
	raw := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(prefix, "/"))
	path = strings.Trim(raw, "/")
	if strings.Contains(path, "{path}") {
		path = strings.Trim(strings.ReplaceAll(path, "{path}", ""), "/")
	}
	if len(path) > kvV2MaxPathBytes {
		return "", "", "", errInvalidRef
	}
	if path != "" && !validSecretRef(path) && !kvWantsList(r) {
		return "", "", "", errInvalidRef
	}
	if path != "" && kvWantsList(r) {
		trimmed := strings.Trim(path, "/")
		if trimmed != "" && !validSecretRef(trimmed) {
			return "", "", "", errInvalidRef
		}
		path = trimmed
	}
	sourceID = strings.TrimSpace(r.URL.Query().Get("source"))
	switch sourceID {
	case "", "local", "local-encrypted-store":
		sourceID = "local"
	}
	mount = strings.TrimSpace(r.URL.Query().Get("mount"))
	if mount == "" {
		mount = kvV2DefaultMount
	}
	if !validKVMount(mount) {
		return "", "", "", errInvalidRef
	}
	return path, sourceID, mount, nil
}

func kvWantsList(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.EqualFold(r.Method, "LIST") {
		return true
	}
	value := strings.TrimSpace(r.URL.Query().Get("list"))
	return value == "true" || value == "1"
}

func kvQueryVersion(r *http.Request) int {
	raw := strings.TrimSpace(r.URL.Query().Get("version"))
	if raw == "" {
		return 0
	}
	version, err := strconv.Atoi(raw)
	if err != nil || version < 0 {
		return 0
	}
	return version
}

func validKVMount(mount string) bool {
	mount = strings.TrimSpace(mount)
	if mount == "" || len(mount) > 64 || strings.ContainsAny(mount, "/\\?#") {
		return false
	}
	for _, r := range mount {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func kvChildKeys(refs []string, prefix string) []string {
	normalized := strings.Trim(prefix, "/")
	if normalized != "" {
		normalized += "/"
	}
	seen := map[string]struct{}{}
	keys := make([]string, 0)
	for _, ref := range refs {
		if normalized != "" && !strings.HasPrefix(ref, normalized) {
			continue
		}
		rest := strings.TrimPrefix(ref, normalized)
		if rest == "" {
			continue
		}
		name, _, found := strings.Cut(rest, "/")
		key := name
		if found {
			key = name + "/"
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func kvStringMap(data map[string]any) map[string]string {
	out := map[string]string{}
	for key, value := range data {
		out[key] = kvStringify(value)
	}
	return out
}

func kvStringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(encoded)
	}
}

func kvPayloadPlaintext(data map[string]string) (string, error) {
	if len(data) == 1 {
		if value, ok := data["value"]; ok {
			return value, nil
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func kvDataFromPlaintext(plaintext string) map[string]string {
	trimmed := strings.TrimSpace(plaintext)
	if strings.HasPrefix(trimmed, "{") {
		var raw map[string]any
		if json.Unmarshal([]byte(trimmed), &raw) == nil && raw != nil {
			return kvStringMap(raw)
		}
	}
	return map[string]string{"value": plaintext}
}

func writeKVErrors(w http.ResponseWriter, status int, messages ...string) {
	if len(messages) == 0 {
		messages = []string{"kv request failed"}
	}
	writeJSON(w, status, kvErrorResponse{Errors: messages})
}

func writeKVStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidRef):
		writeKVErrors(w, http.StatusBadRequest, "invalid path")
	case errors.Is(err, errKVConflict):
		writeKVErrors(w, http.StatusBadRequest, "check-and-set parameter did not match the current version")
	case errors.Is(err, errKVNotFound), errors.Is(err, errMissingRef):
		writeKVErrors(w, http.StatusNotFound, "no data found")
	case errors.Is(err, errKVDeleted):
		writeKVErrors(w, http.StatusNotFound, "no data for version")
	case errors.Is(err, errLocked):
		writeAPIError(w, http.StatusServiceUnavailable, "locked", "Secrets Broker local store is locked.", "locked", "unlock_broker")
	case errors.Is(err, errSourceAuthRequired):
		writeAPIError(w, http.StatusFailedDependency, "source_auth_required", "Vault or OpenBao token is missing.", "source_auth_required", "reconnect_source")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "degraded", "KV backend is unavailable.", "degraded", "inspect_sources")
	}
}
