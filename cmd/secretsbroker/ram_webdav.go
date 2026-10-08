package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxRAMFileBytes = 256 << 10
const maxRAMGrantBytes = 768 << 10
const maxRAMStoreBytes = 64 << 20
const maxRAMGrants = 1024

type ramFileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
type ramGrantRequest struct {
	RequestID     string               `json:"requestId"`
	WorkspaceID   string               `json:"workspaceId"`
	ServiceID     string               `json:"serviceId"`
	IdentityLease *launchIdentityLease `json:"identityLease"`
	InstanceID    string               `json:"instanceId"`
	Files         []ramFileInput       `json:"files"`
	Bindings      []ramSecretBinding   `json:"bindings,omitempty"`
}
type ramSecretBinding struct {
	Selector string `json:"selector"`
	Ref      string `json:"ref"`
	Required bool   `json:"required"`
}
type ramRevokeRequest struct {
	Token string `json:"token"`
}
type ramGrantResponse struct {
	BaseURL   string `json:"baseUrl"`
	Token     string `json:"token"`
	Directory string `json:"directory"`
}
type ramGrant struct {
	owner    string
	id       string
	identity ramFileOwner
	usage    map[string]*ramFileUsage
	files    map[string][]byte
	size     int
	created  time.Time
}
type ramFileStore struct {
	closed  bool
	mu      sync.RWMutex
	grants  map[[32]byte]*ramGrant
	owners  map[string][32]byte
	bytes   int
	baseURL string
}

func newRAMFileStore() *ramFileStore {
	return &ramFileStore{grants: make(map[[32]byte]*ramGrant), owners: make(map[string][32]byte)}
}

// Paths are portable DAV names, never filesystem paths. No normalization may
// turn an untrusted alias into an accepted name.
func validRAMFilePath(p string) bool {
	if len(p) == 0 || len(p) > 512 || strings.ContainsAny(p, "\\:%?#\x00") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (s *ramFileStore) create(owner string, inputs []ramFileInput, identities ...ramFileOwner) (ramGrantResponse, error) {
	if owner == "" || len(inputs) == 0 || len(inputs) > 128 {
		return ramGrantResponse{}, errors.New("invalid file grant")
	}
	files := make(map[string][]byte)
	total := 0
	for _, f := range inputs {
		if !validRAMFilePath(f.Path) || len(f.Content) > maxRAMFileBytes {
			return ramGrantResponse{}, errors.New("invalid file grant")
		}
		if _, ok := files[f.Path]; ok {
			return ramGrantResponse{}, errors.New("duplicate file")
		}
		for p := range files {
			if strings.HasPrefix(p, f.Path+"/") || strings.HasPrefix(f.Path, p+"/") {
				return ramGrantResponse{}, errors.New("file directory conflict")
			}
		}
		total += len(f.Content)
		if total > maxRAMGrantBytes {
			return ramGrantResponse{}, errors.New("file grant too large")
		}
		files[f.Path] = []byte(f.Content)
	}
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return ramGrantResponse{}, errors.New("capability unavailable")
	}
	token := hex.EncodeToString(raw[:32])
	identity := ramFileOwner{}
	if len(identities) > 0 {
		identity = identities[0]
	}
	usage := make(map[string]*ramFileUsage, len(files))
	for name := range files {
		usage[name] = &ramFileUsage{}
	}
	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.owners[owner]
	previousSize := 0
	if exists {
		previousSize = s.grants[previous].size
	}
	if s.closed || s.baseURL == "" || (!exists && len(s.grants) >= maxRAMGrants) || s.bytes-previousSize+total > maxRAMStoreBytes {
		return ramGrantResponse{}, errors.New("RAM provider unavailable or full")
	}
	if exists {
		delete(s.grants, previous)
	}
	s.grants[digest] = &ramGrant{owner: owner, id: hex.EncodeToString(raw[32:]), identity: identity, usage: usage, files: files, size: total, created: time.Now().UTC()}
	s.owners[owner] = digest
	s.bytes = s.bytes - previousSize + total
	return ramGrantResponse{BaseURL: s.baseURL, Token: token, Directory: s.baseURL + "/" + token}, nil
}

func (s *ramFileStore) revoke(token string) {
	digest := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if grant, ok := s.grants[digest]; ok {
		delete(s.grants, digest)
		delete(s.owners, grant.owner)
		s.bytes -= grant.size
	}
}

func (b *localBackend) startRAMWebDAV() (func(), error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	store := newRAMFileStore()
	store.baseURL = "http://" + ln.Addr().String()
	b.ramFiles = store
	server := &http.Server{Handler: store, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.Serve(ln) }()
	return func() {
		_ = server.Close()
		store.mu.Lock()
		store.grants = make(map[[32]byte]*ramGrant)
		store.owners = make(map[string][32]byte)
		store.bytes = 0
		store.closed = true
		store.mu.Unlock()
	}, nil
}

func registerRAMFileHandlers(mux *http.ServeMux, b *localBackend, security localAPISecurity) {
	registerRAMStatusHandler(mux, b, security)
	mux.HandleFunc("/v1/file-grants", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, 405, "method_not_allowed", "Use POST.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req ramGrantRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		refs, err := ramBindingRefs(req.Bindings)
		if err != nil {
			writeAPIError(w, 400, "invalid_file_grant", "Invalid secret bindings.", "invalid_ref", "")
			return
		}
		identity := resolveRequest{RequestID: req.RequestID, WorkspaceID: req.WorkspaceID, ServiceID: req.ServiceID, IdentityLease: req.IdentityLease, Refs: refs}
		if err := b.authorizeResolveLaunchLease(&identity, b.launchLeaseSigningKey(security.token), transportPeerIdentityFromContext(r.Context())); err != nil {
			writeLaunchIdentityAPIError(w, err)
			return
		}
		if b.ramFiles == nil {
			writeAPIError(w, 503, "ram_files_unavailable", "RAM file provider unavailable.", "backend_degraded", "")
			return
		}
		if len(req.InstanceID) != 64 {
			writeAPIError(w, 400, "invalid_request", "Invalid instance identity.", "invalid_ref", "")
			return
		}
		if _, err := hex.DecodeString(req.InstanceID); err != nil {
			writeAPIError(w, 400, "invalid_request", "Invalid instance identity.", "invalid_ref", "")
			return
		}
		// Length-prefix identity fields avoid concatenation aliases.
		owner := fmt.Sprintf("%d:%s%d:%s%s", len(identity.WorkspaceID), identity.WorkspaceID, len(identity.ServiceID), identity.ServiceID, req.InstanceID)
		files, err := b.renderRAMSecretFiles(req.Files, req.Bindings, identity)
		if err != nil {
			writeAPIError(w, 400, "secret_file_provision_failed", "Secret-file inputs are unavailable or invalid.", "policy_denied", "")
			return
		}
		grant, err := b.ramFiles.create(owner, files, ramFileOwner{WorkspaceID: identity.WorkspaceID, ServiceID: identity.ServiceID})
		if err != nil {
			writeAPIError(w, 400, "invalid_file_grant", "File grant rejected by bounds or path policy.", "policy_denied", "")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 201, grant)
	})
	mux.HandleFunc("/v1/file-grants/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeAPIError(w, 405, "method_not_allowed", "Use POST.", "invalid_ref", "")
			return
		}
		if !security.require(w, r) {
			return
		}
		var req ramRevokeRequest
		if err := decodeSecretBearingJSON(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		if b.ramFiles != nil {
			b.ramFiles.revoke(req.Token)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (s *ramFileStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	deny := func(code int) { http.Error(w, "WebDAV request denied", code) }
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() || r.Host != strings.TrimPrefix(s.baseURL, "http://") || r.Header.Get("Origin") != "" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Forwarded-Host") != "" {
		deny(403)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && r.Method != "PROPFIND" {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PROPFIND")
		deny(405)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || strings.Contains(r.URL.Path, "%") {
		deny(400)
		return
	}
	// OPTIONS at the server root advertises protocol only; never grants files.
	if r.Method == http.MethodOptions && r.URL.Path == "/" {
		w.Header().Set("DAV", "1")
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PROPFIND")
		w.WriteHeader(204)
		return
	}
	token := ""
	name := ""
	prefix := ""
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.URL.Path, "/files/") {
			deny(404)
			return
		}
		name = strings.TrimPrefix(r.URL.Path, "/files/")
		prefix = "/files/"
	} else {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		token = parts[0]
		if len(parts) == 2 {
			name = parts[1]
		}
		prefix = "/" + token + "/"
	}
	if len(token) != 64 {
		deny(404)
		return
	}
	if _, err := hex.DecodeString(token); err != nil {
		deny(404)
		return
	}
	trailing := strings.HasSuffix(name, "/")
	name = strings.TrimSuffix(name, "/")
	if name != "" && !validRAMFilePath(name) {
		deny(400)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock() // Revocation waits for bounded in-flight reads.
	grant, ok := s.grants[sha256.Sum256([]byte(token))]
	if !ok {
		deny(404)
		return
	}
	content, isFile := grant.files[name]
	isDir := name == ""
	if !isFile {
		for p := range grant.files {
			if strings.HasPrefix(p, name+"/") {
				isDir = true
				break
			}
		}
	}
	if (!isFile && !isDir) || (trailing && isFile) {
		deny(404)
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("DAV", "1")
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PROPFIND")
		w.WriteHeader(204)
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if !isFile {
			deny(405)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			n, err := w.Write(content)
			usage := grant.usage[name]
			usage.mu.Lock()
			if n >= 0 {
				usage.servedBytes += uint64(n)
			}
			if err == nil && n == len(content) {
				usage.downloads++
				usage.lastAccess = time.Now().UTC()
			}
			usage.mu.Unlock()
		}
		return
	}
	depth := r.Header.Get("Depth")
	if depth != "0" && depth != "1" {
		deny(403)
		return
	}
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 16<<10)); err != nil {
		deny(413)
		return
	}
	names := []string{name}
	if depth == "1" && isDir {
		children := map[string]bool{}
		base := name
		if base != "" {
			base += "/"
		}
		for p := range grant.files {
			if strings.HasPrefix(p, base) {
				rest := strings.TrimPrefix(p, base)
				child := base + strings.SplitN(rest, "/", 2)[0]
				children[child] = true
			}
		}
		for p := range children {
			names = append(names, p)
		}
		sort.Strings(names[1:])
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
	for _, p := range names {
		data, file := grant.files[p]
		href := prefix + p
		if !file && !strings.HasSuffix(href, "/") {
			href += "/"
		}
		_, _ = io.WriteString(w, "<D:response><D:href>")
		_ = xml.EscapeText(w, []byte((&url.URL{Path: href}).EscapedPath()))
		_, _ = io.WriteString(w, "</D:href><D:propstat><D:prop><D:resourcetype>")
		if !file {
			_, _ = io.WriteString(w, "<D:collection/>")
		}
		_, _ = fmt.Fprintf(w, "</D:resourcetype><D:getcontentlength>%d</D:getcontentlength><D:getlastmodified>%s</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>", len(data), grant.created.Format(http.TimeFormat))
	}
	_, _ = io.WriteString(w, "</D:multistatus>")
}
