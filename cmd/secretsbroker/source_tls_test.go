package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProductionSourceHTTPClientTrustsDigestPinnedCustomCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/sample" || r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"resolved-secret"}}}`))
	}))
	defer server.Close()

	caPath, pin := writeTestServerCA(t, server)
	t.Setenv(sourceCAFileEnv, caPath)
	t.Setenv(sourceCASHA256Env, pin)

	result := (sourceConfig{
		Address:    server.URL,
		Token:      "test-token",
		Production: true,
	}).resolveVault(sourceRefConfig{Path: "secret/data/sample", Field: "value"})
	if result.Outcome != "ready" || result.Value != "resolved-secret" {
		t.Fatalf("expected pinned custom CA resolution to succeed, got %#v", result)
	}

	transport, err := sourceHTTPTransport(true)
	if err != nil {
		t.Fatalf("build source transport: %v", err)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("custom source transport must retain certificate verification")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("custom source transport weakened TLS minimum: %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestProductionCustomSourceCAFailsClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	caPath, pin := writeTestServerCA(t, server)

	t.Run("missing digest pin", func(t *testing.T) {
		t.Setenv(sourceCAFileEnv, caPath)
		t.Setenv(sourceCASHA256Env, "")
		if _, err := sourceHTTPTransport(true); err == nil || !strings.Contains(err.Error(), sourceCASHA256Env) {
			t.Fatalf("expected missing pin rejection, got %v", err)
		}
	})

	t.Run("mismatched digest pin", func(t *testing.T) {
		t.Setenv(sourceCAFileEnv, caPath)
		t.Setenv(sourceCASHA256Env, "sha256:"+strings.Repeat("0", 64))
		if _, err := sourceHTTPTransport(true); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("expected digest mismatch rejection, got %v", err)
		}
	})

	t.Run("digest without file", func(t *testing.T) {
		t.Setenv(sourceCAFileEnv, "")
		t.Setenv(sourceCASHA256Env, pin)
		if _, err := sourceHTTPTransport(true); err == nil || !strings.Contains(err.Error(), sourceCAFileEnv) {
			t.Fatalf("expected orphaned digest rejection, got %v", err)
		}
	})

	t.Run("relative path", func(t *testing.T) {
		t.Setenv(sourceCAFileEnv, filepath.Base(caPath))
		t.Setenv(sourceCASHA256Env, pin)
		if _, err := sourceHTTPTransport(true); err == nil || !strings.Contains(err.Error(), "absolute path") {
			t.Fatalf("expected relative path rejection, got %v", err)
		}
	})

	t.Run("malformed certificate", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "malformed.pem")
		contents := []byte("not a PEM certificate")
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("write malformed certificate: %v", err)
		}
		digest := sha256.Sum256(contents)
		t.Setenv(sourceCAFileEnv, path)
		t.Setenv(sourceCASHA256Env, "sha256:"+hex.EncodeToString(digest[:]))
		if _, err := sourceHTTPTransport(true); err == nil || !strings.Contains(err.Error(), "no valid PEM certificates") {
			t.Fatalf("expected malformed certificate rejection, got %v", err)
		}
	})

	t.Run("symlink or reparse indirection", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "ca-link.pem")
		if err := os.Symlink(caPath, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("Windows host does not permit an unprivileged symlink: %v", err)
			}
			t.Fatalf("create CA symlink: %v", err)
		}
		t.Setenv(sourceCAFileEnv, link)
		t.Setenv(sourceCASHA256Env, pin)
		if _, err := sourceHTTPTransport(true); err == nil || !strings.Contains(err.Error(), "without symlink or reparse indirection") {
			t.Fatalf("expected indirect path rejection, got %v", err)
		}
	})
}

func TestDevelopmentCustomSourceCAAllowsUnpinnedBootstrap(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caPath, _ := writeTestServerCA(t, server)
	t.Setenv(sourceCAFileEnv, caPath)
	t.Setenv(sourceCASHA256Env, "")

	client, err := newSourceHTTPClient(time.Second, false, rejectCredentialRedirect)
	if err != nil {
		t.Fatalf("build development source client: %v", err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("call development TLS source: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected development TLS source status: %d", response.StatusCode)
	}
}

func writeTestServerCA(t *testing.T, server *httptest.Server) (string, string) {
	t.Helper()
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("TLS test server did not expose its certificate")
	}
	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	path := filepath.Join(t.TempDir(), "source-ca.pem")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write test source CA: %v", err)
	}
	digest := sha256.Sum256(contents)
	return path, "sha256:" + hex.EncodeToString(digest[:])
}
