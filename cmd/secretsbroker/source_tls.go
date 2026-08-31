package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	sourceCAFileEnv   = "SECRETSBROKER_SOURCE_CA_FILE"
	sourceCASHA256Env = "SECRETSBROKER_SOURCE_CA_SHA256"
	sourceCAMaxBytes  = 1 << 20
)

func newSourceHTTPClient(timeout time.Duration, production bool, checkRedirect func(*http.Request, []*http.Request) error) (*http.Client, error) {
	transport, err := sourceHTTPTransport(production)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
		Transport:     transport,
	}, nil
}

func sourceHTTPTransport(production bool) (*http.Transport, error) {
	path := strings.TrimSpace(os.Getenv(sourceCAFileEnv))
	want := strings.ToLower(strings.TrimSpace(os.Getenv(sourceCASHA256Env)))
	if path == "" {
		if want != "" {
			return nil, fmt.Errorf("%s requires %s", sourceCASHA256Env, sourceCAFileEnv)
		}
		return cloneDefaultHTTPTransport()
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s must be an absolute path", sourceCAFileEnv)
	}
	if production && !validSHA256Pin(want) {
		return nil, fmt.Errorf("production custom source CA requires %s", sourceCASHA256Env)
	}
	if want != "" && !validSHA256Pin(want) {
		return nil, fmt.Errorf("%s must use sha256:<64 lowercase hex characters>", sourceCASHA256Env)
	}

	certificatePEM, got, err := readSourceCA(path)
	if err != nil {
		return nil, fmt.Errorf("read custom source CA: %w", err)
	}
	if want != "" && !constantTimeTokenEqual(got, want) {
		return nil, errors.New("custom source CA SHA-256 digest mismatch")
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system source CA roots: %w", err)
	}
	if !roots.AppendCertsFromPEM(certificatePEM) {
		return nil, errors.New("custom source CA file contains no valid PEM certificates")
	}
	transport, err := cloneDefaultHTTPTransport()
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	return transport, nil
}

func readSourceCA(path string) ([]byte, string, error) {
	file, err := openValidatedRegularFile(path, sourceCAMaxBytes, false)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, sourceCAMaxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(contents) == 0 || len(contents) > sourceCAMaxBytes {
		return nil, "", errors.New("custom source CA file must be nonempty and at most 1 MiB")
	}
	digest := sha256.Sum256(contents)
	return contents, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validSHA256Pin(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func cloneDefaultHTTPTransport() (*http.Transport, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is unavailable")
	}
	return transport.Clone(), nil
}
