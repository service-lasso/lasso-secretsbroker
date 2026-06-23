package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type serveTransportOptions struct {
	Mode       string
	Transport  string
	Listen     string
	UnixSocket string
	NamedPipe  string
}

type serveTransportBinding struct {
	Kind           string
	Network        string
	Address        string
	DisplayAddress string
}

func resolveServeTransport(opts serveTransportOptions) (serveTransportBinding, error) {
	mode := normalizeServeMode(opts.Mode)
	kind := normalizeTransportKind(opts.Transport, mode)
	switch kind {
	case "loopback-http":
		listen := strings.TrimSpace(opts.Listen)
		if listen == "" {
			listen = "127.0.0.1:17890"
		}
		if err := validateLoopbackListen(listen); err != nil {
			return serveTransportBinding{}, err
		}
		if mode == "production" {
			return serveTransportBinding{}, errors.New("production mode requires unix-socket or windows-named-pipe transport; loopback-http is development/bootstrap only")
		}
		return serveTransportBinding{Kind: kind, Network: "tcp", Address: listen, DisplayAddress: listen}, nil
	case "unix-socket":
		path := strings.TrimSpace(opts.UnixSocket)
		if path == "" {
			path = defaultUnixSocketPath()
		}
		return serveTransportBinding{Kind: kind, Network: "unix", Address: filepath.Clean(path), DisplayAddress: filepath.Clean(path)}, nil
	case "windows-named-pipe":
		path := strings.TrimSpace(opts.NamedPipe)
		if path == "" {
			path = defaultNamedPipePath()
		}
		if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) {
			return serveTransportBinding{}, fmt.Errorf("windows named pipe path must start with \\\\.\\pipe\\")
		}
		return serveTransportBinding{Kind: kind, Network: "windows-named-pipe", Address: path, DisplayAddress: path}, nil
	default:
		return serveTransportBinding{}, fmt.Errorf("unsupported serve transport %q", opts.Transport)
	}
}

func normalizeServeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "dev", "development", "bootstrap", "local":
		return "development"
	case "prod", "production":
		return "production"
	default:
		return "development"
	}
}

func normalizeTransportKind(kind, mode string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" || kind == "auto" {
		if normalizeServeMode(mode) == "production" {
			if runtime.GOOS == "windows" {
				return "windows-named-pipe"
			}
			return "unix-socket"
		}
		return "loopback-http"
	}
	return kind
}

func validateLoopbackListen(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("loopback-http listen address must include host and port: %w", err)
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("loopback-http listen address must bind to 127.0.0.1, ::1, or localhost; got %q", host)
	}
	return nil
}

func defaultUnixSocketPath() string {
	return filepath.Join(os.TempDir(), "service-lasso-secretsbroker.sock")
}

func defaultNamedPipePath() string {
	return `\\.\pipe\service-lasso-secretsbroker`
}
