package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.0"

type Status struct {
	ServiceID   string    `json:"serviceId"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	State       string    `json:"state"`
	Ready       bool      `json:"ready"`
	LocalFirst  bool      `json:"localFirst"`
	Backend     string    `json:"backend"`
	Description string    `json:"description"`
	CheckedAt   time.Time `json:"checkedAt"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}

	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "status":
		return printStatus(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: secretsbroker <serve|status|version>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  serve   Start the local-first @secretsbroker daemon")
	fmt.Fprintln(os.Stderr, "  status  Print current broker state JSON")
	fmt.Fprintln(os.Stderr, "  version Print broker version")
}

func defaultStatus(state string) Status {
	state = strings.TrimSpace(state)
	if state == "" {
		state = "setup_needed"
	}
	return Status{
		ServiceID:   "@secretsbroker",
		Name:        "Service Lasso Secrets Broker",
		Version:     version,
		State:       state,
		Ready:       state == "ready",
		LocalFirst:  true,
		Backend:     "local",
		Description: "Lean local-first Vault-like broker bootstrap skeleton. Secrets storage/resolution is intentionally not implemented yet.",
		CheckedAt:   time.Now().UTC(),
	}
}

func printStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	state := fs.String("state", getenvDefault("SECRETSBROKER_STATE", "setup_needed"), "state to report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(defaultStatus(*state))
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", getenvDefault("SECRETSBROKER_LISTEN", "127.0.0.1:17890"), "listen address")
	state := fs.String("state", getenvDefault("SECRETSBROKER_STATE", "setup_needed"), "state to report")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "serviceId": "@secretsbroker", "state": *state})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultStatus(*state))
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"serviceId": "@secretsbroker", "state": defaultStatus(*state).State, "ready": defaultStatus(*state).Ready})
	})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		slog.Info("@secretsbroker listening", "addr", ln.Addr().String(), "state", *state)
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
