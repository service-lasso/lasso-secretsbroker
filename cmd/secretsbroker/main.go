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

const (
	version    = "0.1.0"
	apiVersion = "secretsbroker.local/v1"
	serviceID  = "@secretsbroker"
)

var typedOutcomes = []string{
	"setup_needed",
	"locked",
	"ready",
	"source_auth_required",
	"degraded",
	"policy_denied",
	"missing_ref",
	"invalid_ref",
	"source_unavailable",
	"identity_expired",
}

type Status struct {
	ServiceID   string    `json:"serviceId"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	APIVersion  string    `json:"apiVersion"`
	State       string    `json:"state"`
	Ready       bool      `json:"ready"`
	LocalFirst  bool      `json:"localFirst"`
	Backend     string    `json:"backend"`
	Description string    `json:"description"`
	CheckedAt   time.Time `json:"checkedAt"`
}

type HealthResponse struct {
	OK        bool   `json:"ok"`
	ServiceID string `json:"serviceId"`
	State     string `json:"state"`
}

type StateResponse struct {
	ServiceID        string   `json:"serviceId"`
	APIVersion       string   `json:"apiVersion"`
	State            string   `json:"state"`
	Ready            bool     `json:"ready"`
	Outcome          string   `json:"outcome"`
	AffectedRefs     []string `json:"affectedRefs"`
	AffectedServices []string `json:"affectedServices"`
}

type CapabilitiesResponse struct {
	ServiceID      string   `json:"serviceId"`
	APIVersion     string   `json:"apiVersion"`
	Version        string   `json:"version"`
	Transports     []string `json:"transports"`
	Endpoints      []string `json:"endpoints"`
	Features       []string `json:"features"`
	FutureFeatures []string `json:"futureFeatures"`
	Outcomes       []string `json:"outcomes"`
}

type ErrorEnvelope struct {
	Error APIError `json:"error"`
}

type APIError struct {
	Code             string   `json:"code"`
	Message          string   `json:"message"`
	Outcome          string   `json:"outcome"`
	RequestID        string   `json:"requestId,omitempty"`
	NextAction       string   `json:"nextAction,omitempty"`
	AffectedRefs     []string `json:"affectedRefs"`
	AffectedServices []string `json:"affectedServices"`
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

func normalizeState(state string) string {
	state = strings.TrimSpace(state)
	if state == "" {
		return "setup_needed"
	}
	return state
}

func isReadyState(state string) bool {
	return normalizeState(state) == "ready"
}

func defaultStatus(state string) Status {
	state = normalizeState(state)
	return Status{
		ServiceID:   serviceID,
		Name:        "Service Lasso Secrets Broker",
		Version:     version,
		APIVersion:  apiVersion,
		State:       state,
		Ready:       isReadyState(state),
		LocalFirst:  true,
		Backend:     "local",
		Description: "Lean local-first Vault-like broker bootstrap skeleton. Secrets storage/resolution is intentionally not implemented yet.",
		CheckedAt:   time.Now().UTC(),
	}
}

func defaultHealth(state string) HealthResponse {
	return HealthResponse{OK: true, ServiceID: serviceID, State: normalizeState(state)}
}

func defaultState(state string) StateResponse {
	state = normalizeState(state)
	return StateResponse{
		ServiceID:        serviceID,
		APIVersion:       apiVersion,
		State:            state,
		Ready:            isReadyState(state),
		Outcome:          state,
		AffectedRefs:     []string{},
		AffectedServices: []string{},
	}
}

func defaultCapabilities() CapabilitiesResponse {
	return CapabilitiesResponse{
		ServiceID:  serviceID,
		APIVersion: apiVersion,
		Version:    version,
		Transports: []string{"loopback-http"},
		Endpoints: []string{
			"GET /health",
			"GET /ready",
			"GET /status",
			"GET /state",
			"GET /capabilities",
		},
		Features: []string{
			"liveness",
			"readiness",
			"status",
			"state",
			"capabilities",
		},
		FutureFeatures: []string{
			"batched-resolve",
			"write-back",
			"source-status",
			"typed-errors",
			"audit-redaction",
		},
		Outcomes: append([]string(nil), typedOutcomes...),
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

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: newHandler(state), ReadHeaderTimeout: 5 * time.Second}
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

func newHandler(state *string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultHealth(*state))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		body := defaultState(*state)
		code := http.StatusOK
		if !body.Ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, body)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultStatus(*state))
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultState(*state))
	})
	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultCapabilities())
	})
	return mux
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
