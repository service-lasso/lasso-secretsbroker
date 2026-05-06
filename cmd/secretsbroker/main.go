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

var lifecycleStates = []string{
	"setup_needed",
	"locked",
	"ready",
	"source_auth_required",
	"degraded",
	"policy_denied",
}

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
	KeyState         string   `json:"keyState"`
	NextAction       string   `json:"nextAction"`
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
	case "key":
		return runKey(args[1:])
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
	fmt.Fprintln(os.Stderr, "Usage: secretsbroker <serve|status|key|version>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  serve   Start the local-first @secretsbroker daemon")
	fmt.Fprintln(os.Stderr, "  status  Print current broker state JSON")
	fmt.Fprintln(os.Stderr, "  key     Manage portable master-key foundation")
	fmt.Fprintln(os.Stderr, "  version Print broker version")
}

func normalizeState(state string) string {
	state = strings.TrimSpace(state)
	if state == "" {
		return "setup_needed"
	}
	for _, allowed := range lifecycleStates {
		if state == allowed {
			return state
		}
	}
	return "degraded"
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
	return stateResponse(state, nil, nil)
}

func stateResponse(state string, affectedRefs []string, affectedServices []string) StateResponse {
	state = normalizeState(state)
	return StateResponse{
		ServiceID:        serviceID,
		APIVersion:       apiVersion,
		State:            state,
		Ready:            isReadyState(state),
		Outcome:          state,
		KeyState:         keyStateFor(state),
		NextAction:       nextActionFor(state),
		AffectedRefs:     safeList(affectedRefs),
		AffectedServices: safeList(affectedServices),
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
			"POST /v1/secrets",
			"POST /v1/resolve",
		},
		Features: []string{
			"liveness",
			"readiness",
			"status",
			"state",
			"capabilities",
			"local-encrypted-store",
			"batched-resolve",
			"typed-errors",
			"audit-redaction",
		},
		FutureFeatures: []string{
			"write-back",
			"source-status",
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
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	auditPath := fs.String("audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "local development master key; empty means locked")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	affectedRefs := multiFlag(splitCSV(getenvDefault("SECRETSBROKER_AFFECTED_REFS", "")))
	affectedServices := multiFlag(splitCSV(getenvDefault("SECRETSBROKER_AFFECTED_SERVICES", "")))
	fs.Var(&affectedRefs, "affected-ref", "affected secret ref to report for non-ready states; repeatable")
	fs.Var(&affectedServices, "affected-service", "affected service id to report for non-ready states; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}

	refs := []string(affectedRefs)
	services := []string(affectedServices)
	stateView := runtimeState{state: state, affectedRefs: &refs, affectedServices: &services}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	backend := newLocalBackend(*storePath, *auditPath, material.Value)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: newHandler(stateView, backend), ReadHeaderTimeout: 5 * time.Second}
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

func newHandler(state runtimeState, backend *localBackend) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultHealth(state.current()))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		body := state.response()
		code := http.StatusOK
		if !body.Ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, body)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultStatus(state.current()))
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, state.response())
	})
	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, defaultCapabilities())
	})
	if backend != nil {
		registerLocalStoreHandlers(mux, backend)
	}
	return mux
}

type runtimeState struct {
	state            *string
	affectedRefs     *[]string
	affectedServices *[]string
}

func (s runtimeState) current() string {
	if s.state == nil {
		return "setup_needed"
	}
	return *s.state
}

func (s runtimeState) response() StateResponse {
	var refs []string
	if s.affectedRefs != nil {
		refs = *s.affectedRefs
	}
	var services []string
	if s.affectedServices != nil {
		services = *s.affectedServices
	}
	return stateResponse(s.current(), refs, services)
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, splitCSV(value)...)
	return nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	return safeList(parts)
}

func safeList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			clean = append(clean, value)
		}
	}
	return clean
}

func keyStateFor(state string) string {
	switch normalizeState(state) {
	case "setup_needed":
		return "not_initialized"
	case "locked":
		return "locked"
	default:
		return "available"
	}
}

func nextActionFor(state string) string {
	switch normalizeState(state) {
	case "setup_needed":
		return "run_setup"
	case "locked":
		return "unlock_broker"
	case "source_auth_required":
		return "reconnect_source"
	case "degraded":
		return "inspect_sources"
	case "policy_denied":
		return "review_policy"
	default:
		return ""
	}
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
