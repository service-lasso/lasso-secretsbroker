package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type adminCommonOptions struct {
	StorePath      string
	AuditPath      string
	MasterKey      string
	MasterKeyFile  string
	SourcesPath    string
	EventsPath     string
	AuditHashChain bool
}

type adminStatusResponse struct {
	ServiceID  string                       `json:"serviceId"`
	APIVersion string                       `json:"apiVersion"`
	Outcome    string                       `json:"outcome"`
	Health     HealthResponse               `json:"health"`
	Status     Status                       `json:"status"`
	State      StateResponse                `json:"state"`
	Key        keyStatusResponse            `json:"key"`
	Providers  providerConfigStatusResponse `json:"providers"`
	Recovery   recoveryPolicyStatusResponse `json:"recovery"`
}

type adminAuditExportResponse struct {
	ServiceID   string                 `json:"serviceId"`
	APIVersion  string                 `json:"apiVersion"`
	Outcome     string                 `json:"outcome"`
	Operation   string                 `json:"operation,omitempty"`
	Ref         string                 `json:"ref,omitempty"`
	RefHashOnly bool                   `json:"refHashOnly,omitempty"`
	Chain       auditChainVerification `json:"chain"`
	Events      []auditEvent           `json:"events"`
}

type adminLaunchLeaseIssueResponse struct {
	ServiceID  string              `json:"serviceId"`
	APIVersion string              `json:"apiVersion"`
	Outcome    string              `json:"outcome"`
	Lease      launchIdentityLease `json:"lease"`
}

func runAdmin(args []string) error {
	return executeAdmin(args, os.Stdout)
}

func executeAdmin(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin command %q", "")
	}
	switch args[0] {
	case "status":
		return runAdminStatus(args[1:], out)
	case "secrets":
		return runAdminSecrets(args[1:], out)
	case "providers":
		return runAdminProviders(args[1:], out)
	case "migration":
		return runAdminMigration(args[1:], out)
	case "sync":
		return runAdminSync(args[1:], out)
	case "recovery":
		return runAdminRecovery(args[1:], out)
	case "audit":
		return runAdminAudit(args[1:], out)
	case "telemetry":
		return runAdminTelemetry(args[1:], out)
	case "events":
		return runAdminEvents(args[1:], out)
	case "mcp":
		return runAdminMCP(args[1:], out)
	case "launch-lease":
		return runAdminLaunchLease(args[1:], out)
	default:
		return fmt.Errorf("unknown admin command %q", args[0])
	}
}

func runAdminLaunchLease(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin launch-lease command %q", "")
	}
	sub := args[0]
	fs := flag.NewFlagSet("admin launch-lease "+sub, flag.ContinueOnError)
	service := fs.String("service-id", "", "launched service id")
	workspace := fs.String("workspace-id", "", "workspace id")
	issuer := fs.String("issuer", "service-lasso-local-launcher", "lease issuer")
	jti := fs.String("jti", "", "one-time lease id")
	signingKey := fs.String("signing-key", getenvDefault("SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY", ""), "HMAC signing key; prefer SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY")
	apiToken := fs.String("api-token", getenvDefault("SECRETSBROKER_API_TOKEN", ""), "bootstrap fallback signing key when launch signing key is unset")
	issuedAt := fs.String("issued-at", "", "issued-at timestamp, RFC3339; defaults to now")
	expiresAt := fs.String("expires-at", "", "expires-at timestamp, RFC3339")
	ttl := fs.Duration("ttl", 5*time.Minute, "lease lifetime when --expires-at is omitted")
	transportKind := fs.String("transport-binding-kind", "", "optional transport binding kind: windows-sid or unix-uid")
	transportSubject := fs.String("transport-binding-subject", "", "optional transport binding subject")
	refs := multiFlag{}
	namespaces := multiFlag{}
	operations := multiFlag{}
	fs.Var(&refs, "allowed-ref", "allowed secret ref or glob; repeatable")
	fs.Var(&namespaces, "allowed-namespace", "allowed secret namespace; repeatable")
	fs.Var(&operations, "operation", "allowed operation; repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if sub != "issue" {
		return fmt.Errorf("unknown admin launch-lease command %q", sub)
	}
	key := firstNonEmpty(*signingKey, *apiToken)
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("launch lease issue requires SECRETSBROKER_LAUNCH_IDENTITY_SIGNING_KEY or --signing-key; bootstrap may use SECRETSBROKER_API_TOKEN or --api-token")
	}
	lease, err := buildAdminLaunchLease(adminLaunchLeaseOptions{
		Issuer:                  *issuer,
		ServiceID:               *service,
		WorkspaceID:             *workspace,
		JTI:                     *jti,
		AllowedRefs:             []string(refs),
		AllowedNamespaces:       []string(namespaces),
		AllowedOperations:       []string(operations),
		IssuedAt:                *issuedAt,
		ExpiresAt:               *expiresAt,
		TTL:                     *ttl,
		TransportBindingKind:    *transportKind,
		TransportBindingSubject: *transportSubject,
	}, time.Now().UTC)
	if err != nil {
		return err
	}
	signed, err := signLaunchIdentityLease(lease, key)
	if err != nil {
		return err
	}
	return encodeAdminJSON(out, adminLaunchLeaseIssueResponse{
		ServiceID:  serviceID,
		APIVersion: apiVersion,
		Outcome:    "ready",
		Lease:      signed,
	})
}

type adminLaunchLeaseOptions struct {
	Issuer                  string
	ServiceID               string
	WorkspaceID             string
	JTI                     string
	AllowedRefs             []string
	AllowedNamespaces       []string
	AllowedOperations       []string
	IssuedAt                string
	ExpiresAt               string
	TTL                     time.Duration
	TransportBindingKind    string
	TransportBindingSubject string
}

func buildAdminLaunchLease(opts adminLaunchLeaseOptions, now func() time.Time) (launchIdentityLease, error) {
	issued, err := parseOptionalLeaseTime(opts.IssuedAt, now())
	if err != nil {
		return launchIdentityLease{}, fmt.Errorf("invalid issued-at: %w", err)
	}
	expires, err := parseOptionalLeaseTime(opts.ExpiresAt, issued.Add(opts.TTL))
	if err != nil {
		return launchIdentityLease{}, fmt.Errorf("invalid expires-at: %w", err)
	}
	lease := launchIdentityLease{
		Issuer:            strings.TrimSpace(opts.Issuer),
		ServiceID:         strings.TrimSpace(opts.ServiceID),
		WorkspaceID:       strings.TrimSpace(opts.WorkspaceID),
		AllowedRefs:       safeList(opts.AllowedRefs),
		AllowedNamespaces: safeList(opts.AllowedNamespaces),
		AllowedOperations: safeList(opts.AllowedOperations),
		IssuedAt:          issued.Format(time.RFC3339),
		ExpiresAt:         expires.Format(time.RFC3339),
		JTI:               strings.TrimSpace(opts.JTI),
	}
	if strings.TrimSpace(lease.Issuer) == "" || strings.TrimSpace(lease.ServiceID) == "" || strings.TrimSpace(lease.JTI) == "" {
		return launchIdentityLease{}, fmt.Errorf("launch lease issue requires issuer, service-id, and jti")
	}
	if !expires.After(issued) {
		return launchIdentityLease{}, fmt.Errorf("launch lease expires-at must be after issued-at")
	}
	if len(lease.AllowedRefs) == 0 && len(lease.AllowedNamespaces) == 0 {
		return launchIdentityLease{}, fmt.Errorf("launch lease issue requires at least one allowed-ref or allowed-namespace")
	}
	if len(lease.AllowedOperations) == 0 {
		return launchIdentityLease{}, fmt.Errorf("launch lease issue requires at least one operation")
	}
	binding := normalizeLaunchTransportBinding(&launchTransportBinding{
		Kind:    opts.TransportBindingKind,
		Subject: opts.TransportBindingSubject,
	})
	if (strings.TrimSpace(opts.TransportBindingKind) != "" || strings.TrimSpace(opts.TransportBindingSubject) != "") && binding == nil {
		return launchIdentityLease{}, fmt.Errorf("transport binding requires both kind and subject")
	}
	lease.TransportBinding = binding
	return lease, nil
}

func parseOptionalLeaseTime(value string, fallback time.Time) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return fallback.UTC().Truncate(time.Second), nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func runAdminStatus(args []string, out io.Writer) error {
	fs, opts := newAdminFlagSet("admin status")
	state := fs.String("state", getenvDefault("SECRETSBROKER_STATE", ""), "state override for diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend, material, err := backendFromAdminOptions(opts)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	statusState := normalizeAdminState(*state, backend, material)
	recovery, recoveryErr := backend.recoveryPolicyStatus()
	if recoveryErr != nil && statusState == "ready" {
		statusState = "degraded"
	}
	res := adminStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: statusState, Health: defaultHealth(statusState), Status: defaultStatus(statusState), State: defaultState(statusState), Key: keyStatus(material), Providers: backend.providerConfigStatusResponse(), Recovery: recovery}
	return encodeAdminJSON(out, res)
}

func runAdminSecrets(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin secrets command %q", "")
	}
	sub := args[0]
	fs, opts := newAdminFlagSet("admin secrets " + sub)
	query := fs.String("query", "", "metadata/value search query")
	ref := fs.String("ref", "", "secret ref")
	reason := fs.String("reason", "", "audit reason")
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	confirm := fs.Bool("confirm", false, "explicitly confirm reveal")
	noEcho := fs.Bool("no-echo", false, "suppress revealed value while recording outcome")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	backend, _, err := backendFromAdminOptions(opts)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	switch sub {
	case "list":
		res, err := backend.listManagedSecrets("", false)
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	case "search":
		res, err := backend.listManagedSecrets(*query, false)
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	case "value-search":
		res, err := backend.listManagedSecrets(*query, true)
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	case "reveal":
		if !*confirm {
			res := baseManagedActionResponse(managedSecretActionRequest{RequestID: *requestID, ServiceID: *service, Ref: *ref, Reason: *reason}, "reveal", "apply")
			res.Outcome = "policy_denied"
			res.RequiresConfirmation = true
			res.NextAction = "rerun_with_confirm_and_audit_reason"
			_ = backend.audit("management_reveal", *ref, res.Outcome, *service, *requestID)
			_ = encodeAdminJSON(out, res)
			return errPolicyDenied
		}
		res, err := backend.revealManagedSecret(managedSecretActionRequest{RequestID: *requestID, ServiceID: *service, Ref: *ref, Reason: *reason, Confirm: *confirm})
		if *noEcho {
			res.Value = ""
			res.NextAction = "value_suppressed_by_no_echo"
		}
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	default:
		return fmt.Errorf("unknown admin secrets command %q", sub)
	}
}

func runAdminProviders(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin providers command %q", "")
	}
	sub := args[0]
	fs, opts := newAdminFlagSet("admin providers " + sub)
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	providerID := fs.String("provider-id", "", "provider id")
	providerKind := fs.String("provider-kind", "", "provider kind")
	displayName := fs.String("display-name", "", "display name")
	address := fs.String("address", "", "provider address")
	credentialRef := fs.String("credential-ref", "", "credential ref/handle")
	credentialValue := fs.String("credential-value", "", "plaintext credential value; rejected")
	namespaces := fs.String("namespaces", "", "comma-separated namespaces")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	backend, _, err := backendFromAdminOptions(opts)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	switch sub {
	case "capabilities":
		return encodeAdminJSON(out, backend.providerCapabilitiesResponse())
	case "status":
		return encodeAdminJSON(out, backend.providerConfigStatusResponse())
	case "validate":
		res, err := backend.validateProviderConfig(providerConfigRequest{RequestID: *requestID, ServiceID: *service, ProviderID: *providerID, ProviderKind: *providerKind, DisplayName: *displayName, Address: *address, CredentialRef: *credentialRef, CredentialValue: *credentialValue, Namespaces: splitCSV(*namespaces)})
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	default:
		return fmt.Errorf("unknown admin providers command %q", sub)
	}
}

func runAdminMigration(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin migration command %q", "")
	}
	sub := args[0]
	fs, opts := newAdminFlagSet("admin migration " + sub)
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	operationID := fs.String("operation-id", "", "operation id")
	sourceProvider := fs.String("source-provider", "local", "source provider id")
	targetProvider := fs.String("target-provider", "local", "target provider id")
	reason := fs.String("reason", "", "audit reason")
	confirm := fs.Bool("confirm", false, "confirm apply")
	refs := multiFlag{}
	fs.Var(&refs, "ref", "secret ref; repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	backend, _, err := backendFromAdminOptions(opts)
	if err != nil {
		return err
	}
	req := migrationPlanRequest{RequestID: *requestID, ServiceID: *service, OperationID: *operationID, SourceProviderID: *sourceProvider, TargetProviderID: *targetProvider, Refs: []string(refs), Reason: *reason, Confirm: *confirm}
	switch sub {
	case "dry-run":
		res, err := backend.migrationDryRun(req)
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	case "apply":
		res, err := backend.migrationApply(req)
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	default:
		return fmt.Errorf("unknown admin migration command %q", sub)
	}
}

func runAdminSync(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin sync command %q", "")
	}
	if args[0] != "dry-run" {
		return fmt.Errorf("unknown admin sync command %q", args[0])
	}
	fs, opts := newAdminFlagSet("admin sync dry-run")
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	operationID := fs.String("operation-id", "", "operation id")
	destinationID := fs.String("destination-id", "", "sync destination id")
	destinationKind := fs.String("destination-kind", "github-actions", "sync destination kind")
	owner := fs.String("owner", "", "GitHub owner or organization")
	repository := fs.String("repository", "", "GitHub repository")
	environment := fs.String("environment", "", "GitHub environment")
	secretsLocation := fs.String("secrets-location", "repository", "GitHub secrets location: repository, environment, or organization")
	visibility := fs.String("visibility", "", "GitHub organization secret visibility metadata")
	enterpriseURL := fs.String("enterprise-url", "", "GitHub Enterprise URL metadata")
	authModel := fs.String("auth-model", "github-app", "destination auth model")
	credentialRef := fs.String("credential-ref", "", "destination credential ref/handle")
	credentialValue := fs.String("credential-value", "", "plaintext credential value; rejected")
	nameTemplate := fs.String("name-template", "SERVICE_LASSO_{{ refBase | upper }}", "destination secret name template")
	collisionPolicy := fs.String("collision-policy", "fail_if_unmanaged", "destination collision policy")
	deletePolicy := fs.String("delete-policy", "delete_managed_destination_secret", "destination delete behavior")
	reason := fs.String("reason", "", "audit reason")
	refs := multiFlag{}
	policyRefs := multiFlag{}
	selectedRepos := multiFlag{}
	fs.Var(&refs, "ref", "secret ref; repeatable")
	fs.Var(&policyRefs, "policy-ref", "allowed management policy ref/pattern; repeatable")
	fs.Var(&selectedRepos, "selected-repository", "selected repository metadata for organization secrets; repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	backend, _, err := backendFromAdminOptions(opts)
	if err != nil {
		return err
	}
	req := syncDryRunRequest{
		RequestID:       *requestID,
		ServiceID:       *service,
		OperationID:     *operationID,
		Refs:            []string(refs),
		DestinationID:   *destinationID,
		Reason:          *reason,
		CredentialValue: *credentialValue,
		Secrets:         &serviceSecretsPolicy{Manage: []string(policyRefs)},
		Destination: syncDestinationConfig{
			DestinationID:   *destinationID,
			Kind:            *destinationKind,
			Enabled:         true,
			CredentialRef:   *credentialRef,
			AuthModel:       *authModel,
			NameTemplate:    *nameTemplate,
			CollisionPolicy: *collisionPolicy,
			DeletePolicy:    *deletePolicy,
			Scope: syncDestinationScope{
				Owner:                *owner,
				Repository:           *repository,
				Environment:          *environment,
				SecretsLocation:      *secretsLocation,
				Visibility:           *visibility,
				SelectedRepositories: []string(selectedRepos),
				EnterpriseURL:        *enterpriseURL,
			},
		},
	}
	res, err := backend.syncDryRun(req)
	if err != nil {
		_ = encodeAdminJSON(out, res)
		return err
	}
	return encodeAdminJSON(out, res)
}

func runAdminRecovery(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin recovery command %q", "")
	}
	sub := args[0]
	fs, opts := newAdminFlagSet("admin recovery " + sub)
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	policyID := fs.String("policy-id", "", "recovery policy id")
	keyID := fs.String("key-id", "", "portable master key id")
	keyVersion := fs.String("key-version", masterKeyVersion, "portable master key version")
	threshold := fs.Int("threshold", 0, "threshold required to recover")
	shareCount := fs.Int("share-count", 0, "total recovery share count")
	status := fs.String("status", "active", "policy status: active, rotated, or revoked")
	shareFingerprints := multiFlag{}
	recipientFingerprints := multiFlag{}
	fs.Var(&shareFingerprints, "share-fingerprint", "safe recovery share fingerprint; repeatable")
	fs.Var(&recipientFingerprints, "recipient-fingerprint", "safe recipient fingerprint; repeatable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	backend, _, err := backendFromAdminOptions(opts)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	switch sub {
	case "status":
		res, err := backend.recoveryPolicyStatus()
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	case "enroll":
		res, err := backend.upsertRecoveryPolicy(recoveryPolicyRequest{RequestID: *requestID, ServiceID: *service, PolicyID: *policyID, KeyID: *keyID, KeyVersion: *keyVersion, Threshold: *threshold, ShareCount: *shareCount, ShareFingerprints: []string(shareFingerprints), RecipientFingerprints: []string(recipientFingerprints), Status: *status})
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	case "revoke":
		res, err := backend.revokeRecoveryPolicy(*policyID, *service, *requestID)
		if err != nil {
			_ = encodeAdminJSON(out, res)
			return err
		}
		return encodeAdminJSON(out, res)
	default:
		return fmt.Errorf("unknown admin recovery command %q", sub)
	}
}

func runAdminAudit(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin audit command %q", "")
	}
	if args[0] != "export" {
		return fmt.Errorf("unknown admin audit command %q", args[0])
	}
	fs, opts := newAdminFlagSet("admin audit export")
	operation := fs.String("operation", "", "operation filter")
	ref := fs.String("ref", "", "ref filter")
	refHashOnly := fs.Bool("ref-hash-only", false, "omit raw refs from exported audit events and keep refHash only")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	res, err := exportAuditEvents(opts.AuditPath, *operation, *ref, *refHashOnly)
	if err != nil {
		_ = encodeAdminJSON(out, res)
		return err
	}
	return encodeAdminJSON(out, res)
}

func runAdminTelemetry(args []string, out io.Writer) error {
	fs, opts := newAdminFlagSet("admin telemetry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend, _, err := backendFromAdminOptions(opts)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	res, err := buildTelemetryResponse(backend)
	if err != nil {
		_ = encodeAdminJSON(out, res)
		return err
	}
	return encodeAdminJSON(out, res)
}

func runAdminEvents(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin events command %q", "")
	}
	if args[0] != "list" {
		return fmt.Errorf("unknown admin events command %q", args[0])
	}
	fs, opts := newAdminFlagSet("admin events list")
	since := fs.String("since", "", "RFC3339 lower time bound")
	until := fs.String("until", "", "RFC3339 upper time bound")
	serviceID := fs.String("service-id", "", "service id filter")
	providerID := fs.String("provider-id", "", "provider id filter")
	sourceID := fs.String("source-id", "", "source id filter")
	operation := fs.String("operation", "", "operation filter")
	outcome := fs.String("outcome", "", "outcome filter")
	severity := fs.String("severity", "", "severity filter")
	family := fs.String("family", "", "event family filter")
	refPrefix := fs.String("ref-prefix", "", "safe ref prefix filter")
	refHash := fs.String("ref-hash", "", "ref hash filter")
	limit := fs.Int("limit", defaultOperationalEventLimit, "event page size")
	cursor := fs.Int("cursor", 0, "event page cursor")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	finalizeAdminEventPath(opts)
	values := url.Values{}
	values.Set("limit", strconv.Itoa(*limit))
	values.Set("cursor", strconv.Itoa(*cursor))
	for key, value := range map[string]string{
		"since":      *since,
		"until":      *until,
		"serviceId":  *serviceID,
		"providerId": *providerID,
		"sourceId":   *sourceID,
		"operation":  *operation,
		"outcome":    *outcome,
		"severity":   *severity,
		"family":     *family,
		"refPrefix":  *refPrefix,
		"refHash":    *refHash,
	} {
		if strings.TrimSpace(value) != "" {
			values.Set(key, value)
		}
	}
	filters, err := parseEventFilters(values)
	if err != nil {
		return err
	}
	res, err := buildEventsResponse(opts.EventsPath, filters)
	if err != nil {
		_ = encodeAdminJSON(out, res)
		return err
	}
	return encodeAdminJSON(out, res)
}

func finalizeAdminEventPath(opts *adminCommonOptions) {
	if strings.TrimSpace(os.Getenv("SECRETSBROKER_EVENTS_PATH")) != "" {
		return
	}
	if opts.EventsPath == defaultEventsPath(defaultAuditPath()) {
		opts.EventsPath = defaultEventsPath(opts.AuditPath)
	}
}

func newAdminFlagSet(name string) (*flag.FlagSet, *adminCommonOptions) {
	opts := &adminCommonOptions{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&opts.StorePath, "store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	fs.StringVar(&opts.AuditPath, "audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	fs.StringVar(&opts.EventsPath, "events", getenvDefault("SECRETSBROKER_EVENTS_PATH", defaultEventsPath(opts.AuditPath)), "operational events JSONL path")
	fs.StringVar(&opts.MasterKey, "master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	fs.StringVar(&opts.MasterKeyFile, "master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	fs.StringVar(&opts.SourcesPath, "sources", getenvDefault("SECRETSBROKER_SOURCES_PATH", ""), "source adapter config path")
	fs.BoolVar(&opts.AuditHashChain, "audit-hash-chain", envBoolDefault("SECRETSBROKER_AUDIT_HASH_CHAIN", false), "append tamper-evident audit hash-chain metadata")
	return fs, opts
}

func backendFromAdminOptions(opts *adminCommonOptions) (*localBackend, keyMaterial, error) {
	finalizeAdminEventPath(opts)
	material, err := loadKeyMaterial(opts.MasterKey, opts.MasterKeyFile)
	if err != nil && !errors.Is(err, errLocked) {
		return nil, material, err
	}
	backend := newLocalBackend(opts.StorePath, opts.AuditPath, material.Value)
	backend.eventPath = opts.EventsPath
	backend.auditHashChain = opts.AuditHashChain
	sources, sourceErr := loadSourceConfig(opts.SourcesPath)
	if sourceErr != nil {
		return nil, material, sourceErr
	}
	backend.sources = sources
	backend.configureProviderMigrationExecutors()
	return backend, material, err
}

func normalizeAdminState(state string, backend *localBackend, material keyMaterial) string {
	if strings.TrimSpace(state) != "" {
		return normalizeState(state)
	}
	if strings.TrimSpace(material.Value) == "" {
		if _, err := os.Stat(backend.storePath); errors.Is(err, os.ErrNotExist) {
			return "setup_needed"
		}
		return "locked"
	}
	if _, _, err := backend.validateStoreForKey(); err != nil {
		return outcomeForError(err)
	}
	return "ready"
}

func exportAuditEvents(path, operation, ref string, refHashOnly bool) (adminAuditExportResponse, error) {
	res := adminAuditExportResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", Operation: strings.TrimSpace(operation), Ref: strings.TrimSpace(ref), RefHashOnly: refHashOnly, Chain: auditChainVerification{Status: "not_enabled"}, Events: []auditEvent{}}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		res.Outcome = "degraded"
		return res, errBackendDegraded
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event auditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			res.Outcome = "degraded"
			return res, errBackendDegraded
		}
		if res.Operation != "" && event.Operation != res.Operation {
			continue
		}
		if res.Ref != "" && event.Ref != res.Ref {
			continue
		}
		event = normalizeAuditEvent(event)
		res.Events = append(res.Events, event)
	}
	if err := scanner.Err(); err != nil {
		res.Outcome = "degraded"
		return res, errBackendDegraded
	}
	res.Chain, res.Events = verifyAuditChain(res.Events)
	if res.Chain.Status == "invalid" {
		res.Outcome = "degraded"
	}
	if refHashOnly {
		for i := range res.Events {
			res.Events[i].Ref = ""
		}
	}
	return res, nil
}

func encodeAdminJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
