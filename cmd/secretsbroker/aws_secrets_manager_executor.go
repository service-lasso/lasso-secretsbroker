package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultAWSSecretsManagerMigrationTimeout  = 3 * time.Second
	maximumAWSSecretsManagerMigrationTimeout  = 30 * time.Second
	defaultAWSSecretsManagerMigrationMaxBytes = 64 * 1024
	maximumAWSSecretsManagerMigrationMaxBytes = 1024 * 1024
)

var awsEnvironmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type awsSecretsManagerMigrationExecutor struct {
	source   sourceConfig
	endpoint url.URL
	client   *http.Client
	now      func() time.Time
}

type awsSecretsManagerCredentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

type awsSecretsManagerMigrationReadResult struct {
	secretString string
	outcome      string
}

type awsSecretsManagerPutSecretValueRequest struct {
	ClientRequestToken string `json:"ClientRequestToken"`
	SecretID           string `json:"SecretId"`
	SecretString       string `json:"SecretString"`
}

func newAWSSecretsManagerMigrationExecutor(source sourceConfig) (*awsSecretsManagerMigrationExecutor, error) {
	if !source.Enabled || !source.EnableMigrationTarget || !strings.EqualFold(strings.TrimSpace(source.Kind), "aws-secrets-manager") {
		return nil, errors.New("AWS Secrets Manager migration target is not explicitly enabled")
	}
	if !validAWSSecretsManagerRegion(source.Region) {
		return nil, errors.New("AWS Secrets Manager migration target region is invalid")
	}
	endpoint, err := validatedAWSSecretsManagerEndpoint(source)
	if err != nil {
		return nil, err
	}
	if !awsSecretsManagerCredentialHandlesConfigured(source) || !awsSecretsManagerCredentialsAvailable(source) {
		return nil, errors.New("AWS Secrets Manager migration target authentication is missing")
	}
	if len(source.Refs) == 0 {
		return nil, errors.New("AWS Secrets Manager migration target has no ref mappings")
	}
	for ref, mapping := range source.Refs {
		if !validSecretRef(ref) || !validAWSSecretsManagerMigrationMapping(mapping) {
			return nil, errors.New("AWS Secrets Manager migration target mapping is invalid")
		}
	}
	client, err := newSourceHTTPClient(maximumAWSSecretsManagerMigrationTimeout, source.Production, rejectCredentialRedirect)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets Manager migration target TLS trust configuration is invalid: %w", err)
	}
	return &awsSecretsManagerMigrationExecutor{
		source:   source,
		endpoint: endpoint,
		client:   client,
		now:      func() time.Time { return time.Now().UTC() },
	}, nil
}

func awsSecretsManagerCredentialHandlesConfigured(source sourceConfig) bool {
	return awsEnvironmentNamePattern.MatchString(strings.TrimSpace(source.AccessKeyIDEnv)) &&
		awsEnvironmentNamePattern.MatchString(strings.TrimSpace(source.SecretAccessKeyEnv)) &&
		(strings.TrimSpace(source.SessionTokenEnv) == "" || awsEnvironmentNamePattern.MatchString(strings.TrimSpace(source.SessionTokenEnv)))
}

func awsSecretsManagerCredentialsAvailable(source sourceConfig) bool {
	credentials := awsSecretsManagerCredentialsFromEnvironment(source)
	return credentials.accessKeyID != "" && credentials.secretAccessKey != ""
}

func awsSecretsManagerCredentialsFromEnvironment(source sourceConfig) awsSecretsManagerCredentials {
	return awsSecretsManagerCredentials{
		accessKeyID:     strings.TrimSpace(os.Getenv(strings.TrimSpace(source.AccessKeyIDEnv))),
		secretAccessKey: strings.TrimSpace(os.Getenv(strings.TrimSpace(source.SecretAccessKeyEnv))),
		sessionToken:    strings.TrimSpace(os.Getenv(strings.TrimSpace(source.SessionTokenEnv))),
	}
}

func validAWSSecretsManagerRegion(region string) bool {
	region = strings.TrimSpace(region)
	if len(region) < 3 || len(region) > 64 {
		return false
	}
	for _, char := range region {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return !strings.HasPrefix(region, "-") && !strings.HasSuffix(region, "-")
}

func validatedAWSSecretsManagerEndpoint(source sourceConfig) (url.URL, error) {
	address := strings.TrimSpace(source.Address)
	if address == "" {
		address = "https://secretsmanager." + strings.TrimSpace(source.Region) + ".amazonaws.com"
	}
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return url.URL{}, errors.New("AWS Secrets Manager migration target address is invalid")
	}
	if parsed.Scheme == "http" && !awsSecretsManagerLoopbackHost(parsed.Hostname()) {
		return url.URL{}, errors.New("AWS Secrets Manager migration target requires HTTPS outside loopback")
	}
	return url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/"}, nil
}

func awsSecretsManagerLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func validAWSSecretsManagerMigrationMapping(mapping sourceRefConfig) bool {
	path := strings.TrimSpace(mapping.Path)
	field := strings.TrimSpace(mapping.Field)
	if path == "" || len(path) > 2048 || len(field) > 256 || strings.TrimSpace(mapping.VersionID) != "" {
		return false
	}
	if stage := strings.TrimSpace(mapping.VersionStage); stage != "" && stage != "AWSCURRENT" {
		return false
	}
	for _, value := range []string{path, field} {
		for _, char := range value {
			if char < 0x20 || char == 0x7f {
				return false
			}
		}
	}
	return true
}

func (e *awsSecretsManagerMigrationExecutor) Write(req providerMigrationWriteRequest) providerMigrationExecutorResult {
	mapping, ok := e.source.Refs[req.Ref]
	if !ok || !validAWSSecretsManagerMigrationMapping(mapping) {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	current := e.read(mapping)
	if current.outcome != "ready" {
		if current.outcome == "missing_ref" {
			return providerMigrationExecutorResult{Outcome: "invalid_ref"}
		}
		return providerMigrationExecutorResult{Outcome: current.outcome}
	}
	secretString, alreadyEqual, outcome := awsSecretsManagerUpdatedSecretString(current.secretString, mapping.Field, req.Value)
	if outcome != "ready" {
		return providerMigrationExecutorResult{Outcome: outcome}
	}
	if alreadyEqual {
		return providerMigrationExecutorResult{Outcome: "applied"}
	}
	payload, err := json.Marshal(awsSecretsManagerPutSecretValueRequest{
		ClientRequestToken: awsSecretsManagerClientRequestToken(req),
		SecretID:           strings.TrimSpace(mapping.Path),
		SecretString:       secretString,
	})
	if err != nil || len(payload) > awsSecretsManagerMigrationMaxBytes(mapping) {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	status, body, requestOutcome := e.request("secretsmanager.PutSecretValue", payload, mapping)
	if requestOutcome != "ready" {
		return providerMigrationExecutorResult{Outcome: requestOutcome}
	}
	if status < 200 || status >= 300 {
		return providerMigrationExecutorResult{Outcome: awsSecretsManagerMigrationStatusOutcome(status, body, true)}
	}
	var response struct {
		VersionID string `json:"VersionId"`
	}
	if len(body) == 0 || json.Unmarshal(body, &response) != nil || strings.TrimSpace(response.VersionID) == "" {
		return providerMigrationExecutorResult{Outcome: "source_unavailable"}
	}
	return providerMigrationExecutorResult{Outcome: "applied"}
}

func (e *awsSecretsManagerMigrationExecutor) Verify(req providerMigrationVerifyRequest) providerMigrationExecutorResult {
	mapping, ok := e.source.Refs[req.Ref]
	if !ok || !validAWSSecretsManagerMigrationMapping(mapping) {
		return providerMigrationExecutorResult{Outcome: "invalid_ref"}
	}
	current := e.read(mapping)
	if current.outcome != "ready" {
		if current.outcome == "missing_ref" || current.outcome == "invalid_ref" {
			return providerMigrationExecutorResult{Outcome: "verification_failed"}
		}
		return providerMigrationExecutorResult{Outcome: current.outcome}
	}
	value, ok := awsSecretsManagerMigrationField(current.secretString, mapping.Field)
	if !ok || value != req.ExpectedValue {
		return providerMigrationExecutorResult{Outcome: "verification_failed"}
	}
	return providerMigrationExecutorResult{Outcome: "verified"}
}

func (e *awsSecretsManagerMigrationExecutor) read(mapping sourceRefConfig) awsSecretsManagerMigrationReadResult {
	payload, err := json.Marshal(awsSecretsManagerGetSecretValueRequest{SecretID: strings.TrimSpace(mapping.Path), VersionStage: firstNonEmpty(strings.TrimSpace(mapping.VersionStage), "AWSCURRENT")})
	if err != nil || len(payload) > awsSecretsManagerMigrationMaxBytes(mapping) {
		return awsSecretsManagerMigrationReadResult{outcome: "invalid_ref"}
	}
	status, body, requestOutcome := e.request("secretsmanager.GetSecretValue", payload, mapping)
	if requestOutcome != "ready" {
		return awsSecretsManagerMigrationReadResult{outcome: requestOutcome}
	}
	if status < 200 || status >= 300 {
		return awsSecretsManagerMigrationReadResult{outcome: awsSecretsManagerMigrationStatusOutcome(status, body, false)}
	}
	var response struct {
		SecretString *string `json:"SecretString"`
		VersionID    string  `json:"VersionId"`
	}
	if len(body) == 0 || json.Unmarshal(body, &response) != nil || response.SecretString == nil || strings.TrimSpace(response.VersionID) == "" {
		return awsSecretsManagerMigrationReadResult{outcome: "source_unavailable"}
	}
	return awsSecretsManagerMigrationReadResult{secretString: *response.SecretString, outcome: "ready"}
}

func awsSecretsManagerUpdatedSecretString(current, field, value string) (string, bool, string) {
	field = strings.TrimSpace(field)
	if field == "" {
		return value, current == value, "ready"
	}
	data := map[string]any{}
	if json.Unmarshal([]byte(current), &data) != nil || data == nil {
		return "", false, "invalid_ref"
	}
	if existing, ok := data[field].(string); ok && existing == value {
		return current, true, "ready"
	}
	data[field] = value
	updated, err := json.Marshal(data)
	if err != nil {
		return "", false, "invalid_ref"
	}
	return string(updated), false, "ready"
}

func awsSecretsManagerMigrationField(secretString, field string) (string, bool) {
	field = strings.TrimSpace(field)
	if field == "" {
		return secretString, true
	}
	data := map[string]any{}
	if json.Unmarshal([]byte(secretString), &data) != nil {
		return "", false
	}
	value, ok := data[field].(string)
	return value, ok
}

func awsSecretsManagerClientRequestToken(req providerMigrationWriteRequest) string {
	material := strings.TrimSpace(req.IdempotencyKey)
	if material == "" {
		material = strings.Join([]string{req.OperationID, req.TargetProviderID, req.Ref}, "\n")
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func (e *awsSecretsManagerMigrationExecutor) request(target string, body []byte, mapping sourceRefConfig) (int, []byte, string) {
	credentials := awsSecretsManagerCredentialsFromEnvironment(e.source)
	if credentials.accessKeyID == "" || credentials.secretAccessKey == "" {
		return 0, nil, "source_auth_required"
	}
	ctx, cancel := context.WithTimeout(context.Background(), awsSecretsManagerMigrationTimeout(mapping))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, "invalid_ref"
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	awsSignSecretsManagerRequest(req, body, strings.TrimSpace(e.source.Region), credentials, e.now().UTC())
	res, err := e.client.Do(req)
	if err != nil {
		return 0, nil, "source_unavailable"
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(res.Body, int64(awsSecretsManagerMigrationMaxBytes(mapping))+1))
	if err != nil || len(responseBody) > awsSecretsManagerMigrationMaxBytes(mapping) {
		return res.StatusCode, nil, "source_unavailable"
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return res.StatusCode, nil, "source_unavailable"
	}
	return res.StatusCode, responseBody, "ready"
}

func awsSignSecretsManagerRequest(req *http.Request, body []byte, region string, credentials awsSecretsManagerCredentials, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if credentials.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", credentials.sessionToken)
	}
	headers := map[string]string{
		"content-type":         canonicalAWSHeaderValue(req.Header.Get("Content-Type")),
		"host":                 strings.ToLower(req.URL.Host),
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
		"x-amz-target":         canonicalAWSHeaderValue(req.Header.Get("X-Amz-Target")),
	}
	if credentials.sessionToken != "" {
		headers["x-amz-security-token"] = canonicalAWSHeaderValue(credentials.sessionToken)
	}
	headerNames := make([]string, 0, len(headers))
	for name := range headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	var canonicalHeaders strings.Builder
	for _, name := range headerNames {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(headers[name])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(headerNames, ";")
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalRequest := strings.Join([]string{req.Method, canonicalURI, req.URL.Query().Encode(), canonicalHeaders.String(), signedHeaders, payloadHash}, "\n")
	scope := strings.Join([]string{date, region, "secretsmanager", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest))}, "\n")
	dateKey := awsHMAC([]byte("AWS4"+credentials.secretAccessKey), date)
	regionKey := awsHMAC(dateKey, region)
	serviceKey := awsHMAC(regionKey, "secretsmanager")
	signingKey := awsHMAC(serviceKey, "aws4_request")
	signature := hex.EncodeToString(awsHMAC(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credentials.accessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func canonicalAWSHeaderValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func awsHMAC(key []byte, value string) []byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(value))
	return hash.Sum(nil)
}

func awsSecretsManagerMigrationStatusOutcome(status int, body []byte, write bool) string {
	var payload struct {
		Type string `json:"__type"`
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &payload)
	errorType := strings.ToLower(firstNonEmpty(payload.Type, payload.Code))
	switch {
	case strings.Contains(errorType, "expiredtoken"), strings.Contains(errorType, "unrecognizedclient"), strings.Contains(errorType, "invalidclienttoken"), strings.Contains(errorType, "missingauthentication"):
		return "source_auth_required"
	case strings.Contains(errorType, "accessdenied"), strings.Contains(errorType, "notauthorized"):
		return "policy_denied"
	case strings.Contains(errorType, "throttl"), strings.Contains(errorType, "limitexceeded"):
		return "rate_limited"
	case strings.Contains(errorType, "resourceexists"), strings.Contains(errorType, "conflict"):
		return "conflict"
	case strings.Contains(errorType, "resourcenotfound"):
		if write {
			return "invalid_ref"
		}
		return "missing_ref"
	case strings.Contains(errorType, "invalidrequest"), strings.Contains(errorType, "invalidparameter"):
		return "invalid_ref"
	case strings.Contains(errorType, "internalservice"), strings.Contains(errorType, "serviceunavailable"), strings.Contains(errorType, "decryptionfailure"):
		return "source_unavailable"
	}
	switch status {
	case http.StatusUnauthorized:
		return "source_auth_required"
	case http.StatusForbidden:
		return "policy_denied"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusConflict, http.StatusPreconditionFailed:
		return "conflict"
	case http.StatusNotFound:
		if write {
			return "invalid_ref"
		}
		return "missing_ref"
	case http.StatusBadRequest:
		return "invalid_ref"
	}
	if status >= 500 || status == http.StatusRequestTimeout || (status >= 300 && status < 400) {
		return "source_unavailable"
	}
	return "invalid_ref"
}

func awsSecretsManagerMigrationTimeout(mapping sourceRefConfig) time.Duration {
	timeout := time.Duration(firstPositive(mapping.TimeoutMs, int(defaultAWSSecretsManagerMigrationTimeout/time.Millisecond))) * time.Millisecond
	if timeout < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	if timeout > maximumAWSSecretsManagerMigrationTimeout {
		return maximumAWSSecretsManagerMigrationTimeout
	}
	return timeout
}

func awsSecretsManagerMigrationMaxBytes(mapping sourceRefConfig) int {
	limit := firstPositive(mapping.MaxBytes, firstPositive(mapping.MaxStdoutBytes, defaultAWSSecretsManagerMigrationMaxBytes))
	if limit > maximumAWSSecretsManagerMigrationMaxBytes {
		return maximumAWSSecretsManagerMigrationMaxBytes
	}
	return limit
}
