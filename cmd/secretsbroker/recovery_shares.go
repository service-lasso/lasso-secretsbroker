package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	recoveryShareVersion             = 1
	recoveryShareAlg                 = "shamir-gf256-v1"
	recoveryShareEnvelopeAgeX25519V1 = "age-x25519-v1"
	maxRecoveryShareSize             = 64 * 1024
)

var (
	errInvalidRecoveryShare        = errors.New("invalid recovery share")
	errInsufficientRecoveryShares  = errors.New("insufficient recovery shares")
	errRecoveryShareOutputRequired = errors.New("explicit recovery share output targets are required")
	errRecoveryKeyMismatch         = errors.New("recovery shares do not match store key")
)

type recoveryShareFile struct {
	Version          int                    `json:"version"`
	ServiceID        string                 `json:"serviceId"`
	APIVersion       string                 `json:"apiVersion"`
	PolicyID         string                 `json:"policyId"`
	KeyID            string                 `json:"keyId"`
	KeyVersion       string                 `json:"keyVersion"`
	Threshold        int                    `json:"threshold"`
	ShareCount       int                    `json:"shareCount"`
	ShareIndex       int                    `json:"shareIndex"`
	Alg              string                 `json:"alg"`
	Share            string                 `json:"share,omitempty"`
	Envelope         *recoveryShareEnvelope `json:"envelope,omitempty"`
	ShareFingerprint string                 `json:"shareFingerprint"`
	CreatedAt        time.Time              `json:"createdAt"`
}

type recoveryShareEnvelope struct {
	Format               string `json:"format"`
	RecipientFingerprint string `json:"recipientFingerprint"`
	Ciphertext           string `json:"ciphertext"`
}

type recoveryShareGenerateRequest struct {
	PolicyID          string
	Threshold         int
	Outputs           []string
	AgeRecipients     []string
	AgeRecipientFiles []string
	ServiceID         string
	RequestID         string
}

type recoveryShareImportRequest struct {
	Inputs           []string
	AgeIdentities    []string
	AgeIdentityFiles []string
	WrapperPath      string
	OS               string
	ServiceID        string
	RequestID        string
}

type recoveryShareFileMetadata struct {
	ShareIndex           int    `json:"shareIndex"`
	Path                 string `json:"path"`
	ShareFingerprint     string `json:"shareFingerprint"`
	EnvelopeFormat       string `json:"envelopeFormat,omitempty"`
	RecipientFingerprint string `json:"recipientFingerprint,omitempty"`
}

type recoveryShareOperationResponse struct {
	ServiceID   string                      `json:"serviceId"`
	APIVersion  string                      `json:"apiVersion"`
	Outcome     string                      `json:"outcome"`
	KeyID       string                      `json:"keyId,omitempty"`
	KeyVersion  string                      `json:"keyVersion,omitempty"`
	Policy      *recoveryPolicyMetadata     `json:"policy,omitempty"`
	Shares      []recoveryShareFileMetadata `json:"shares,omitempty"`
	StorePath   string                      `json:"storePath,omitempty"`
	WrapperPath string                      `json:"wrapperPath,omitempty"`
	Wrapper     *wrapperStatusDetail        `json:"wrapper,omitempty"`
	SecretCount int                         `json:"secretCount"`
	NextAction  string                      `json:"nextAction"`
	AuditStatus string                      `json:"auditStatus"`
}

func runKeyRecovery(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown key recovery command %q", "")
	}
	switch args[0] {
	case "generate":
		return runKeyRecoveryGenerate(args[1:])
	case "import":
		return runKeyRecoveryImport(args[1:])
	default:
		return fmt.Errorf("unknown key recovery command %q", args[0])
	}
}

func runKeyRecoveryGenerate(args []string) error {
	fs := flag.NewFlagSet("key recovery generate", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "portable master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path used when explicit master-key input is absent")
	policyID := fs.String("policy-id", "", "recovery policy id")
	threshold := fs.Int("threshold", 0, "threshold required to recover")
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	outputs := multiFlag{}
	ageRecipients := multiFlag{}
	ageRecipientFiles := multiFlag{}
	fs.Var(&outputs, "share-out", "explicit recovery share output file; repeatable")
	fs.Var(&ageRecipients, "age-recipient", "age/X25519 recipient for encrypted share output; repeatable and ordered with --share-out")
	fs.Var(&ageRecipientFiles, "age-recipient-file", "file containing age/X25519 recipient; repeatable and ordered with --share-out")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterialWithWrapper(*masterKey, *masterKeyFile, *wrapperPath)
	if err != nil {
		return err
	}
	backend := audit.newBackend(*storePath, material.Value)
	res, err := backend.generateRecoveryShares(recoveryShareGenerateRequest{PolicyID: *policyID, Threshold: *threshold, Outputs: []string(outputs), AgeRecipients: []string(ageRecipients), AgeRecipientFiles: []string(ageRecipientFiles), ServiceID: *service, RequestID: *requestID})
	if err != nil {
		_ = encodeIndented(os.Stdout, res)
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func runKeyRecoveryImport(args []string) error {
	fs := flag.NewFlagSet("key recovery import", flag.ContinueOnError)
	storePath := fs.String("store", getenvDefault("SECRETSBROKER_STORE_PATH", defaultStorePath()), "local encrypted store path")
	audit := addAuditCommandOptions(fs)
	wrapperPath := fs.String("wrapper", getenvDefault("SECRETSBROKER_WRAPPER_PATH", defaultWrapperPath()), "local OS wrapper path")
	osName := fs.String("os", runtime.GOOS, "wrapper OS override for validation/testing")
	requestID := fs.String("request-id", "", "request id")
	service := fs.String("service-id", "@operator", "requesting service/operator id")
	inputs := multiFlag{}
	ageIdentities := multiFlag{}
	ageIdentityFiles := multiFlag{}
	fs.Var(&inputs, "share-in", "explicit recovery share input file; repeatable")
	fs.Var(&ageIdentities, "age-identity", "local age/X25519 identity for encrypted recovery share import; repeatable")
	fs.Var(&ageIdentityFiles, "age-identity-file", "file containing local age/X25519 identity; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend := audit.newBackend(*storePath, "")
	res, err := backend.importRecoveryShares(recoveryShareImportRequest{Inputs: []string(inputs), AgeIdentities: []string(ageIdentities), AgeIdentityFiles: []string(ageIdentityFiles), WrapperPath: *wrapperPath, OS: *osName, ServiceID: *service, RequestID: *requestID})
	if err != nil {
		_ = encodeIndented(os.Stdout, res)
		return err
	}
	return encodeIndented(os.Stdout, res)
}

func (b *localBackend) generateRecoveryShares(req recoveryShareGenerateRequest) (recoveryShareOperationResponse, error) {
	res := recoveryShareOperationResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "degraded", StorePath: b.storePath, NextAction: "inspect_recovery_share_generation", AuditStatus: "audit_recorded"}
	if err := validatePortableMasterKey(b.masterKey); err != nil {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "locked", req.ServiceID, req.RequestID)
		res.Outcome = "locked"
		res.NextAction = "provide_portable_master_key"
		return res, err
	}
	b.masterKey = strings.TrimSpace(b.masterKey)
	state, secretCount, err := b.validateStoreForKey()
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_generate", "", state, req.ServiceID, req.RequestID)
		res.Outcome = state
		res.SecretCount = secretCount
		res.NextAction = "verify_store_before_recovery_enrollment"
		return res, err
	}
	outputs := safeList(req.Outputs)
	if len(outputs) == 0 {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "policy_denied", req.ServiceID, req.RequestID)
		res.Outcome = "policy_denied"
		res.NextAction = "provide_explicit_share_output_targets"
		return res, errRecoveryShareOutputRequired
	}
	if hasDuplicate(outputs) {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "policy_denied", req.ServiceID, req.RequestID)
		res.Outcome = "policy_denied"
		res.NextAction = "provide_unique_share_output_targets"
		return res, errRecoveryShareOutputRequired
	}
	if req.Threshold < 1 || req.Threshold > len(outputs) || len(outputs) > 255 {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "policy_denied", req.ServiceID, req.RequestID)
		res.Outcome = "policy_denied"
		res.NextAction = "provide_valid_threshold_and_share_count"
		return res, errInvalidRecoveryPolicy
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(b.masterKey)
	if err != nil || len(keyBytes) != 32 {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "locked", req.ServiceID, req.RequestID)
		res.Outcome = "locked"
		res.NextAction = "provide_valid_portable_master_key"
		return res, errInvalidMasterKey
	}
	defer zeroBytes(keyBytes)
	shares, err := splitSecretGF256(keyBytes, req.Threshold, len(outputs))
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "degraded", req.ServiceID, req.RequestID)
		res.NextAction = "retry_recovery_share_generation"
		return res, err
	}
	recipients, recipientFingerprints, err := loadAgeRecipients(req.AgeRecipients, req.AgeRecipientFiles, len(outputs))
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_generate", "", "policy_denied", req.ServiceID, req.RequestID)
		res.Outcome = "policy_denied"
		res.NextAction = "provide_valid_age_recipients"
		return res, err
	}
	keyID := masterKeyID(b.masterKey)
	policyID := scrubAuditField(req.PolicyID)
	if policyID == "" {
		policyID = "recovery-" + keyID
	}
	now := b.now().UTC()
	metadata := make([]recoveryShareFileMetadata, 0, len(shares))
	fingerprints := make([]string, 0, len(shares))
	files := make([]recoveryShareFile, 0, len(shares))
	for i, share := range shares {
		encodedShare := base64.RawURLEncoding.EncodeToString(share.Value)
		fp := recoveryShareFingerprint(policyID, keyID, share.Index, encodedShare)
		file := recoveryShareFile{Version: recoveryShareVersion, ServiceID: serviceID, APIVersion: apiVersion, PolicyID: policyID, KeyID: keyID, KeyVersion: masterKeyVersion, Threshold: req.Threshold, ShareCount: len(shares), ShareIndex: share.Index, Alg: recoveryShareAlg, Share: encodedShare, ShareFingerprint: fp, CreatedAt: now}
		meta := recoveryShareFileMetadata{ShareIndex: share.Index, Path: outputs[i], ShareFingerprint: fp}
		if len(recipients) > 0 {
			ciphertext, err := encryptAgeEnvelope(encodedShare, recipients[i])
			if err != nil {
				_ = b.auditRecoveryShares("recovery_share_generate", policyID, "degraded", req.ServiceID, req.RequestID)
				res.NextAction = "retry_recovery_share_envelope_generation"
				return res, err
			}
			file.Share = ""
			file.Envelope = &recoveryShareEnvelope{Format: recoveryShareEnvelopeAgeX25519V1, RecipientFingerprint: recipientFingerprints[i], Ciphertext: ciphertext}
			meta.EnvelopeFormat = recoveryShareEnvelopeAgeX25519V1
			meta.RecipientFingerprint = recipientFingerprints[i]
		}
		files = append(files, file)
		fingerprints = append(fingerprints, fp)
		metadata = append(metadata, meta)
	}
	if _, err := normalizeRecoveryPolicyRequest(recoveryPolicyRequest{PolicyID: policyID, KeyID: keyID, KeyVersion: masterKeyVersion, Threshold: req.Threshold, ShareCount: len(shares), ShareFingerprints: fingerprints, RecipientFingerprints: recipientFingerprints, CreatedAt: &now, Status: "active"}, now); err != nil {
		_ = b.auditRecoveryShares("recovery_share_generate", policyID, "policy_denied", req.ServiceID, req.RequestID)
		res.Outcome = "policy_denied"
		res.NextAction = "provide_valid_recovery_policy_metadata"
		return res, err
	}
	for i, file := range files {
		if err := writeRecoveryShareFile(outputs[i], file); err != nil {
			_ = b.auditRecoveryShares("recovery_share_generate", policyID, "degraded", req.ServiceID, req.RequestID)
			res.NextAction = "inspect_recovery_share_output_targets"
			return res, err
		}
	}
	policyRes, err := b.upsertRecoveryPolicy(recoveryPolicyRequest{RequestID: req.RequestID, ServiceID: req.ServiceID, PolicyID: policyID, KeyID: keyID, KeyVersion: masterKeyVersion, Threshold: req.Threshold, ShareCount: len(shares), ShareFingerprints: fingerprints, RecipientFingerprints: recipientFingerprints, CreatedAt: &now, Status: "active"})
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_generate", policyID, "degraded", req.ServiceID, req.RequestID)
		return res, err
	}
	_ = b.auditRecoveryShares("recovery_share_generate", policyID, "ready", req.ServiceID, req.RequestID)
	return recoveryShareOperationResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", KeyID: keyID, KeyVersion: masterKeyVersion, Policy: policyRes.Policy, Shares: metadata, StorePath: b.storePath, SecretCount: secretCount, NextAction: "store_recovery_shares_separately_and_verify_recovery_import", AuditStatus: "audit_recorded"}, nil
}

func (b *localBackend) importRecoveryShares(req recoveryShareImportRequest) (recoveryShareOperationResponse, error) {
	return b.importRecoverySharesWithProvider(req, wrapperContextFor(req.OS), platformKeyWrapperProvider())
}

func (b *localBackend) importRecoverySharesWithProvider(req recoveryShareImportRequest, ctx wrapperContext, provider keyWrapperProvider) (recoveryShareOperationResponse, error) {
	res := recoveryShareOperationResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "locked", StorePath: b.storePath, WrapperPath: req.WrapperPath, NextAction: "provide_threshold_recovery_shares", AuditStatus: "audit_recorded"}
	inputs := safeList(req.Inputs)
	if len(inputs) == 0 {
		_ = b.auditRecoveryShares("recovery_share_import", "", "locked", req.ServiceID, req.RequestID)
		return res, errInsufficientRecoveryShares
	}
	identities, err := loadAgeIdentities(req.AgeIdentities, req.AgeIdentityFiles)
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_import", "", "locked", req.ServiceID, req.RequestID)
		res.NextAction = "provide_valid_age_identities"
		return res, err
	}
	shareFiles := make([]recoveryShareFile, 0, len(inputs))
	metadata := make([]recoveryShareFileMetadata, 0, len(inputs))
	for _, path := range inputs {
		file, err := readRecoveryShareFile(path)
		if err != nil {
			_ = b.auditRecoveryShares("recovery_share_import", "", "locked", req.ServiceID, req.RequestID)
			res.NextAction = "inspect_recovery_share_files"
			return res, err
		}
		shareFiles = append(shareFiles, file)
		meta := recoveryShareFileMetadata{ShareIndex: file.ShareIndex, Path: path, ShareFingerprint: file.ShareFingerprint}
		if file.Envelope != nil {
			meta.EnvelopeFormat = file.Envelope.Format
			meta.RecipientFingerprint = file.Envelope.RecipientFingerprint
		}
		metadata = append(metadata, meta)
	}
	header, sharePoints, err := validateRecoveryShareSet(shareFiles, identities)
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_import", "", "locked", req.ServiceID, req.RequestID)
		res.Shares = metadata
		res.NextAction = "provide_valid_threshold_recovery_shares"
		return res, err
	}
	res.KeyID = header.KeyID
	res.KeyVersion = header.KeyVersion
	res.Shares = metadata
	if len(sharePoints) < header.Threshold {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "locked", req.ServiceID, req.RequestID)
		res.NextAction = "provide_configured_threshold_number_of_shares"
		return res, errInsufficientRecoveryShares
	}
	recoveredBytes, err := combineSecretGF256(sharePoints[:header.Threshold])
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "locked", req.ServiceID, req.RequestID)
		res.NextAction = "provide_valid_threshold_recovery_shares"
		return res, err
	}
	defer zeroBytes(recoveredBytes)
	recoveredKey := base64.RawURLEncoding.EncodeToString(recoveredBytes)
	if err := validatePortableMasterKey(recoveredKey); err != nil {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "locked", req.ServiceID, req.RequestID)
		res.NextAction = "provide_valid_threshold_recovery_shares"
		return res, err
	}
	if masterKeyID(recoveredKey) != header.KeyID {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "locked", req.ServiceID, req.RequestID)
		res.NextAction = "provide_recovery_shares_for_matching_key"
		return res, errRecoveryKeyMismatch
	}
	if !ctx.Supported {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "degraded", req.ServiceID, req.RequestID)
		res.Outcome = "degraded"
		res.NextAction = "use_portable_key_unlock_until_wrapper_supported"
		return res, errUnsupportedOSWrapper
	}
	b.masterKey = recoveredKey
	state, secretCount, err := b.validateStoreForKey()
	res.SecretCount = secretCount
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, state, req.ServiceID, req.RequestID)
		res.Outcome = state
		res.NextAction = "inspect_store_before_wrapper_refresh"
		return res, err
	}
	wrapper, err := wrapMasterKeyWithProvider(req.WrapperPath, recoveredKey, ctx, b.now(), provider)
	if err != nil {
		_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "degraded", req.ServiceID, req.RequestID)
		res.Outcome = "degraded"
		res.NextAction = "inspect_wrapper_output_target"
		return res, err
	}
	_ = b.auditRecoveryShares("recovery_share_import", header.PolicyID, "ready", req.ServiceID, req.RequestID)
	detail := wrapper.detail(true, "ready", "")
	return recoveryShareOperationResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: "ready", KeyID: wrapper.KeyID, KeyVersion: wrapper.KeyVersion, Shares: metadata, StorePath: b.storePath, WrapperPath: req.WrapperPath, Wrapper: &detail, SecretCount: secretCount, NextAction: "operate_normally", AuditStatus: "audit_recorded"}, nil
}

func (b *localBackend) auditRecoveryShares(operation, policyID, outcome, requestServiceID, requestID string) error {
	return b.writeAuditEvent(auditEvent{TS: b.now(), Operation: operation, PolicyID: policyID, Outcome: outcome, ServiceID: requestServiceID, RequestID: requestID})
}

type recoverySharePoint struct {
	Index int
	Value []byte
}

func splitSecretGF256(secret []byte, threshold, shareCount int) ([]recoverySharePoint, error) {
	if threshold < 1 || threshold > shareCount || shareCount > 255 || len(secret) == 0 {
		return nil, errInvalidRecoveryPolicy
	}
	shares := make([]recoverySharePoint, shareCount)
	for i := range shares {
		shares[i] = recoverySharePoint{Index: i + 1, Value: make([]byte, len(secret))}
	}
	coefficients := make([]byte, threshold)
	for secretIndex, secretByte := range secret {
		coefficients[0] = secretByte
		if threshold > 1 {
			if _, err := io.ReadFull(rand.Reader, coefficients[1:]); err != nil {
				return nil, err
			}
		}
		for shareIndex := range shares {
			x := byte(shares[shareIndex].Index)
			y := coefficients[threshold-1]
			for i := threshold - 2; i >= 0; i-- {
				y = gfMul(y, x) ^ coefficients[i]
				if i == 0 {
					break
				}
			}
			shares[shareIndex].Value[secretIndex] = y
		}
	}
	zeroBytes(coefficients)
	return shares, nil
}

func combineSecretGF256(shares []recoverySharePoint) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errInsufficientRecoveryShares
	}
	length := len(shares[0].Value)
	if length == 0 {
		return nil, errInvalidRecoveryShare
	}
	seen := map[int]struct{}{}
	for _, share := range shares {
		if share.Index < 1 || share.Index > 255 || len(share.Value) != length {
			return nil, errInvalidRecoveryShare
		}
		if _, ok := seen[share.Index]; ok {
			return nil, errInvalidRecoveryShare
		}
		seen[share.Index] = struct{}{}
	}
	secret := make([]byte, length)
	for byteIndex := 0; byteIndex < length; byteIndex++ {
		var value byte
		for i, share := range shares {
			xi := byte(share.Index)
			basis := byte(1)
			for j, other := range shares {
				if i == j {
					continue
				}
				xj := byte(other.Index)
				denominator := xi ^ xj
				if denominator == 0 {
					return nil, errInvalidRecoveryShare
				}
				basis = gfMul(basis, gfDiv(xj, denominator))
			}
			value ^= gfMul(share.Value[byteIndex], basis)
		}
		secret[byteIndex] = value
	}
	return secret, nil
}

func validateRecoveryShareSet(files []recoveryShareFile, identities []age.Identity) (recoveryShareFile, []recoverySharePoint, error) {
	if len(files) == 0 {
		return recoveryShareFile{}, nil, errInsufficientRecoveryShares
	}
	header := files[0]
	if err := validateRecoveryShareHeader(header); err != nil {
		return recoveryShareFile{}, nil, err
	}
	points := make([]recoverySharePoint, 0, len(files))
	seen := map[int]struct{}{}
	for _, file := range files {
		if err := validateRecoveryShareHeader(file); err != nil {
			return recoveryShareFile{}, nil, err
		}
		if file.PolicyID != header.PolicyID || file.KeyID != header.KeyID || file.KeyVersion != header.KeyVersion || file.Threshold != header.Threshold || file.ShareCount != header.ShareCount {
			return recoveryShareFile{}, nil, errInvalidRecoveryShare
		}
		if _, ok := seen[file.ShareIndex]; ok {
			return recoveryShareFile{}, nil, errInvalidRecoveryShare
		}
		seen[file.ShareIndex] = struct{}{}
		encodedShare, err := recoverySharePlaintext(file, identities)
		if err != nil {
			return recoveryShareFile{}, nil, err
		}
		shareValue, err := base64.RawURLEncoding.DecodeString(encodedShare)
		if err != nil || len(shareValue) == 0 {
			return recoveryShareFile{}, nil, errInvalidRecoveryShare
		}
		if recoveryShareFingerprint(file.PolicyID, file.KeyID, file.ShareIndex, encodedShare) != file.ShareFingerprint {
			return recoveryShareFile{}, nil, errInvalidRecoveryShare
		}
		points = append(points, recoverySharePoint{Index: file.ShareIndex, Value: shareValue})
	}
	return header, points, nil
}

func validateRecoveryShareHeader(file recoveryShareFile) error {
	if file.Version != recoveryShareVersion || file.ServiceID != serviceID || file.APIVersion != apiVersion || file.Alg != recoveryShareAlg {
		return errInvalidRecoveryShare
	}
	if !validSafeMetadataID(file.PolicyID) || !validSafeMetadataID(file.KeyID) || !validSafeMetadataID(file.KeyVersion) || !validSafeMetadataID(file.ShareFingerprint) {
		return errInvalidRecoveryShare
	}
	if file.Threshold < 1 || file.ShareCount < 1 || file.Threshold > file.ShareCount || file.ShareCount > 255 || file.ShareIndex < 1 || file.ShareIndex > file.ShareCount {
		return errInvalidRecoveryShare
	}
	hasShare := strings.TrimSpace(file.Share) != ""
	hasEnvelope := file.Envelope != nil
	if hasShare == hasEnvelope || file.CreatedAt.IsZero() {
		return errInvalidRecoveryShare
	}
	if hasEnvelope && validateRecoveryShareEnvelope(*file.Envelope) != nil {
		return errInvalidRecoveryShare
	}
	return nil
}

func validateRecoveryShareEnvelope(envelope recoveryShareEnvelope) error {
	if envelope.Format != recoveryShareEnvelopeAgeX25519V1 {
		return errInvalidRecoveryShare
	}
	if !validSafeMetadataID(envelope.RecipientFingerprint) || strings.TrimSpace(envelope.Ciphertext) == "" {
		return errInvalidRecoveryShare
	}
	return nil
}

func recoverySharePlaintext(file recoveryShareFile, identities []age.Identity) (string, error) {
	if strings.TrimSpace(file.Share) != "" {
		return file.Share, nil
	}
	if file.Envelope == nil || validateRecoveryShareEnvelope(*file.Envelope) != nil {
		return "", errInvalidRecoveryShare
	}
	if len(identities) == 0 {
		return "", errInvalidRecoveryShare
	}
	if file.Envelope.Format != recoveryShareEnvelopeAgeX25519V1 {
		return "", errInvalidRecoveryShare
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(file.Envelope.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return "", errInvalidRecoveryShare
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return "", errInvalidRecoveryShare
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxRecoveryShareSize))
	if err != nil || len(plaintext) == 0 {
		return "", errInvalidRecoveryShare
	}
	return strings.TrimSpace(string(plaintext)), nil
}

func writeRecoveryShareFile(path string, share recoveryShareFile) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errRecoveryShareOutputRequired
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("recovery share output already exists: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(share, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, bytes, 0o600)
}

func readRecoveryShareFile(path string) (recoveryShareFile, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return recoveryShareFile{}, err
	}
	defer file.Close()
	dec := json.NewDecoder(io.LimitReader(file, maxRecoveryShareSize))
	dec.DisallowUnknownFields()
	var share recoveryShareFile
	if err := dec.Decode(&share); err != nil {
		return recoveryShareFile{}, errInvalidRecoveryShare
	}
	if err := validateRecoveryShareHeader(share); err != nil {
		return recoveryShareFile{}, err
	}
	return share, nil
}

func recoveryShareFingerprint(policyID, keyID string, shareIndex int, encodedShare string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{policyID, keyID, fmt.Sprintf("%d", shareIndex), encodedShare}, "|")))
	return "share-" + hex.EncodeToString(sum[:])[:16]
}

func loadAgeRecipients(inlineRecipients, recipientFiles []string, expectedCount int) ([]age.Recipient, []string, error) {
	specs, err := loadAgeStrings(inlineRecipients, recipientFiles)
	if err != nil {
		return nil, nil, err
	}
	if len(specs) == 0 {
		return nil, nil, nil
	}
	if len(specs) != expectedCount {
		return nil, nil, errInvalidRecoveryPolicy
	}
	recipients := make([]age.Recipient, 0, len(specs))
	fingerprints := make([]string, 0, len(specs))
	for _, spec := range specs {
		recipient, err := age.ParseX25519Recipient(spec)
		if err != nil {
			return nil, nil, errInvalidRecoveryPolicy
		}
		recipients = append(recipients, recipient)
		fingerprints = append(fingerprints, ageRecipientFingerprint(spec))
	}
	return recipients, fingerprints, nil
}

func loadAgeIdentities(inlineIdentities, identityFiles []string) ([]age.Identity, error) {
	specs, err := loadAgeStrings(inlineIdentities, identityFiles)
	if err != nil {
		return nil, err
	}
	identities := make([]age.Identity, 0, len(specs))
	for _, spec := range specs {
		identity, err := age.ParseX25519Identity(spec)
		if err != nil {
			return nil, errInvalidRecoveryShare
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func loadAgeStrings(inlineValues, files []string) ([]string, error) {
	values := make([]string, 0, len(inlineValues)+len(files))
	for _, value := range inlineValues {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	for _, path := range files {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(bytes), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			values = append(values, line)
		}
	}
	return values, nil
}

func encryptAgeEnvelope(plaintext string, recipient age.Recipient) (string, error) {
	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write([]byte(plaintext)); err != nil {
		_ = writer.Close()
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

func ageRecipientFingerprint(recipient string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(recipient)))
	return "age-" + hex.EncodeToString(sum[:])[:16]
}

func gfMul(a, b byte) byte {
	var product byte
	for b != 0 {
		if b&1 == 1 {
			product ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return product
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	var result byte = 1
	base := a
	power := 254
	for power > 0 {
		if power&1 == 1 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
		power >>= 1
	}
	return result
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}
