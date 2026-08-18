package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRecoveryPolicyMetadataPersistsAndAuditsSafeMetadataOnly(t *testing.T) {
	backend := testBackend(t)
	res, err := backend.upsertRecoveryPolicy(recoveryPolicyRequest{
		RequestID:             "req-recovery-create",
		ServiceID:             "@operator",
		PolicyID:              "recovery-policy-1",
		KeyID:                 "mk-safe-key",
		KeyVersion:            masterKeyVersion,
		Threshold:             2,
		ShareCount:            3,
		ShareFingerprints:     []string{"share-fp-1", "share-fp-2", "share-fp-3"},
		RecipientFingerprints: []string{"age-recipient-1", "age-recipient-2", "age-recipient-3"},
		Status:                "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "active" || res.Policy == nil || res.Policy.NextAction != "monitor_recovery_policy" {
		t.Fatalf("recovery create response = %#v", res)
	}

	status, err := backend.recoveryPolicyStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Policy == nil || status.Policy.PolicyID != "recovery-policy-1" || status.Policy.Threshold != 2 || len(status.Policy.ShareFingerprints) != 3 {
		t.Fatalf("recovery status = %#v", status)
	}

	storeBytes, err := os.ReadFile(backend.storePath)
	if err != nil {
		t.Fatal(err)
	}
	auditBytes, err := os.ReadFile(backend.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, storeBytes, "portable-master-key-bytes", "plaintext-recovery-share", "recipient-private-key", "source-credential-value")
	assertNoSecretMaterial(t, auditBytes, "portable-master-key-bytes", "plaintext-recovery-share", "recipient-private-key", "source-credential-value")
	for _, want := range []string{"recovery_policy_create", "recovery_policy_status", "recovery-policy-1", "mk-safe-key"} {
		if !bytes.Contains(auditBytes, []byte(want)) {
			t.Fatalf("audit missing %q: %s", want, auditBytes)
		}
	}
}

func TestRecoveryPolicyMetadataValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		req  recoveryPolicyRequest
	}{
		{name: "missing key id", req: recoveryPolicyRequest{PolicyID: "policy", Threshold: 1, ShareCount: 1, ShareFingerprints: []string{"share-fp-1"}}},
		{name: "threshold greater than shares", req: recoveryPolicyRequest{PolicyID: "policy", KeyID: "mk-safe", Threshold: 3, ShareCount: 2, ShareFingerprints: []string{"share-fp-1", "share-fp-2"}}},
		{name: "missing share fingerprint", req: recoveryPolicyRequest{PolicyID: "policy", KeyID: "mk-safe", Threshold: 1, ShareCount: 2, ShareFingerprints: []string{"share-fp-1"}}},
		{name: "duplicate share fingerprint", req: recoveryPolicyRequest{PolicyID: "policy", KeyID: "mk-safe", Threshold: 1, ShareCount: 2, ShareFingerprints: []string{"share-fp-1", "share-fp-1"}}},
		{name: "bad status", req: recoveryPolicyRequest{PolicyID: "policy", KeyID: "mk-safe", Threshold: 1, ShareCount: 1, ShareFingerprints: []string{"share-fp-1"}, Status: "plaintext"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := testBackend(t)
			res, err := backend.upsertRecoveryPolicy(tt.req)
			if !errors.Is(err, errInvalidRecoveryPolicy) || res.Outcome != "policy_denied" {
				t.Fatalf("err=%v res=%#v", err, res)
			}
			status, statusErr := backend.recoveryPolicyStatus()
			if statusErr != nil || status.Policy != nil || status.Outcome != "setup_needed" {
				t.Fatalf("invalid metadata should not persist, status=%#v err=%v", status, statusErr)
			}
		})
	}
}

func TestHTTPRecoveryPolicyRejectsUnknownSecretMaterialField(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"policyId":"recovery-policy-1","keyId":"mk-safe-key","threshold":1,"shareCount":1,"shareFingerprints":["share-fp-1"],"recoveryShare":"plaintext-recovery-share"}`)
	res, payload := postJSON(t, server.URL+"/v1/recovery/policy", "test-token", body)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown secret field status=%d body=%s", res.StatusCode, payload)
	}
	assertNoSecretMaterial(t, payload, "plaintext-recovery-share", "test-token")

	statusRes, err := http.Get(server.URL + "/v1/recovery/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer statusRes.Body.Close()
	statusPayload, err := io.ReadAll(statusRes.Body)
	if err != nil {
		t.Fatal(err)
	}
	if statusRes.StatusCode != http.StatusOK || !bytes.Contains(statusPayload, []byte(`"outcome":"setup_needed"`)) {
		t.Fatalf("status after rejection code=%d body=%s", statusRes.StatusCode, statusPayload)
	}
	assertNoSecretMaterial(t, statusPayload, "plaintext-recovery-share", "test-token")
}

func TestRecoveryPolicyHTTPAndCLIStatusExposeSafeLifecycle(t *testing.T) {
	backend := testBackend(t)
	state := "ready"
	server := httptest.NewServer(newHandler(runtimeState{state: &state}, backend, localAPISecurity{token: "test-token"}))
	defer server.Close()

	body := []byte(`{"requestId":"req-http-recovery","serviceId":"@operator","policyId":"policy-http","keyId":"mk-http-safe","threshold":2,"shareCount":2,"shareFingerprints":["share-fp-a","share-fp-b"],"recipientFingerprints":["age-recipient-a","age-recipient-b"]}`)
	res, payload := postJSON(t, server.URL+"/v1/recovery/policy", "test-token", body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll status=%d body=%s", res.StatusCode, payload)
	}
	assertNoSecretMaterial(t, payload, "test-token", "portable-master-key-bytes")

	var cli bytes.Buffer
	if err := executeAdmin([]string{"recovery", "status", "--store", backend.storePath, "--audit", backend.auditPath, "--wrapper", backend.wrapperPath}, &cli); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, cli.Bytes(), "test-token", "portable-master-key-bytes")
	if !bytes.Contains(cli.Bytes(), []byte(`"policyId": "policy-http"`)) || !bytes.Contains(cli.Bytes(), []byte(`"nextAction": "monitor_recovery_policy"`)) {
		t.Fatalf("cli recovery status missing lifecycle metadata: %s", cli.String())
	}

	var adminStatus bytes.Buffer
	if err := executeAdmin([]string{"status", "--store", backend.storePath, "--audit", backend.auditPath, "--master-key", "test-master-key"}, &adminStatus); err != nil {
		t.Fatal(err)
	}
	assertNoSecretMaterial(t, adminStatus.Bytes(), "test-token", "portable-master-key-bytes")
	if !strings.Contains(adminStatus.String(), `"recovery"`) || !strings.Contains(adminStatus.String(), `"policy-http"`) {
		t.Fatalf("admin status missing recovery metadata: %s", adminStatus.String())
	}
}

func TestRecoveryPolicyRevokeSetsSafeLifecycleState(t *testing.T) {
	backend := testBackend(t)
	if _, err := backend.upsertRecoveryPolicy(recoveryPolicyRequest{PolicyID: "policy-revoke", KeyID: "mk-revoke", Threshold: 1, ShareCount: 1, ShareFingerprints: []string{"share-fp-1"}}); err != nil {
		t.Fatal(err)
	}
	res, err := backend.revokeRecoveryPolicy("policy-revoke", "@operator", "req-revoke")
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "revoked" || res.Policy == nil || res.Policy.RevokedAt == nil || res.NextAction != "enroll_replacement_recovery_policy" {
		t.Fatalf("revoke response = %#v", res)
	}
}
