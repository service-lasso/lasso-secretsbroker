package main

import (
	"errors"
	"testing"
	"time"
)

func TestLaunchIdentityLeaseTransportBinding(t *testing.T) {
	backend := testBackend(t)
	backend.now = func() time.Time { return time.Date(2026, 5, 7, 0, 1, 0, 0, time.UTC) }
	key := "transport-binding-key"
	peer := transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-1000"}

	lease := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-transport-ok")
	lease.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	lease = mustSignLaunchIdentityLease(t, lease, key)
	if err := backend.verifyLaunchIdentityLease(&lease, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, peer); err != nil {
		t.Fatalf("bound lease should authorize matching transport peer: %v", err)
	}

	mismatch := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-transport-mismatch")
	mismatch.TransportBinding = &launchTransportBinding{Kind: peer.Kind, Subject: peer.Subject}
	mismatch = mustSignLaunchIdentityLease(t, mismatch, key)
	err := backend.verifyLaunchIdentityLease(&mismatch, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, transportPeerIdentity{Kind: "windows-sid", Subject: "S-1-5-21-2000"})
	if !errors.Is(err, errPolicyDenied) {
		t.Fatalf("mismatched transport peer error = %v, want policy denied", err)
	}

	missing := testLaunchIdentityLease(t, backend, "api-service", []string{"services/api-service/*"}, nil, []string{"resolve"}, "jti-transport-missing")
	missing.TransportBinding = &launchTransportBinding{Kind: "unix-uid", Subject: "501"}
	missing = mustSignLaunchIdentityLease(t, missing, key)
	err = backend.verifyLaunchIdentityLease(&missing, key, "api-service", "", "resolve", []string{"services/api-service/runtime/API_TOKEN"}, nil, transportPeerIdentity{})
	if !errors.Is(err, errPolicyDenied) {
		t.Fatalf("missing transport peer error = %v, want policy denied", err)
	}
}

func mustSignLaunchIdentityLease(t *testing.T, lease launchIdentityLease, key string) launchIdentityLease {
	t.Helper()
	signed, err := signLaunchIdentityLease(lease, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
