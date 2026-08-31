package main

import (
	"encoding/json"
	"testing"
)

// FuzzSecurityContractParsers continuously exercises the three attacker-facing
// JSON contract families that carry recovery, source, and launch-lease state.
func FuzzSecurityContractParsers(f *testing.F) {
	f.Add([]byte(`{"version":"secretsbroker.recovery-share.v1","serviceId":"@secretsbroker","apiVersion":"v1","policyId":"policy-1","keyId":"sha256:0000000000000000000000000000000000000000000000000000000000000000","keyVersion":"v1","threshold":2,"shareCount":3,"shareIndex":1,"alg":"shamir-gf256-age-x25519"}`))
	f.Add([]byte(`{"sources":[{"sourceId":"local-file","kind":"file","enabled":true,"trustedDirs":["/srv/secrets"],"refs":{"services/example/token":{"path":"/srv/secrets/token"}}}]}`))
	f.Add([]byte(`{"issuer":"service-lasso-local-launcher","serviceId":"example","workspaceId":"workspace-1","allowedRefs":["services/example/runtime/TOKEN"],"allowedOperations":["resolve"],"issuedAt":"2026-08-31T00:00:00Z","expiresAt":"2026-08-31T00:05:00Z","jti":"lease-1","transportBinding":{"kind":"unix-uid","subject":"1000"}}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		var share recoveryShareFile
		if json.Unmarshal(input, &share) == nil {
			_ = validateRecoveryShareHeader(share)
		}
		var sources sourceConfigFile
		if json.Unmarshal(input, &sources) == nil {
			for _, source := range sources.Sources {
				_ = source.SourceID
				for ref := range source.Refs {
					_ = validSecretRef(ref)
				}
			}
		}
		var lease launchIdentityLease
		if json.Unmarshal(input, &lease) == nil {
			_, _ = launchIdentitySignatureInput(lease)
			_ = normalizeLaunchTransportBinding(lease.TransportBinding)
		}
	})
}
