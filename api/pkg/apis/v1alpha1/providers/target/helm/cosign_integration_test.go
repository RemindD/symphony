package helm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateVerifier(t *testing.T) {
	tests := []struct {
		name        string
		chart       *HelmChartProperty
		expectError bool
	}{
		{
			name: "create keyless verifier without identity",
			chart: &HelmChartProperty{
				VerificationType: "keyless",
			},
			expectError: true,
		},
		{
			name: "create keyless verifier with identity",
			chart: &HelmChartProperty{
				VerificationType:    "keyless",
				SigningOIDCIssuer:   "https://token.actions.githubusercontent.com",
				SigningOIDCIdentity: "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main",
			},
			expectError: false,
		},
		{
			name: "create keyless verifier with partial identity",
			chart: &HelmChartProperty{
				VerificationType:  "keyless",
				SigningOIDCIssuer: "https://token.actions.githubusercontent.com",
			},
			expectError: true,
		},
		{
			name: "create certificate verifier without cert",
			chart: &HelmChartProperty{
				VerificationType: "certificate",
			},
			expectError: true,
		},
		{
			name: "create certificate verifier with cert",
			chart: &HelmChartProperty{
				VerificationType: "certificate",
				SigningCert:      "-----BEGIN CERTIFICATE-----\nMIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL\nMAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC\nVU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx\nNDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD\nTjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu\nZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j\nV14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj\ngbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA\nFFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE\nCBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS\nBgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE\nBQADQQA/CFbiKqwn4IzB/8bB7D5fqA8JKRyV+K1zKQQAWVYtDDf+y5nBNb3TBJkx\nZwIcQqTHCI/NXXff4QB1NYyL9BIK\n-----END CERTIFICATE-----",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := createVerifier(tt.chart)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, verifier)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, verifier)
			}
		})
	}
}

func TestPreVerifySignature_SkipWhenNoSignature(t *testing.T) {
	provider := &HelmTargetProvider{}
	ctx := context.Background()

	chart := &HelmChartProperty{
		Repo:      "https://charts.example.com",
		Name:      "test-chart",
		Version:   "1.0.0",
		Signature: "", // No signature specified
	}

	sigPath, err := provider.preVerifySignature(ctx, chart)
	require.NoError(t, err)  // Should succeed without verification
	assert.Empty(t, sigPath) // Should return empty string for no signature
}

func TestPreVerifySignature_InvalidSignatureURL(t *testing.T) {
	provider := &HelmTargetProvider{}
	ctx := context.Background()

	chart := &HelmChartProperty{
		Repo:      "https://charts.example.com",
		Name:      "test-chart",
		Version:   "1.0.0",
		Signature: "https://invalid-signature-url.com/nonexistent.sig",
	}

	sigPath, err := provider.preVerifySignature(ctx, chart)
	require.Error(t, err)    // Should fail due to missing OIDC issuer/identity for signature verification
	assert.Empty(t, sigPath) // Should return empty string on error
	assert.Contains(t, err.Error(), "OIDC issuer and identity must be specified for signature verification")
}

func TestPreVerifySignature_OCIInplaceSignature(t *testing.T) {
	provider := &HelmTargetProvider{}
	ctx := context.Background()

	chart := &HelmChartProperty{
		Repo:      "oci://registry.example.com/charts/test-chart",
		Name:      "test-chart",
		Version:   "1.0.0",
		Signature: "inplace", // OCI signature verification
	}

	sigPath, err := provider.preVerifySignature(ctx, chart)
	require.Error(t, err)    // Should fail due to missing OIDC issuer/identity for signature verification
	assert.Empty(t, sigPath) // Should return empty string on error
	assert.Contains(t, err.Error(), "OIDC issuer and identity must be specified for signature verification")
}

func TestPreVerifySignature_WithOIDCIdentity(t *testing.T) {
	provider := &HelmTargetProvider{}
	ctx := context.Background()

	chart := &HelmChartProperty{
		Repo:                "oci://registry.example.com/charts/test-chart",
		Name:                "test-chart",
		Version:             "1.0.0",
		Signature:           "inplace",
		SigningOIDCIssuer:   "https://token.actions.githubusercontent.com",
		SigningOIDCIdentity: "https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main",
	}

	sigPath, err := provider.preVerifySignature(ctx, chart)
	require.Error(t, err)    // Should fail due to nonexistent registry/signature, but verifier should be created with identity
	assert.Empty(t, sigPath) // Should return empty string for OCI charts
	assert.Contains(t, err.Error(), "OCI chart inplace signature verification failed")
}

func TestPreVerifySignature_HTTPWithCredentials(t *testing.T) {
	provider := &HelmTargetProvider{}
	ctx := context.Background()

	chart := &HelmChartProperty{
		Repo:                "https://charts.example.com",
		Name:                "test-chart",
		Version:             "1.0.0",
		Signature:           "https://charts.example.com/test-chart-1.0.0.tgz.sig",
		Username:            "testuser",
		Password:            "testpass",
		SigningOIDCIssuer:   "https://token.actions.githubusercontent.com",
		SigningOIDCIdentity: "user@example.com",
	}

	sigPath, err := provider.preVerifySignature(ctx, chart)
	require.Error(t, err)    // Should fail due to nonexistent signature URL, but should try HTTP verification
	assert.Empty(t, sigPath) // Should return empty string on error
	assert.Contains(t, err.Error(), "failed to download signature file")
}

func TestPullChart_IntegrationWithVerification(t *testing.T) {
	provider := &HelmTargetProvider{}
	ctx := context.Background()

	// Test with no signature (should succeed for the verification part)
	chart := &HelmChartProperty{
		Repo:      "https://charts.example.com/nonexistent",
		Name:      "test-chart",
		Version:   "1.0.0",
		Signature: "", // No signature
	}

	_, err := provider.pullChart(ctx, chart)
	require.Error(t, err) // Should fail at download stage, not verification
	// The error should be about chart download, not verification
	assert.NotContains(t, err.Error(), "signature verification failed")
}
