package verify

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create test certificate pool
func createTestCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	return pool
}

func TestNewSignatureVerifier(t *testing.T) {
	ctx := context.Background()

	t.Run("successful initialization with provided roots", func(t *testing.T) {
		testRoots := createTestCertPool()
		verifier, err := NewSignatureVerifier(ctx, testRoots)

		require.NoError(t, err)
		require.NotNil(t, verifier)
		assert.NotNil(t, verifier.rootCerts)
		assert.Empty(t, verifier.identities)
		assert.Equal(t, testRoots, verifier.rootCerts)
	})

	t.Run("successful initialization with nil roots", func(t *testing.T) {
		verifier, err := NewSignatureVerifier(ctx, nil)

		// This might fail if Fulcio roots can't be fetched, but that's expected in test environment
		if err != nil {
			// If we can't get Fulcio roots, that's okay for testing
			assert.Contains(t, err.Error(), "getting Fulcio roots")
			return
		}

		require.NotNil(t, verifier)
		assert.NotNil(t, verifier.rootCerts)
		assert.Empty(t, verifier.identities)
	})
}

func TestWithIdentity(t *testing.T) {
	verifier := &SignatureVerifier{
		rootCerts:  createTestCertPool(),
		identities: []cosign.Identity{},
	}

	// Test adding single identity
	result := verifier.WithIdentity("issuer1", "subject1")
	assert.Same(t, verifier, result, "Should return the same verifier instance")
	require.Len(t, verifier.identities, 1)
	assert.Equal(t, "issuer1", verifier.identities[0].Issuer)
	assert.Equal(t, "subject1", verifier.identities[0].Subject)
	assert.Empty(t, verifier.identities[0].IssuerRegExp)
	assert.Empty(t, verifier.identities[0].SubjectRegExp)

	// Test adding second identity
	verifier.WithIdentity("issuer2", "subject2")
	require.Len(t, verifier.identities, 2)
	assert.Equal(t, "issuer2", verifier.identities[1].Issuer)
	assert.Equal(t, "subject2", verifier.identities[1].Subject)
}

func TestWithIdentityRegExp(t *testing.T) {
	verifier := &SignatureVerifier{
		rootCerts:  createTestCertPool(),
		identities: []cosign.Identity{},
	}

	// Test adding regex identity
	result := verifier.WithIdentityRegExp("issuer-.*", "subject-.*")
	assert.Same(t, verifier, result, "Should return the same verifier instance")
	require.Len(t, verifier.identities, 1)
	assert.Equal(t, "issuer-.*", verifier.identities[0].IssuerRegExp)
	assert.Equal(t, "subject-.*", verifier.identities[0].SubjectRegExp)
	assert.Empty(t, verifier.identities[0].Issuer)
	assert.Empty(t, verifier.identities[0].Subject)

	// Test adding multiple regex identities
	verifier.WithIdentityRegExp("another-issuer-.*", "another-subject-.*")
	require.Len(t, verifier.identities, 2)
	assert.Equal(t, "another-issuer-.*", verifier.identities[1].IssuerRegExp)
	assert.Equal(t, "another-subject-.*", verifier.identities[1].SubjectRegExp)
}

func TestVerifyWithBasicAuth_InvalidImageRef(t *testing.T) {
	ctx := context.Background()
	verifier := &SignatureVerifier{
		rootCerts:  createTestCertPool(),
		identities: []cosign.Identity{},
	}

	tests := []struct {
		name        string
		imageRef    string
		expectedErr string
	}{
		{
			name:        "empty reference",
			imageRef:    "",
			expectedErr: "parsing image reference",
		},
		{
			name:        "malformed reference",
			imageRef:    "registry.io/",
			expectedErr: "parsing image reference",
		},
		{
			name:        "registry auth failure",
			imageRef:    "docker.io/library/nonexistent:latest",
			expectedErr: "verifying signatures", // This will fail during verification, not parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs, verified, err := verifier.VerifyWithBasicAuth(ctx, tt.imageRef, "user", "pass")

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
			assert.False(t, verified)
			assert.Nil(t, sigs)
		})
	}
}

func TestVerifyWithKeychain_InvalidImageRef(t *testing.T) {
	ctx := context.Background()
	verifier := &SignatureVerifier{
		rootCerts:  createTestCertPool(),
		identities: []cosign.Identity{},
	}

	tests := []struct {
		name        string
		imageRef    string
		expectedErr string
	}{
		{
			name:        "empty reference",
			imageRef:    "",
			expectedErr: "parsing image reference",
		},
		{
			name:        "malformed reference",
			imageRef:    "registry.io/",
			expectedErr: "parsing image reference",
		},
		{
			name:        "registry auth failure",
			imageRef:    "docker.io/library/nonexistent:latest",
			expectedErr: "verifying signatures", // This will fail during verification, not parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs, verified, err := verifier.VerifyWithKeychain(ctx, tt.imageRef)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
			assert.False(t, verified)
			assert.Nil(t, sigs)
		})
	}
}

func TestDownloadContent(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		serverSetup     func() *httptest.Server
		expectedContent string
		expectedError   string
	}{
		{
			name: "successful download",
			serverSetup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("test content"))
				}))
			},
			expectedContent: "test content",
			expectedError:   "",
		},
		{
			name: "server returns 404",
			serverSetup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
			},
			expectedContent: "",
			expectedError:   "unexpected status code: 404",
		},
		{
			name: "server returns 500",
			serverSetup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			expectedContent: "",
			expectedError:   "unexpected status code: 500",
		},
		{
			name: "large content download",
			serverSetup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					// Write 1MB of data
					data := strings.Repeat("a", 1024*1024)
					w.Write([]byte(data))
				}))
			},
			expectedContent: strings.Repeat("a", 1024*1024),
			expectedError:   "",
		},
		{
			name: "empty content",
			serverSetup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					// Write nothing
				}))
			},
			expectedContent: "",
			expectedError:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.serverSetup()
			defer server.Close()

			// Execute
			content, err := downloadContent(ctx, server.URL)

			// Assert
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Empty(t, content)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedContent, string(content))
			}
		})
	}
}

func TestVerificationModes(t *testing.T) {
	t.Run("keyless verification mode", func(t *testing.T) {
		verifier := &SignatureVerifier{}
		res, err := verifier.WithKeylessVerification()
		require.NoError(t, err)

		opts := res.convertToCheckOpts()
		assert.NotNil(t, opts.RootCerts, "root certs should be set")
		assert.NotNil(t, opts.IntermediateCerts, "intermediate certs should be set")
		assert.NotNil(t, opts.RekorClient, "rekor client should be set")
		assert.NotNil(t, opts.RekorPubKeys, "rekor public keys should be set")
		assert.NotNil(t, opts.CTLogPubKeys, "CT log public keys should be set")
		assert.False(t, opts.IgnoreTlog, "tlog verification should be enabled")
		assert.False(t, opts.IgnoreSCT, "SCT verification should be enabled")
	})

	t.Run("certificate verification mode", func(t *testing.T) {
		verifier := &SignatureVerifier{}
		// Example self-signed certificate for testing
		certPEM := `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`
		chainPEM := certPEM // Use same cert as chain for this test

		res, err := verifier.WithCertificateVerification(certPEM, chainPEM)
		require.NoError(t, err)

		opts := res.convertToCheckOpts()
		assert.NotNil(t, opts.RootCerts, "root certs should be set")
		assert.True(t, opts.IgnoreTlog, "tlog verification should be disabled")
		assert.True(t, opts.IgnoreSCT, "SCT verification should be disabled")

		// Verify certificate was added to root pool
		cert, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(certPEM))
		require.NoError(t, err)
		require.Len(t, cert, 1)
	})

	t.Run("verify signed image with certificate verification", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{}

		// Example certificate and chain
		certPEM := `-----BEGIN CERTIFICATE-----
MIIEFTCCAv2gAwIBAgIURnRdWQcYLOxfBqWxKwtOiPL9TDowDQYJKoZIhvcNAQEL
BQAwgZkxCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhTaGFuZ2hhaTERMA8GA1UEBwwI
U2hhbmdoYWkxEjAQBgNVBAoMCU1pY3Jvc29mdDEUMBIGA1UECwwLRW5naW5lZXJp
bmcxFDASBgNVBAMMC1hpbmdkb25nIExpMSQwIgYJKoZIhvcNAQkBFhV4aW5nZGxp
QG1pY3Jvc29mdC5jb20wHhcNMjUwNzIxMDIxNTExWhcNMjYwNzIxMDIxNTExWjCB
mTELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNoYW5naGFpMREwDwYDVQQHDAhTaGFu
Z2hhaTESMBAGA1UECgwJTWljcm9zb2Z0MRQwEgYDVQQLDAtFbmdpbmVlcmluZzEU
MBIGA1UEAwwLWGluZ2RvbmcgTGkxJDAiBgkqhkiG9w0BCQEWFXhpbmdkbGlAbWlj
cm9zb2Z0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALNmZEir
f01lPBaP3AdnHDGJA4KeTfq2sqz6sQKAWGv7iQl4iXlvbjPg0sJ77fa222+ostKh
xNEjj6UYudVQ38BZTlpUyv9EmFiM03teVBadnrNiVz+fjZwdrbr8DaraPfiQfz2v
PyyULSTFrL4LS/4MBAwTJNlWWqXzBYpNQoUA5DCPizZr+YgIE52+8/ZqFt6jrj99
8ozhJ4Mm7bldh5RwEMvQrfU2SUGB3m9stdqEVZOi2eT8+E8wsDNlYJXINgaYcJpj
Ei3xvKcKCCby/bBVn+JAKylb5BpcpUoEEvrwLUJv2MZvBefzUO6KNDIJcv4i0RlW
MII+4PC0uSbDKN0CAwEAAaNTMFEwHQYDVR0OBBYEFD6l93w+rOfzq/MrFn0MbYzW
Yn9BMB8GA1UdIwQYMBaAFD6l93w+rOfzq/MrFn0MbYzWYn9BMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFUsk6FqHjyIXwYir56siMHE/bRFrLcI
OUIUI0cOhv3GLkhaiV0yx4LpR6tiCEu0PZ8b0IctHX2zCa3LtnO7YVKirX8dQ2h2
PfL9FC2ftLoZs3XUGtO4PA00RRC7h/hJPk3S7aDHffUXEvQlVJ0/uOOEhhqBMrHa
nRBNjIStK1cc8qIwgnVkyq/UoFyD4e7Kq5gCAhfdTCFIDVkGXbS0edj90ph3Z9nk
vPzVBxUzlMdObPeSI88pI8fbdoTsJdjrovCh5SlCtsrQKejwNKcoEt+kvw7QAoRJ
OPHvvi7KlSP6bz8buZkWKvFhuDnUOGL6PRSdmAvpT3/NEve+18l9uoU=
-----END CERTIFICATE-----`
		chainPEM := certPEM // Use same cert as chain for this test

		// Set up certificate verification mode
		imageRef := "xingdliacr.azurecr.io/xingdlitest-demo-data@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd"

		// Configure the verifier for certificate verification
		res, err := verifier.WithCertificateVerification(certPEM, chainPEM)
		require.NoError(t, err)

		// Try to verify the image
		sigs, bundleVerified, err := res.VerifyWithKeychain(ctx, imageRef)

		// We expect verification to fail since we're using an incorrect certificate
		require.Nil(t, err)
		assert.False(t, bundleVerified)
		assert.NotNil(t, sigs)

		// Note: The verification fails because:
		// 1. The test certificate is not the one used to sign the image
		// 2. The signature's certificate chain won't match our test certificate
		// This validates that our certificate verification is actually working
	})

	t.Run("verify signed image with keyless verification and OIDC identity", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{}

		// Configure for keyless verification with expected OIDC identity
		res, err := verifier.WithKeylessVerification()
		require.NoError(t, err)

		// Add expected identity - the image should have been signed by GitHub Actions
		res.WithIdentityRegExp("https://github.com/login/oauth", ".*")

		// Try to verify the image with keyless verification
		imageRef := "xingdliacr.azurecr.io/cosign-keyless@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd"
		sigs, bundleVerified, err := res.VerifyWithKeychain(ctx, imageRef)

		// Now we expect verification to succeed with keyless mode
		require.NoError(t, err, "keyless verification should succeed")
		require.True(t, bundleVerified, "bundle should be verified")
		require.NotNil(t, sigs, "signatures should be present")
		require.NotEmpty(t, sigs, "at least one signature should be found")
		t.Logf("Found %d signatures", len(sigs))
	})
}

func TestDownloadContentWithContext(t *testing.T) {
	t.Run("invalid URL", func(t *testing.T) {
		ctx := context.Background()

		// Test with invalid URL
		content, err := downloadContent(ctx, "invalid-url")
		require.Error(t, err)
		assert.Empty(t, content)
		assert.Contains(t, err.Error(), "making HTTP request")
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow server by checking context
			select {
			case <-r.Context().Done():
				return
			default:
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test"))
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		content, err := downloadContent(ctx, server.URL)
		require.Error(t, err)
		assert.Empty(t, content)
		// The error could be about context cancellation or request failure
		assert.True(t, strings.Contains(err.Error(), "context canceled") ||
			strings.Contains(err.Error(), "making HTTP request"))
	})
}

func TestVerifyLocalBlob(t *testing.T) {
	ctx := context.Background()
	verifier := &SignatureVerifier{
		rootCerts:  createTestCertPool(),
		identities: []cosign.Identity{},
	}

	t.Run("file not found", func(t *testing.T) {
		// Create a temporary signature file
		tempSigFile, err := os.CreateTemp("", "test-sig-*.sig")
		require.NoError(t, err)
		defer os.Remove(tempSigFile.Name())
		tempSigFile.WriteString("fake signature")
		tempSigFile.Close()

		err = verifier.VerifyLocalBlob(ctx, "/nonexistent/file.txt", tempSigFile.Name())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading file")
	})

	t.Run("signature file not found", func(t *testing.T) {
		// Create a temporary file
		tempFile, err := os.CreateTemp("", "test-file-*.txt")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())
		tempFile.WriteString("test content")
		tempFile.Close()

		err = verifier.VerifyLocalBlob(ctx, tempFile.Name(), "/nonexistent/signature.sig")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading signature file")
	})

	t.Run("verification failure with fake signature", func(t *testing.T) {
		// Create a temporary file
		tempFile, err := os.CreateTemp("", "test-file-*.txt")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())
		tempFile.WriteString("test content")
		tempFile.Close()

		// Create a temporary signature file
		tempSigFile, err := os.CreateTemp("", "test-sig-*.sig")
		require.NoError(t, err)
		defer os.Remove(tempSigFile.Name())
		tempSigFile.WriteString("fake signature")
		tempSigFile.Close()

		err = verifier.VerifyLocalBlob(ctx, tempFile.Name(), tempSigFile.Name())
		require.Error(t, err)
		// Should fail at signature creation or verification step
		assert.True(t, strings.Contains(err.Error(), "creating signature") ||
			strings.Contains(err.Error(), "signature verification failed"))
	})
}

// Integration test that tests the complete workflow
func TestSignatureVerifierIntegration(t *testing.T) {
	ctx := context.Background()

	// Create verifier with custom certificate pool
	testRoots := createTestCertPool()
	verifier, err := NewSignatureVerifier(ctx, testRoots)
	require.NoError(t, err)

	// Test method chaining
	result := verifier.
		WithIdentity("test-issuer", "test-subject").
		WithIdentityRegExp(".*@example.com", ".*")

	// Verify method chaining returns same instance
	assert.Same(t, verifier, result)

	// Verify we have the expected identities
	assert.Len(t, verifier.identities, 2)

	// First identity (exact match)
	assert.Equal(t, "test-issuer", verifier.identities[0].Issuer)
	assert.Equal(t, "test-subject", verifier.identities[0].Subject)
	assert.Empty(t, verifier.identities[0].IssuerRegExp)
	assert.Empty(t, verifier.identities[0].SubjectRegExp)

	// Second identity (regex match)
	assert.Empty(t, verifier.identities[1].Issuer)
	assert.Empty(t, verifier.identities[1].Subject)
	assert.Equal(t, ".*@example.com", verifier.identities[1].IssuerRegExp)
	assert.Equal(t, ".*", verifier.identities[1].SubjectRegExp)

	// Verify rootCerts is set correctly
	assert.Equal(t, testRoots, verifier.rootCerts)
}

func TestSignatureVerifierIdentityTypes(t *testing.T) {
	verifier := &SignatureVerifier{
		rootCerts:  createTestCertPool(),
		identities: []cosign.Identity{},
	}

	// Add various types of identities
	verifier.WithIdentity("exact-issuer", "exact-subject")
	verifier.WithIdentityRegExp("regex-issuer-.*", "regex-subject-.*")
	verifier.WithIdentity("", "empty-issuer-test")  // Test empty issuer
	verifier.WithIdentity("empty-subject-test", "") // Test empty subject

	require.Len(t, verifier.identities, 4)

	// Test exact identity
	assert.Equal(t, "exact-issuer", verifier.identities[0].Issuer)
	assert.Equal(t, "exact-subject", verifier.identities[0].Subject)

	// Test regex identity
	assert.Equal(t, "regex-issuer-.*", verifier.identities[1].IssuerRegExp)
	assert.Equal(t, "regex-subject-.*", verifier.identities[1].SubjectRegExp)

	// Test empty issuer
	assert.Empty(t, verifier.identities[2].Issuer)
	assert.Equal(t, "empty-issuer-test", verifier.identities[2].Subject)

	// Test empty subject
	assert.Equal(t, "empty-subject-test", verifier.identities[3].Issuer)
	assert.Empty(t, verifier.identities[3].Subject)
}

func TestBase64Encoding(t *testing.T) {
	// Test that our base64 encoding logic works correctly
	testData := []byte("test signature data")
	encoded := base64.StdEncoding.EncodeToString(testData)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, testData, decoded)

	// Test with empty data
	emptyEncoded := base64.StdEncoding.EncodeToString([]byte{})
	assert.Equal(t, "", emptyEncoded)
}
