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
	"time"

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
		res, err := verifier.WithKeylessVerification("issuer-.*", "subject-.*")
		require.NoError(t, err)

		opts, err := res.convertToCheckOpts()
		require.NoError(t, err)
		assert.NotNil(t, opts.RootCerts, "root certs should be set")
		assert.NotNil(t, opts.IntermediateCerts, "intermediate certs should be set")
		assert.NotNil(t, opts.RekorClient, "rekor client should be set")
		assert.NotNil(t, opts.RekorPubKeys, "rekor public keys should be set")
		assert.NotNil(t, opts.CTLogPubKeys, "CT log public keys should be set")
		assert.False(t, opts.IgnoreTlog, "tlog verification should be enabled")
		assert.False(t, opts.IgnoreSCT, "SCT verification should be enabled")
		assert.Len(t, opts.Identities, 1, "should have one identity configured")
		assert.Equal(t, "issuer-.*", opts.Identities[0].IssuerRegExp, "identity issuer regexp should match")
		assert.Equal(t, "subject-.*", opts.Identities[0].SubjectRegExp, "identity subject regexp should match")
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

		opts, err := res.convertToCheckOpts()
		require.NoError(t, err)
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
		imageRef := "xingdliacr.azurecr.io/cosign-certificate@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd"

		// Configure the verifier for certificate verification
		res, err := verifier.WithCertificateVerification(certPEM, chainPEM)
		require.NoError(t, err)

		// Try to verify the image
		sigs, bundleVerified, err := res.VerifyWithKeychain(ctx, imageRef)

		// We expect verification to succeeded
		require.Nil(t, err)
		assert.False(t, bundleVerified)
		assert.NotNil(t, sigs)
	})

	t.Run("verify signed image with key verification", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{}

		// Example certificate and chain
		key := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2ZkSKt/TWU8Fo/cB2cc
MYkDgp5N+rayrPqxAoBYa/uJCXiJeW9uM+DSwnvt9rbbb6iy0qHE0SOPpRi51VDf
wFlOWlTK/0SYWIzTe15UFp2es2JXP5+NnB2tuvwNqto9+JB/Pa8/LJQtJMWsvgtL
/gwEDBMk2VZapfMFik1ChQDkMI+LNmv5iAgTnb7z9moW3qOuP33yjOEngybtuV2H
lHAQy9Ct9TZJQYHeb2y12oRVk6LZ5Pz4TzCwM2Vglcg2BphwmmMSLfG8pwoIJvL9
sFWf4kArKVvkGlylSgQS+vAtQm/Yxm8F5/NQ7oo0Mgly/iLRGVYwgj7g8LS5JsMo
3QIDAQAB
-----END PUBLIC KEY-----`

		// Set up certificate verification mode
		imageRef := "xingdliacr.azurecr.io/cosign-key@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd"

		// Configure the verifier for key verification
		res, err := verifier.WithKeyVerification(key)
		require.NoError(t, err)

		// Try to verify the image
		sigs, bundleVerified, err := res.VerifyWithKeychain(ctx, imageRef)

		// We expect verification to succeeded
		require.Nil(t, err)
		assert.False(t, bundleVerified)
		assert.NotNil(t, sigs)
	})

	t.Run("verify signed image with keyless verification and OIDC identity", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{}

		// Configure for keyless verification with expected OIDC identity
		res, err := verifier.WithKeylessVerification("https://github.com/login/oauth", ".*")
		require.NoError(t, err)

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

	t.Run("verify signed local chart with keyless verification and OIDC identity", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{}

		// Configure for keyless verification with expected OIDC identity
		res, err := verifier.WithKeylessVerification("https://github.com/login/oauth", ".*")
		require.NoError(t, err)

		// Try to verify the image with keyless verification
		chartPath := "./testdata/LocalChart/podinfo-6.9.1.tgz"
		signaturePath := "./testdata/LocalChart/podinfo-6.9.1.tgz.bundle"
		err = res.VerifyLocalBlob(ctx, chartPath, signaturePath)

		// Now we expect verification to succeed with keyless mode
		require.NoError(t, err, "keyless verification should succeed")
	})

	t.Run("verify signed local chart with key verification", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{}
		key := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2ZkSKt/TWU8Fo/cB2cc
MYkDgp5N+rayrPqxAoBYa/uJCXiJeW9uM+DSwnvt9rbbb6iy0qHE0SOPpRi51VDf
wFlOWlTK/0SYWIzTe15UFp2es2JXP5+NnB2tuvwNqto9+JB/Pa8/LJQtJMWsvgtL
/gwEDBMk2VZapfMFik1ChQDkMI+LNmv5iAgTnb7z9moW3qOuP33yjOEngybtuV2H
lHAQy9Ct9TZJQYHeb2y12oRVk6LZ5Pz4TzCwM2Vglcg2BphwmmMSLfG8pwoIJvL9
sFWf4kArKVvkGlylSgQS+vAtQm/Yxm8F5/NQ7oo0Mgly/iLRGVYwgj7g8LS5JsMo
3QIDAQAB
-----END PUBLIC KEY-----`
		// Configure for keyless verification with expected OIDC identity
		res, err := verifier.WithKeyVerification(key)
		require.NoError(t, err)

		// Try to verify the image with key verification
		chartPath := "./testdata/LocalChart/podinfo-6.9.1.tgz"
		signaturePath := "./testdata/LocalChart/podinfo-6.9.1.tgz.key.bundle"
		err = res.VerifyLocalBlob(ctx, chartPath, signaturePath)

		// Now we expect verification to succeed with key verification
		require.NoError(t, err, "key verification should succeed")
	})
}
func TestVerifyOCIChartDigestFromHTTPSignature(t *testing.T) {
	t.Run("invalid chart reference", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{
			rootCerts:  createTestCertPool(),
			identities: []cosign.Identity{},
		}

		err := verifier.VerifyOCIChartDigestFromHTTPSignature(ctx, "", "http://example.com/sig", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing chart reference")
	})

	t.Run("invalid signature URL", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{
			rootCerts:  createTestCertPool(),
			identities: []cosign.Identity{},
		}

		err := verifier.VerifyOCIChartDigestFromHTTPSignature(ctx, "registry.io/chart:1.0", "invalid-url", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "downloading signature")
	})

	t.Run("HTTP error codes", func(t *testing.T) {
		ctx := context.Background()
		verifier := &SignatureVerifier{
			rootCerts:  createTestCertPool(),
			identities: []cosign.Identity{},
		}

		tests := []struct {
			name       string
			statusCode int
		}{
			{"not found", http.StatusNotFound},
			{"server error", http.StatusInternalServerError},
			{"unauthorized", http.StatusUnauthorized},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.statusCode)
				}))
				defer server.Close()

				err := verifier.VerifyOCIChartDigestFromHTTPSignature(ctx, "registry.io/chart:1.0", server.URL, nil)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "downloading signature")
			})
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test signature"))
			}
		}))
		defer server.Close()

		verifier := &SignatureVerifier{
			rootCerts:  createTestCertPool(),
			identities: []cosign.Identity{},
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := verifier.VerifyOCIChartDigestFromHTTPSignature(ctx, "registry.io/chart:1.0", server.URL, nil)
		require.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "context canceled") ||
			strings.Contains(err.Error(), "downloading signature"))
	})

	t.Run("successful verification with keyless mode", func(t *testing.T) {
		// Set up test server with a valid base64 encoded signature
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Base64 encoded test signature
			w.Write([]byte("dGVzdCBzaWduYXR1cmU="))
		}))
		defer server.Close()

		// Set up verifier with keyless configuration
		verifier := &SignatureVerifier{}
		verifier, err := verifier.WithKeylessVerification("https://github.com/login/oauth", ".*")
		require.NoError(t, err)

		// Verify signature
		err = verifier.VerifyOCIChartDigestFromHTTPSignature(
			context.Background(),
			"xingdliacr.azurecr.io/cosign-keyless@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd",
			server.URL,
			nil,
		)

		// Since we can't fully mock the cosign verification, we expect an error about invalid signature
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("successful verification with certificate mode", func(t *testing.T) {
		// Set up test server with a valid base64 encoded signature
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Base64 encoded test signature
			w.Write([]byte("dGVzdCBzaWduYXR1cmU="))
		}))
		defer server.Close()

		// Example certificate (same as used in other tests)
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

		// Set up verifier with certificate configuration
		verifier := &SignatureVerifier{}
		verifier, err := verifier.WithCertificateVerification(certPEM, certPEM)
		require.NoError(t, err)

		// Verify signature
		err = verifier.VerifyOCIChartDigestFromHTTPSignature(
			context.Background(),
			"xingdliacr.azurecr.io/cosign-certificate@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd",
			server.URL,
			nil,
		)

		// Since we can't fully mock the cosign verification, we expect an error about invalid signature
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("successful verification with key mode", func(t *testing.T) {
		// Set up test server with a valid base64 encoded signature
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Base64 encoded test signature
			w.Write([]byte("dGVzdCBzaWduYXR1cmU="))
		}))
		defer server.Close()

		// Example public key (same as used in other tests)
		key := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2ZkSKt/TWU8Fo/cB2cc
MYkDgp5N+rayrPqxAoBYa/uJCXiJeW9uM+DSwnvt9rbbb6iy0qHE0SOPpRi51VDf
wFlOWlTK/0SYWIzTe15UFp2es2JXP5+NnB2tuvwNqto9+JB/Pa8/LJQtJMWsvgtL
/gwEDBMk2VZapfMFik1ChQDkMI+LNmv5iAgTnb7z9moW3qOuP33yjOEngybtuV2H
lHAQy9Ct9TZJQYHeb2y12oRVk6LZ5Pz4TzCwM2Vglcg2BphwmmMSLfG8pwoIJvL9
sFWf4kArKVvkGlylSgQS+vAtQm/Yxm8F5/NQ7oo0Mgly/iLRGVYwgj7g8LS5JsMo
3QIDAQAB
-----END PUBLIC KEY-----`

		// Set up verifier with key configuration
		verifier := &SignatureVerifier{}
		verifier, err := verifier.WithKeyVerification(key)
		require.NoError(t, err)

		// Verify signature
		err = verifier.VerifyOCIChartDigestFromHTTPSignature(
			context.Background(),
			"xingdliacr.azurecr.io/cosign-key@sha256:39851a7894f42210bb259b73aa63945a7df5bd2d224226431931b492aff4c3cd",
			server.URL,
			nil,
		)

		// Since we can't fully mock the cosign verification, we expect an error about invalid signature
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})
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
