/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package script

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/eclipse-symphony/symphony/api/pkg/apis/v1alpha1/model"
	"github.com/eclipse-symphony/symphony/api/pkg/apis/v1alpha1/providers/target/conformance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitMissingGet tests that we can init with a map fails if get is missing
func TestInitMissingGet(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"scriptFolder":  ".",
		"stagingFolder": ".",
		"applyScript":   "a",
		"removeScript":  "b",
	})
	require.NotNil(t, err)
}

// TestInitMissingApply tests that we can init with a map fails if apply is missing
func TestInitMissingApply(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"scriptFolder":  ".",
		"stagingFolder": ".",
		"getScript":     "a",
		"removeScript":  "b",
	})
	require.NotNil(t, err)
}

// TestInitMissingRemove tests that we can init with a map fails if remove is missing
func TestInitMissingRemove(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"scriptFolder":  ".",
		"stagingFolder": ".",
		"getScript":     "a",
		"applyScript":   "b",
	})
	require.NotNil(t, err)
	assert.Equal(t, err.Error(), "Bad Config: invalid script provider config, exptected 'removeScript'")
}

// TestInitWithMap tests that we can init with a map
func TestInitWithMap(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":          "test",
		"needsUpdate":   "mock-needsupdate.sh",
		"needsRemove":   "mock-needsremove.sh",
		"stagingFolder": "./staging",
		"scriptFolder":  "https://raw.githubusercontent.com/eclipse-symphony/symphony/main/docs/samples/script-provider",
		"applyScript":   "mock-apply.sh",
		"removeScript":  "mock-remove.sh",
		"getScript":     "mock-get.sh",
		"scriptEngine":  "bash",
	})
	require.Nil(t, err)
}

// TestGet tests that we can get a script
func TestGet(t *testing.T) {
	provider := ScriptProvider{}
	currentFolder, _ := filepath.Abs(".")
	err := provider.Init(ScriptProviderConfig{
		ScriptFolder: "",
		GetScript:    filepath.Join(currentFolder, "mock-get.sh"),
	})
	require.Nil(t, err)
	components, err := provider.Get(context.Background(), model.DeploymentSpec{
		Solution: model.SolutionState{
			Spec: &model.SolutionSpec{
				Components: []model.ComponentSpec{
					{
						Name: "com1",
					},
				},
			},
		},
		Instance: model.InstanceState{
			Spec: &model.InstanceSpec{
				Scope: "test-scope",
			},
		},
	}, []model.ComponentStep{
		{
			Action: model.ComponentUpdate,
			Component: model.ComponentSpec{
				Name: "com1",
			},
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, 1, len(components))
}

// TestRemoveScript tests that we can remove a script
func TestRemoveScript(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.Init(ScriptProviderConfig{
		RemoveScript: "mock-remove.sh",
	})
	assert.Nil(t, err)
	_, err = provider.Apply(context.Background(), model.DeploymentSpec{
		Solution: model.SolutionState{
			Spec: &model.SolutionSpec{
				Components: []model.ComponentSpec{
					{
						Name: "com1",
					},
				},
			},
		},
		Instance: model.InstanceState{
			Spec: &model.InstanceSpec{
				Scope: "test-scope",
			},
		},
	}, model.DeploymentStep{
		Components: []model.ComponentStep{
			{
				Action: model.ComponentDelete,
				Component: model.ComponentSpec{
					Name: "com1",
				},
			},
		},
	}, false)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "executing script returned error output")
}

// TestApplyScript tests that we can apply a script
func TestApplyScript(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.Init(ScriptProviderConfig{
		ApplyScript: "mock-apply.sh",
	})
	assert.Nil(t, err)
	_, err = provider.Apply(context.Background(), model.DeploymentSpec{
		Solution: model.SolutionState{
			Spec: &model.SolutionSpec{
				Components: []model.ComponentSpec{
					{
						Name: "com1",
					},
				},
			},
		},
		Instance: model.InstanceState{
			Spec: &model.InstanceSpec{
				Scope: "test-scope",
			},
		},
	}, model.DeploymentStep{
		Components: []model.ComponentStep{
			{
				Action: model.ComponentUpdate,
				Component: model.ComponentSpec{
					Name: "com1",
				},
			},
		},
	}, false)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "executing script returned error output")
}

func TestGetScriptFromUrl(t *testing.T) {
	testScriptProvider := os.Getenv("TEST_SCRIPT_PROVIDER")
	if testScriptProvider == "" {
		t.Skip("Skipping because TEST_SCRIPT_PROVIDER environment variable is not set")
	}
	provider := ScriptProvider{}
	err := provider.Init(ScriptProviderConfig{
		GetScript:     "mock-get.sh",
		ApplyScript:   "mock-apply.sh",
		RemoveScript:  "mock-remove.sh",
		StagingFolder: "./staging",
		ScriptFolder:  "https://raw.githubusercontent.com/eclipse-symphony/symphony/main/docs/samples/script-provider",
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "executing script returned error output")
}

// TestInitWithSignature tests initialization with signature verification config
func TestInitWithSignature(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":                 "test",
		"stagingFolder":        "./staging",
		"scriptFolder":         "https://test.example.com/scripts",
		"applyScript":          "mock-apply.sh",
		"removeScript":         "mock-remove.sh",
		"getScript":            "mock-get.sh",
		"scriptEngine":         "bash",
		"applyScriptSignature": "https://test.example.com/signatures/mock-apply.sh.sig",
		"signingOIDCIssuer":    "https://issuer.example.com",
		"signingOIDCIdentity":  "test@example.com",
	})
	require.Nil(t, err)
}

// TestInitFailsWithoutOIDCParams tests that init fails if signatures are specified without OIDC params
func TestInitFailsWithoutOIDCParams(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":                 "test",
		"stagingFolder":        "./staging",
		"scriptFolder":         "https://test.example.com/scripts",
		"applyScript":          "mock-apply.sh",
		"removeScript":         "mock-remove.sh",
		"getScript":            "mock-get.sh",
		"scriptEngine":         "bash",
		"applyScriptSignature": "https://test.example.com/signatures/mock-apply.sh.sig",
	})
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "OIDC issuer required when script signatures are specified")
}

// TestInitWithMultipleSignatures tests initialization with multiple script signatures
func TestInitWithInvalidSignatures(t *testing.T) {
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":                  "test",
		"stagingFolder":         "./staging",
		"scriptFolder":          "https://test.example.com/scripts",
		"applyScript":           "mock-apply.sh",
		"removeScript":          "mock-remove.sh",
		"getScript":             "mock-get.sh",
		"scriptEngine":          "bash",
		"applyScriptSignature":  "https://test.example.com/signatures/mock-apply.sh.sig",
		"removeScriptSignature": "https://test.example.com/signatures/mock-remove.sh.sig",
		"getScriptSignature":    "https://test.example.com/signatures/mock-get.sh.sig",
		"signingOIDCIssuer":     "https://issuer.example.com",
		"signingOIDCIdentity":   "test@example.com",
	})
	require.NotNil(t, err)
}

// TestScriptVerification tests actual script signature verification
func TestScriptVerification(t *testing.T) {
	tmpDir := t.TempDir()
	scriptFolder := "https://raw.githubusercontent.com/RemindD/symphony/users/xingdong/signature/api/pkg/apis/v1alpha1/providers/target/script/"
	// Test the provider
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":                  "test",
		"stagingFolder":         tmpDir,
		"scriptFolder":          scriptFolder,
		"applyScript":           "mock-apply.sh",
		"removeScript":          "mock-remove.sh",
		"getScript":             "mock-get.sh",
		"applyScriptSignature":  "", //scriptFolder + "/mock-apply.sh.bundle",
		"removeScriptSignature": scriptFolder + "/mock-remove.sh.bundle",
		"getScriptSignature":    scriptFolder + "/mock-get.sh.bundle",
		"keylessSigning":        "true",
		"signingOIDCIssuer":     "https://github.com/login/oauth",
		"signingOIDCIdentity":   "xdlisjtu@gmail.com",
	})
	require.Nil(t, err)
}

func TestScriptVerificationLocal(t *testing.T) {
	tmpDir := t.TempDir()
	scriptFolder := "/home/xingdong/symphony/api/pkg/apis/v1alpha1/providers/target/script/"
	// Test the provider
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":                  "test",
		"stagingFolder":         tmpDir,
		"scriptFolder":          scriptFolder,
		"applyScript":           "mock-apply.sh",
		"removeScript":          "mock-remove.sh",
		"getScript":             "mock-get.sh",
		"applyScriptSignature":  scriptFolder + "/mock-apply.sh.bundle",
		"removeScriptSignature": scriptFolder + "/mock-remove.sh.bundle",
		"getScriptSignature":    scriptFolder + "/mock-get.sh.bundle",
		"keylessSigning":        "true",
		"signingOIDCIssuer":     "https://github.com/login/oauth",
		"signingOIDCIdentity":   "xdlisjtu@gmail.com",
	})
	require.Nil(t, err)
	ctx := context.Background()
	err = provider.verifyScript(ctx, "/home/xingdong/symphony/api/pkg/apis/v1alpha1/providers/target/script/mock-apply.sh", provider.Config.ApplyScriptSignature)
	require.Nil(t, err)
	err = provider.verifyScript(ctx, "/home/xingdong/symphony/api/pkg/apis/v1alpha1/providers/target/script/mock-get.sh", provider.Config.GetScriptSignature)
	require.Nil(t, err)
	err = provider.verifyScript(ctx, "/home/xingdong/symphony/api/pkg/apis/v1alpha1/providers/target/script/mock-remove.sh", provider.Config.RemoveScriptSignature)
	require.Nil(t, err)
}

func TestScriptVerificationWithCertLocal(t *testing.T) {
	tmpDir := t.TempDir()
	scriptFolder := "/home/xingdong/symphony/api/pkg/apis/v1alpha1/providers/target/script/"
	// Test the provider
	provider := ScriptProvider{}
	err := provider.InitWithMap(map[string]string{
		"name":                  "test",
		"stagingFolder":         tmpDir,
		"scriptFolder":          scriptFolder,
		"applyScript":           "mock-apply.sh",
		"removeScript":          "mock-remove.sh",
		"getScript":             "mock-get.sh",
		"applyScriptSignature":  "",
		"removeScriptSignature": "",
		"getScriptSignature":    "/home/xingdong/symphony/myfile.txt.bundle",
		"keylessSigning":        "false",
		"signingCert": `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
	})
	require.Nil(t, err)
	ctx := context.Background()
	err = provider.verifyScript(ctx, "/home/xingdong/symphony/api/pkg/apis/v1alpha1/providers/target/script/mock-get.sh", provider.Config.GetScriptSignature)
	require.Nil(t, err)
}

// TestScriptVerificationFailure tests that verification fails with invalid signature
func TestScriptVerificationFailure(t *testing.T) {
	testScriptProvider := os.Getenv("TEST_SCRIPT_PROVIDER")
	if testScriptProvider == "" {
		t.Skip("Skipping because TEST_SCRIPT_PROVIDER environment variable is not set")
	}

	// Create test files
	tmpDir := t.TempDir()
	scriptContent := []byte("#!/bin/bash\necho 'test'\n")
	invalidSig := []byte("invalid signature")

	scriptPath := filepath.Join(tmpDir, "test.sh")
	sigPath := filepath.Join(tmpDir, "test.sh.sig")

	err := os.WriteFile(scriptPath, scriptContent, 0644)
	require.Nil(t, err)
	err = os.WriteFile(sigPath, invalidSig, 0644)
	require.Nil(t, err)

	// Create HTTP server to serve files
	fs := http.FileServer(http.Dir(tmpDir))
	server := httptest.NewServer(fs)
	defer server.Close()

	// Test the provider
	provider := ScriptProvider{}
	err = provider.InitWithMap(map[string]string{
		"name":                 "test",
		"stagingFolder":        tmpDir,
		"scriptFolder":         server.URL,
		"applyScript":          "test.sh",
		"removeScript":         "test.sh",
		"getScript":            "test.sh",
		"applyScriptSignature": server.URL + "/test.sh.sig",
		"signingOIDCIssuer":    "https://container.googleapis.com/v1/projects/project-id/locations/global",
		"signingOIDCIdentity":  "serviceAccount:test@project-id.iam.gserviceaccount.com",
	})
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "script verification failed")
}

// TestCreateVerifierWithKeylessSigning tests creating a verifier with keyless signing configuration
func TestCreateVerifierWithKeylessSigning(t *testing.T) {
	config := ScriptProviderConfig{
		KeylessSigning:      true,
		SigningOIDCIssuer:   "https://github.com/login/oauth",
		SigningOIDCIdentity: "test@example.com",
	}

	verifier, err := createVerifier(config)
	require.NoError(t, err)
	require.NotNil(t, verifier)

	// Verify that the keyless verifier was created successfully
	assert.NotNil(t, verifier)
}

// TestCreateVerifierWithCertificateSigning tests creating a verifier with certificate signing configuration
func TestCreateVerifierWithCertificateSigning(t *testing.T) {
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

	config := ScriptProviderConfig{
		KeylessSigning: false,
		SigningCert:    certPEM,
	}

	verifier, err := createVerifier(config)
	require.NoError(t, err)
	require.NotNil(t, verifier)

	// Verify that the certificate verifier was created successfully
	assert.NotNil(t, verifier)
}

// TestCreateVerifierFailures tests various error cases when creating a verifier
func TestCreateVerifierFailures(t *testing.T) {
	tests := []struct {
		name        string
		config      ScriptProviderConfig
		expectedErr string
	}{
		{
			name: "keyless signing missing OIDC issuer",
			config: ScriptProviderConfig{
				KeylessSigning:      true,
				SigningOIDCIdentity: "test@example.com",
			},
			expectedErr: "SigningOIDCIssuer and SigningOIDCIdentity must be specified for keyless signing",
		},
		{
			name: "keyless signing missing OIDC identity",
			config: ScriptProviderConfig{
				KeylessSigning:    true,
				SigningOIDCIssuer: "https://github.com/login/oauth",
			},
			expectedErr: "SigningOIDCIssuer and SigningOIDCIdentity must be specified for keyless signing",
		},
		{
			name: "certificate signing missing cert",
			config: ScriptProviderConfig{
				KeylessSigning: false,
			},
			expectedErr: "SigningCert must be specified for certificate-based signing",
		},
		{
			name: "certificate signing with invalid cert",
			config: ScriptProviderConfig{
				KeylessSigning: false,
				SigningCert:    "invalid certificate data",
			},
			expectedErr: "parsing certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := createVerifier(tt.config)
			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, verifier)
			} else {
				require.NoError(t, err)
				require.NotNil(t, verifier)
			}
		})
	}
}

// Conformance: you should call the conformance suite to ensure provider conformance
func TestConformanceSuite(t *testing.T) {
	provider := &ScriptProvider{}
	err := provider.Init(ScriptProviderConfig{})
	require.Nil(t, err)
	conformance.ConformanceSuite(t, provider)
}
