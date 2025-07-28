package verify

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"bytes"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	RekorURL = "https://rekor.sigstore.dev"
)

type VerificationType string

const (
	KeylessVerification     VerificationType = "keyless"
	CertificateVerification VerificationType = "certificate"
	KeyVerification         VerificationType = "key"
)

var VerificationTypeMap = map[string]VerificationType{
	"keyless":     KeylessVerification,
	"certificate": CertificateVerification,
	"key":         KeyVerification,
}

// SignatureVerifier provides methods to verify signatures using Cosign
type SignatureVerifier struct {
	// Verification type (keyless or certificate-based)
	verificationType VerificationType
	// Root certificates for verification
	rootCerts *x509.CertPool
	// Intermediate certificates for verification
	intermediateCerts *x509.CertPool
	// Public key for verification
	publicKey crypto.PublicKey
	// OIDC identity requirements
	identities []cosign.Identity
	// Rekor client for transparency log verification
	rekorClient *client.Rekor
	// Rekor public keys for verification
	rekorPubKeys *cosign.TrustedTransparencyLogPubKeys
	// CT Log public keys for SCT verification
	ctLogPubKeys *cosign.TrustedTransparencyLogPubKeys
}

func (sv *SignatureVerifier) convertToCheckOpts() (*cosign.CheckOpts, error) {
	switch sv.verificationType {
	case CertificateVerification:
		return &cosign.CheckOpts{
			RootCerts:         sv.rootCerts,
			IntermediateCerts: sv.intermediateCerts,
			IgnoreTlog:        true,
			IgnoreSCT:         true,
		}, nil
	case KeyVerification:
		verifier, err := signature.LoadVerifier(sv.publicKey, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &cosign.CheckOpts{
			IgnoreTlog:  true,
			IgnoreSCT:   true,
			SigVerifier: verifier,
		}, nil
	default: // KeylessVerification
		return &cosign.CheckOpts{
			RootCerts:         sv.rootCerts,
			IntermediateCerts: sv.intermediateCerts,
			Identities:        sv.identities,
			RekorClient:       sv.rekorClient,
			RekorPubKeys:      sv.rekorPubKeys,
			CTLogPubKeys:      sv.ctLogPubKeys,
			IgnoreSCT:         false,
			IgnoreTlog:        false,
		}, nil
	}
}

// WithCertificateVerification configures the verifier for certificate-based verification
// certPEM and chainPEM are PEM encoded certificate and certificate chain
func (sv *SignatureVerifier) WithCertificateVerification(certPEM, chainPEM string) (*SignatureVerifier, error) {
	sv.verificationType = CertificateVerification

	// Parse the certificate
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in certPEM")
	}

	if chainPEM == "" {
		chainPEM = certPEM // Use the same cert as chain if no chain provided
	}

	// Parse the certificate chain
	chainCerts, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(chainPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing certificate chain: %w", err)
	}

	// Set up certificate pools
	sv.rootCerts = x509.NewCertPool()
	sv.intermediateCerts = x509.NewCertPool()

	// Add chain certificates to appropriate pools
	for _, cert := range chainCerts {
		if cert.IsCA {
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				// Self-signed certificate goes to root pool
				sv.rootCerts.AddCert(cert)
			} else {
				// Intermediate certificate
				sv.intermediateCerts.AddCert(cert)
			}
		}
	}

	return sv, nil
}

func (sv *SignatureVerifier) WithKeyVerification(publicKey string) (*SignatureVerifier, error) {
	sv.verificationType = KeyVerification
	var err error
	sv.publicKey, err = cryptoutils.UnmarshalPEMToPublicKey([]byte(publicKey))
	return sv, err
}

// WithKeylessVerification configures the verifier for keyless verification using Fulcio and Rekor
func (sv *SignatureVerifier) WithKeylessVerification(SigningOIDCIssuer, SigningOIDCIdentity string) (*SignatureVerifier, error) {
	sv.verificationType = KeylessVerification

	// Get Fulcio root certificates if not already set
	if sv.rootCerts == nil {
		roots, err := fulcioroots.Get()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio roots: %w", err)
		}
		sv.rootCerts = roots
	}

	// Get Fulcio intermediate certificates if not already set
	if sv.intermediateCerts == nil {
		intermediates, err := fulcioroots.GetIntermediates()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
		}
		sv.intermediateCerts = intermediates
	}

	// Initialize rekor client if not already set
	if sv.rekorClient == nil {
		rekorClient, err := rekor.GetRekorClient(RekorURL)
		if err != nil {
			return nil, fmt.Errorf("getting rekor client: %w", err)
		}
		sv.rekorClient = rekorClient
	}

	// Get Rekor public keys if not already set
	if sv.rekorPubKeys == nil {
		rekorPubs, err := cosign.GetRekorPubs(context.Background())
		if err != nil {
			return nil, fmt.Errorf("getting Rekor public keys: %w", err)
		}
		sv.rekorPubKeys = rekorPubs
	}

	// Get CT Log public keys if not already set
	if sv.ctLogPubKeys == nil {
		ctLogPubs, err := cosign.GetCTLogPubs(context.Background())
		if err != nil {
			return nil, fmt.Errorf("getting CT log public keys: %w", err)
		}
		sv.ctLogPubKeys = ctLogPubs
	}
	sv.identities = append(sv.identities, cosign.Identity{
		IssuerRegExp:  SigningOIDCIssuer,
		SubjectRegExp: SigningOIDCIdentity,
	})
	return sv, nil
}

// verifyImage contains the common verification logic
func (sv *SignatureVerifier) verifyRemoteImage(ctx context.Context, imageRef string, remoteOptions []remote.Option) ([]oci.Signature, bool, error) {
	// Parse the image reference
	repo, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, false, fmt.Errorf("parsing image reference: %w", err)
	}

	checkOpts, err := sv.convertToCheckOpts()
	if err != nil {
		return nil, false, err
	}
	checkOpts.RegistryClientOpts = []ociremote.Option{
		ociremote.WithRemoteOptions(remoteOptions...),
	}

	// Perform verification
	sigs, bundleVerified, err := cosign.VerifyImageSignatures(ctx, repo, checkOpts)
	if err != nil {
		return nil, false, fmt.Errorf("verifying signatures: %w", err)
	}

	return sigs, bundleVerified, nil
}

// VerifyWithBasicAuth verifies a signature using username/password authentication
func (sv *SignatureVerifier) VerifyWithBasicAuth(ctx context.Context, imageRef, username, password string) ([]oci.Signature, bool, error) {
	// Create authentication object
	auth := &authn.Basic{
		Username: username,
		Password: password,
	}

	// Define remote options with authentication
	remoteOptions := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(auth),
	}

	return sv.verifyRemoteImage(ctx, imageRef, remoteOptions)
}

// VerifyWithKeychain verifies a signature using the default keychain
func (sv *SignatureVerifier) VerifyWithKeychain(ctx context.Context, imageRef string) ([]oci.Signature, bool, error) {
	// Define remote options with keychain authentication
	remoteOptions := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	return sv.verifyRemoteImage(ctx, imageRef, remoteOptions)
}

// VerifyLocalBlob verifies a signature for a local file and signature
// verifyBlobWithBundle verifies a blob using a bundle
func (sv *SignatureVerifier) verifyBlobWithBundle(ctx context.Context, fileContent []byte, b *cosign.LocalSignedPayload) error {
	checkOpts, err := sv.convertToCheckOpts()
	if err != nil {
		return err
	}

	// Parse signature
	opts := make([]static.Option, 0)
	targetSig := []byte(b.Base64Signature)
	var sig string
	if isb64(targetSig) {
		sig = string(targetSig)
	} else {
		sig = base64.StdEncoding.EncodeToString(targetSig)
	}

	// Prepare certificate
	if b.Cert != "" {
		certBytes := []byte(b.Cert)
		if isb64(certBytes) {
			certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
		}
		bundleCert, err := loadCertFromPEM(certBytes)
		if err != nil {
			checkOpts.SigVerifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
			if err != nil {
				return fmt.Errorf("loading verifier from public key: %w", err)
			}
		}
		if bundleCert != nil {
			certPEM, err := cryptoutils.MarshalCertificateToPEM(bundleCert)
			if err != nil {
				return err
			}
			opts = append(opts, static.WithCertChain(certPEM, []byte{}))
		}
	}

	opts = append(opts, static.WithBundle(b.Bundle))
	signature, err := static.NewSignature(fileContent, sig, opts...)
	if err != nil {
		return fmt.Errorf("creating signature: %w", err)
	}

	// Verify the signature using cosign's bundle verification
	_, err = cosign.VerifyBlobSignature(ctx, signature, checkOpts)
	if err != nil {
		return fmt.Errorf("bundle verification failed: %w", err)
	}
	return nil
}

func (sv *SignatureVerifier) VerifyLocalBlob(ctx context.Context, filePath, bundlePath string) error {
	// Read the file content
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Try to parse as bundle
	b, err := cosign.FetchLocalSignedPayloadFromPath(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to parse signature as bundle: %w", err)
	}
	return sv.verifyBlobWithBundle(ctx, fileContent, b)
}

// VerifyOCIChartDigestFromHTTPSignature verifies an OCI chart against an HTTP signature without downloading the chart content
func (sv *SignatureVerifier) VerifyOCIChartDigestFromHTTPSignature(ctx context.Context, chartRef, sigURL string, remoteOptions []remote.Option) error {
	// Parse the image reference
	repo, err := name.ParseReference(chartRef)
	if err != nil {
		return fmt.Errorf("parsing chart reference: %w", err)
	}

	// Get OCI chart descriptor (metadata only, no content download)
	descriptor, err := remote.Get(repo, remoteOptions...)
	if err != nil {
		return fmt.Errorf("getting chart descriptor: %w", err)
	}

	// Download signature from HTTP URL
	signatureBytes, err := downloadContent(ctx, sigURL)
	if err != nil {
		return fmt.Errorf("downloading signature: %w", err)
	}

	// Use the signature bytes as-is (they should already be base64 encoded)
	b64sig := string(signatureBytes)

	// Create a signature object from the chart digest and signature
	// We use the digest bytes as the "content" for signature verification
	digestBytes := []byte(descriptor.Digest.String())
	sig, err := static.NewSignature(digestBytes, b64sig)
	if err != nil {
		return fmt.Errorf("creating signature: %w", err)
	}

	checkOpts, err := sv.convertToCheckOpts()
	if err != nil {
		return err
	}

	// Verify the signature using VerifyBlobSignature
	_, err = cosign.VerifyBlobSignature(ctx, sig, checkOpts)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// VerifyOCIChartDigestFromHTTPSignatureWithBasicAuth verifies an OCI chart against an HTTP signature using basic auth
func (sv *SignatureVerifier) VerifyOCIChartDigestFromHTTPSignatureWithBasicAuth(ctx context.Context, chartRef, sigURL, username, password string) error {
	// Create authentication object
	auth := &authn.Basic{
		Username: username,
		Password: password,
	}

	// Define remote options with authentication
	remoteOptions := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(auth),
	}

	return sv.VerifyOCIChartDigestFromHTTPSignature(ctx, chartRef, sigURL, remoteOptions)
}

// downloadContent downloads content from a URL and returns it as a byte slice
func downloadContent(ctx context.Context, url string) ([]byte, error) {
	// Create an HTTP client with context support
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the entire response body into a byte slice
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return content, nil
}

func isb64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

func loadCertFromPEM(pems []byte) (*x509.Certificate, error) {
	var out []byte
	out, err := base64.StdEncoding.DecodeString(string(pems))
	if err != nil {
		// not a base64
		out = pems
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(out)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem file")
	}
	return certs[0], nil
}
