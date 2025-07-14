package verify

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

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
)

const (
	RekorURL = "https://rekor.sigstore.dev"
)

// SignatureVerifier provides methods to verify signatures using Cosign
type SignatureVerifier struct {
	// Root certificates for verification
	rootCerts *x509.CertPool
	// Intermediate certificates for verification
	intermediateCerts *x509.CertPool
	// OIDC identity requirements
	identities []cosign.Identity
	// Rekor client for transparency log verification
	rekorClient *client.Rekor
	// Rekor public keys for verification
	rekorPubKeys *cosign.TrustedTransparencyLogPubKeys
	// CT Log public keys for SCT verification
	ctLogPubKeys *cosign.TrustedTransparencyLogPubKeys
	// Whether to skip SCT verification
	ignoreSCT bool
	// Whether to skip transparency log verification
	ignoreTlog bool
}

func (sv *SignatureVerifier) convertToCheckOpts() *cosign.CheckOpts {
	return &cosign.CheckOpts{
		RootCerts:         sv.rootCerts,
		IntermediateCerts: sv.intermediateCerts,
		Identities:        sv.identities,
		RekorClient:       sv.rekorClient,
		RekorPubKeys:      sv.rekorPubKeys,
		CTLogPubKeys:      sv.ctLogPubKeys,
		IgnoreSCT:         sv.ignoreSCT,
		IgnoreTlog:        sv.ignoreTlog,
	}
}

// GetRekorClient returns a configured Rekor client
func GetRekorClient() (*client.Rekor, error) {
	return rekor.GetRekorClient(RekorURL)
}

// NewSignatureVerifier creates a new signature verifier
func NewSignatureVerifier(ctx context.Context, roots *x509.CertPool) (*SignatureVerifier, error) {
	// Get Fulcio root certificates
	if roots == nil {
		var err error
		roots, err = fulcioroots.Get()
		if err != nil {
			return nil, fmt.Errorf("getting Fulcio roots: %w", err)
		}
	}
	intermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, fmt.Errorf("getting Fulcio intermediates: %w", err)
	}

	// Initialize rekor client
	rekorClient, err := GetRekorClient()
	if err != nil {
		return nil, fmt.Errorf("getting rekor client: %w", err)
	}

	// Get Rekor public keys
	rekorPubs, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting Rekor public keys: %w", err)
	}

	// Get CT Log public keys
	ctLogPubs, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting CT log public keys: %w", err)
	}

	return &SignatureVerifier{
		rootCerts:         roots,
		intermediateCerts: intermediates,
		identities:        []cosign.Identity{},
		rekorClient:       rekorClient,
		rekorPubKeys:      rekorPubs,
		ctLogPubKeys:      ctLogPubs,
		ignoreSCT:         false, // Default to requiring SCT
		ignoreTlog:        false, // Default to requiring tlog
	}, nil
}

// WithIgnoreSCT configures whether to skip SCT verification
func (sv *SignatureVerifier) WithIgnoreSCT(ignore bool) *SignatureVerifier {
	sv.ignoreSCT = ignore
	return sv
}

// WithIgnoreTlog configures whether to skip transparency log verification
func (sv *SignatureVerifier) WithIgnoreTlog(ignore bool) *SignatureVerifier {
	sv.ignoreTlog = ignore
	return sv
}

// WithIdentity adds an identity requirement
func (sv *SignatureVerifier) WithIdentity(issuer, subject string) *SignatureVerifier {
	sv.identities = append(sv.identities, cosign.Identity{
		Issuer:  issuer,
		Subject: subject,
	})
	return sv
}

// WithIdentityRegExp adds an identity requirement using regular expressions
func (sv *SignatureVerifier) WithIdentityRegExp(issuerRegex, subjectRegex string) *SignatureVerifier {
	sv.identities = append(sv.identities, cosign.Identity{
		IssuerRegExp:  issuerRegex,
		SubjectRegExp: subjectRegex,
	})
	return sv
}

// verifyImage contains the common verification logic
func (sv *SignatureVerifier) verifyRemoteImage(ctx context.Context, imageRef string, remoteOptions []remote.Option) ([]oci.Signature, bool, error) {
	// Parse the image reference
	repo, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, false, fmt.Errorf("parsing image reference: %w", err)
	}

	checkOpts := sv.convertToCheckOpts()
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

// VerifyLocalImage verifies a signature using a local image
func (sv *SignatureVerifier) VerifyLocalImage(ctx context.Context, imagePath string) ([]oci.Signature, bool, error) {
	// Check if file exists
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		return nil, false, fmt.Errorf("local image not found: %s", imagePath)
	}

	checkOpts := sv.convertToCheckOpts()

	// Perform verification on local file
	sigs, bundleVerified, err := cosign.VerifyLocalImageSignatures(ctx, imagePath, checkOpts)
	if err != nil {
		return nil, false, fmt.Errorf("verifying local image: %w", err)
	}

	return sigs, bundleVerified, nil
}

// VerifyLocalBlob verifies a signature for a local file and signature
// verifyBlobWithBundle verifies a blob using a bundle
func (sv *SignatureVerifier) verifyBlobWithBundle(ctx context.Context, fileContent []byte, b *cosign.LocalSignedPayload) error {
	checkOpts := sv.convertToCheckOpts()

	// Parse rekor bundle
	opts := make([]static.Option, 0)
	targetSig := []byte(b.Base64Signature)
	var sig string
	if isb64(targetSig) {
		sig = string(targetSig)
	} else {
		sig = base64.StdEncoding.EncodeToString(targetSig)
	}

	if b.Cert == "" {
		return fmt.Errorf("no certificate found in bundle")
	}

	certBytes := []byte(b.Cert)
	if isb64(certBytes) {
		certBytes, _ = base64.StdEncoding.DecodeString(b.Cert)
	}
	bundleCert, err := loadCertFromPEM(certBytes)
	if err != nil {
		// check if cert is actually a public key
		checkOpts.SigVerifier, err = sigs.LoadPublicKeyRaw(certBytes, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("loading verifier from bundle: %w", err)
		}
	}
	opts = append(opts, static.WithBundle(b.Bundle))
	if bundleCert != nil {
		certPEM, err := cryptoutils.MarshalCertificateToPEM(bundleCert)
		if err != nil {
			return err
		}
		opts = append(opts, static.WithCertChain(certPEM, []byte{}))
	}

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

// VerifyBlobFromHTTP downloads a file and its signature from an HTTP server and verifies it
func (sv *SignatureVerifier) VerifyBlobFromHTTP(ctx context.Context, fileURL, bundleURL string) error {
	// Download the file content
	fileContent, err := downloadContent(ctx, fileURL)
	if err != nil {
		return fmt.Errorf("downloading file content: %w", err)
	}

	// Download the signature
	signatureBytes, err := downloadContent(ctx, bundleURL)
	if err != nil {
		return fmt.Errorf("downloading signature: %w", err)
	}

	var b *cosign.LocalSignedPayload
	if err := json.Unmarshal(signatureBytes, &b); err != nil {
		return fmt.Errorf("signature URL is not a valid bundle file: %w", err)
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

	checkOpts := sv.convertToCheckOpts()

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
