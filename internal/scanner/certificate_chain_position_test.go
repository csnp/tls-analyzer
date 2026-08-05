package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The tests in this file name nothing that did not already exist, so they
// build against the sources before the fix and fail there at runtime.
//
// Measured in 0.4.1: that does not hold. Copied alone into a pristine tree at
// a869357 this file does not build (`undefined: verifyCertificateChain`),
// because 0.4.0 landed as one squashed commit and the production change arrived
// with its tests. See docs/testing/red-proof.md for how these are red-proved
// instead. Anything that has to name a new helper lives in
// certificate_chain_position_fields_test.go.
//
// The defect: verifyCertificateChain stepped aside whenever x509 returned
// CertificateInvalidError{Reason: Expired}, on the stated grounds that the
// certificate's validity window "is reported on its own". Go returns that reason
// for ANY certificate in the chain and names the offender in invalid.Cert, while
// Certificate.Expired and Certificate.NotYetValid are derived from the leaf
// alone. So a chain whose INTERMEDIATE had expired, with a perfectly current
// leaf, was reported as not evaluated and nothing anywhere reported the window.

// signedCert mints a certificate under parent, or a self-signed one when parent
// is nil. It returns the error rather than failing the test itself, so a caller
// can assert on it; a helper that fatals cannot be tested for its own failure.
func signedCert(
	tmpl, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, _, key, err := signedCertDER(tmpl, parent, parentKey)
	return cert, key, err
}

// signedCertDER also returns the DER, which a server needs to present a chain.
func signedCertDER(
	tmpl, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
) (*x509.Certificate, []byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, signee := parentKey, parent
	if signer == nil {
		signer, signee = key, tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signee, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, der, key, nil
}

// threeLevelChain is a root, an intermediate and a leaf, with the intermediate's
// validity window supplied by the caller so a test can place it in the past, in
// the future, or squarely around now.
//
// serving carries the chain a server actually presents, leaf first, so the same
// fixture can be driven through the whole Scan path against a local listener.
type threeLevelChain struct {
	root    *x509.Certificate
	inter   *x509.Certificate
	leaf    *x509.Certificate
	roots   *x509.CertPool
	serving tls.Certificate
}

func buildThreeLevelChain(t *testing.T, interNotBefore, interNotAfter time.Time) threeLevelChain {
	t.Helper()
	now := time.Now()

	root, rootKey, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chain position test root"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build root: %v", err)
	}

	inter, interDER, interKey, err := signedCertDER(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "chain position test intermediate"},
		NotBefore:             interNotBefore,
		NotAfter:              interNotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, root, rootKey)
	if err != nil {
		t.Fatalf("build intermediate: %v", err)
	}

	// The leaf is current in every fixture here. The whole point is that the
	// defect is invisible in every field that describes the leaf.
	leaf, leafDER, leafKey, err := signedCertDER(&x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now.AddDate(0, -1, 0),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, inter, interKey)
	if err != nil {
		t.Fatalf("build leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	return threeLevelChain{
		root:  root,
		inter: inter,
		leaf:  leaf,
		roots: roots,
		serving: tls.Certificate{
			Certificate: [][]byte{leafDER, interDER},
			PrivateKey:  leafKey,
			Leaf:        leaf,
		},
	}
}

// TestExpiredIntermediateFailsChainTrust is the reproduction. Measured before
// the fix: chainTrust=notPerformed with leaf.Expired and leaf.NotYetValid both
// false, so the reason string's promise that the window "is reported on its own"
// was false, and no field anywhere carried it.
func TestExpiredIntermediateFailsChainTrust(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	parsed := parseCertificate(chain.leaf)
	verifyCertificateChain(chain.leaf, []*x509.Certificate{chain.inter}, parsed, chain.roots)

	// Guard the fixture: if the leaf's own flags were set, the defect under test
	// would be masked by a condition that IS reported elsewhere, and the
	// assertion below would prove nothing.
	if parsed.Expired || parsed.NotYetValid {
		t.Fatalf("fixture is wrong: the leaf must be current, got expired=%v notYetValid=%v",
			parsed.Expired, parsed.NotYetValid)
	}

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("an expired intermediate left chainTrust=%v (reason %q) while the leaf is "+
			"current, so no client would accept this chain and nothing in the report says so",
			parsed.ChainTrust, parsed.ChainTrustReason)
	}

	// The operator has to be able to find the certificate at fault, and it is not
	// the one every other field of the report describes.
	if !strings.Contains(parsed.ChainTrustReason, chain.inter.Subject.CommonName) {
		t.Errorf("the reason %q does not name the failing certificate %q, so the report "+
			"does not say which certificate to replace",
			parsed.ChainTrustReason, chain.inter.Subject.CommonName)
	}
}

// TestNotYetValidIntermediateFailsChainTrust covers the other end of the window.
// x509 reports Expired for both ends, so a fix that special-cased the word
// "expired" rather than the position in the chain would pass the test above and
// still swallow a pre-staged intermediate.
func TestNotYetValidIntermediateFailsChainTrust(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(0, 1, 0), now.AddDate(5, 0, 0))

	parsed := parseCertificate(chain.leaf)
	verifyCertificateChain(chain.leaf, []*x509.Certificate{chain.inter}, parsed, chain.roots)

	if parsed.Expired || parsed.NotYetValid {
		t.Fatalf("fixture is wrong: the leaf must be current, got expired=%v notYetValid=%v",
			parsed.Expired, parsed.NotYetValid)
	}
	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("a not-yet-valid intermediate left chainTrust=%v (reason %q) while the leaf "+
			"is current", parsed.ChainTrust, parsed.ChainTrustReason)
	}
}

// TestExpiredLeafStillSkipsTheChainCheck is the control that keeps the fix
// honest. The exemption exists so an expired LEAF is not reported twice, once as
// expiry and again as a differently worded trust failure. Deleting the exemption
// outright would pass both tests above and reintroduce the double report, so
// this asserts the exemption survives for the certificate it was written for.
func TestExpiredLeafStillSkipsTheChainCheck(t *testing.T) {
	now := time.Now()

	root, rootKey, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired leaf control root"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build root: %v", err)
	}

	// Only the leaf is outside its window. The root is current.
	leaf, _, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(0, -1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, root, rootKey)
	if err != nil {
		t.Fatalf("build leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	parsed := parseCertificate(leaf)
	verifyCertificateChain(leaf, nil, parsed, roots)

	if !parsed.Expired {
		t.Fatalf("fixture is wrong: the leaf must be expired for this control to mean anything")
	}
	if parsed.ChainTrust != types.CheckNotPerformed {
		t.Errorf("the leaf's own expiry is reported by the expiry finding, so the chain check "+
			"steps aside for it; got chainTrust=%v reason=%q. Reporting it here as well states "+
			"one defect twice", parsed.ChainTrust, parsed.ChainTrustReason)
	}
}

// TestATrustedChainStillPasses is the second control. A fix that failed the
// chain whenever any error came back would pass every assertion above while
// breaking every healthy scan.
func TestATrustedChainStillPasses(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0))

	parsed := parseCertificate(chain.leaf)
	verifyCertificateChain(chain.leaf, []*x509.Certificate{chain.inter}, parsed, chain.roots)

	if parsed.ChainTrust != types.CheckPassed {
		t.Errorf("a chain with a current root, a current intermediate and a current leaf did "+
			"not pass: chainTrust=%v reason=%q", parsed.ChainTrust, parsed.ChainTrustReason)
	}
}

// TestExpiredIntermediateScoresTheCertificateDimensionZero is the half of the
// finding that an operator actually sees. Measured before the fix: Certificate
// 25/25 "Certificate is current; name or chain verification did not run", grade
// A 91/100, zero vulnerabilities, for a chain no client accepts.
func TestExpiredIntermediateScoresTheCertificateDimensionZero(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	parsed := parseCertificate(chain.leaf)
	verifyCertificateName(chain.leaf, parsed, "localhost")
	verifyCertificateChain(chain.leaf, []*x509.Certificate{chain.inter}, parsed, chain.roots)

	result := &types.ScanResult{
		Host:        "localhost",
		Port:        443,
		Certificate: parsed,
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true},
			{Version: "TLS 1.2", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true, Protocol: "TLS 1.3"},
		},
	}
	result.QuantumRisk = types.QuantumRiskAssessment{Score: 64}

	s := &Scanner{config: &Config{CheckQuantum: true, CheckVulns: true}}
	result.Vulnerabilities = s.checkVulnerabilities(result)
	result.Grade = s.calculateGrade(result)

	var certFactor *types.GradeFactor
	for i := range result.Grade.Factors {
		if result.Grade.Factors[i].Category == "Certificate" {
			certFactor = &result.Grade.Factors[i]
			break
		}
	}
	if certFactor == nil {
		t.Fatal("no Certificate grade factor, so this test cannot measure what it is about")
	}

	if certFactor.Score == certFactor.MaxScore {
		t.Errorf("the certificate dimension scored full %d/%d (%q) for a chain with an expired "+
			"intermediate, grading %s %d/100",
			certFactor.Score, certFactor.MaxScore, certFactor.Details,
			result.Grade.Letter, result.Grade.Score)
	}

	var found bool
	for _, v := range result.Vulnerabilities {
		if v.ID == "CERT_CHAIN_UNTRUSTED" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no CERT_CHAIN_UNTRUSTED finding for a chain with an expired intermediate; "+
			"got %d findings", len(result.Vulnerabilities))
	}
}

// TestScanOfAServerWithAnExpiredIntermediate drives the whole Scan path against
// a real listener, rather than calling the chain check directly.
//
// This cannot be reproduced through the CLI on this platform: the binary has no
// flag for the trust store, and Go on macOS verifies through the system verifier
// and ignores SSL_CERT_FILE, so a hand-built root is never trusted and the
// handshake fails with UnknownAuthority before the branch under test is reached.
// Setting TrustRoots in-process is what makes the branch reachable, and it is
// the same field the library exposes to callers.
func TestScanOfAServerWithAnExpiredIntermediate(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	host, port := startLocalTLSServer(t, chain.serving)

	cfg := localScanConfig()
	cfg.TrustRoots = chain.roots
	result := scanLocal(t, cfg, host, port)

	// Guard the fixture: if the root were not trusted the handshake would fail
	// with UnknownAuthority and never reach the expiry branch, so the assertions
	// below would pass for the wrong reason.
	if strings.Contains(result.Certificate.ChainTrustReason, "not trusted") {
		t.Fatalf("the test root was not trusted, so the branch under test never ran: %q",
			result.Certificate.ChainTrustReason)
	}
	if result.Certificate.Expired || result.Certificate.NotYetValid {
		t.Fatalf("fixture is wrong: the leaf must be current, got expired=%v notYetValid=%v",
			result.Certificate.Expired, result.Certificate.NotYetValid)
	}

	if result.Certificate.ChainTrust != types.CheckFailed {
		t.Errorf("a full scan of a server presenting an expired intermediate reported "+
			"chainTrust=%v (%q)", result.Certificate.ChainTrust,
			result.Certificate.ChainTrustReason)
	}
	if f := certificateFactor(t, result); f.Score == f.MaxScore {
		t.Errorf("the certificate dimension scored full %d/%d (%q) on a scan of a server no "+
			"client would accept, grading %s %d/100",
			f.Score, f.MaxScore, f.Details, result.Grade.Letter, result.Grade.Score)
	}
	if findVulnerability(result, "CERT_CHAIN_UNTRUSTED") == nil {
		t.Errorf("a full scan raised no CERT_CHAIN_UNTRUSTED finding; got %d findings",
			len(result.Vulnerabilities))
	}
}

// TestScanOfAServerWithACurrentChain is the control for the scan-level test. A
// fix that failed every chain would satisfy the test above while breaking every
// healthy scan, and this is the assertion that tells those apart at the same
// level.
func TestScanOfAServerWithACurrentChain(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0))

	host, port := startLocalTLSServer(t, chain.serving)

	cfg := localScanConfig()
	cfg.TrustRoots = chain.roots
	result := scanLocal(t, cfg, host, port)

	if result.Certificate.ChainTrust != types.CheckPassed {
		t.Errorf("a scan of a server presenting a wholly current chain reported "+
			"chainTrust=%v (%q)", result.Certificate.ChainTrust,
			result.Certificate.ChainTrustReason)
	}
	if findVulnerability(result, "CERT_CHAIN_UNTRUSTED") != nil {
		t.Errorf("a healthy chain raised CERT_CHAIN_UNTRUSTED")
	}
}
