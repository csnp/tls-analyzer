package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The enforcement matrix for verifyCertificateChain: every condition it is
// responsible for rejecting needs a case that violates exactly that condition
// and asserts the verdict flips to CheckFailed. A verifier is defined by what it
// rejects, and a suite that only proves good chains pass proves nothing.
//
// The chain-position cases (expired and not-yet-valid intermediates) live in
// certificate_chain_position_test.go. This file covers the rest of the surface
// the Verify call declares, which had no rejection case of its own:
//
//	Roots         -> untrusted root                 (covered here)
//	Intermediates -> missing intermediate           (covered here)
//	KeyUsages     -> certificate not for serverAuth (covered here)
//
// One correction to what this header used to say, made in 0.4.1. It claimed the
// KeyUsages enforcement "was unproven rather than known-good". The enforcement
// is proven, by TestACertificateNotValidForServerAuthFailsTheChain below. What
// is not provable is that the EXPLICIT option changes anything: deleting
// `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}` from the
// production call leaves this whole suite green, because crypto/x509 documents
// an empty KeyUsages as meaning exactly that value. No input distinguishes the
// two, so no test here can.
//
// The option is kept, and the equivalence with Go's default is pinned directly
// in production_verifier_config_test.go, which fails if that default ever moves.
//
// Every case in this file passes an explicit non-nil Roots. A real scan passes
// nil, which routes to the platform verifier on darwin and windows; that
// configuration is exercised in production_verifier_config_test.go, because
// nothing here does.

// chainFixture is a root plus a leaf built to whatever shape a case needs.
type chainFixture struct {
	root  *x509.Certificate
	inter *x509.Certificate
	leaf  *x509.Certificate
	roots *x509.CertPool
}

// buildLeafWithEKU mints root -> intermediate -> leaf, all current, with the
// leaf's extended key usages supplied by the caller.
func buildLeafWithEKU(t *testing.T, eku []x509.ExtKeyUsage) chainFixture {
	t.Helper()
	now := time.Now()

	root, rootKey, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "eku matrix root"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build root: %v", err)
	}

	inter, interKey, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "eku matrix intermediate"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, root, rootKey)
	if err != nil {
		t.Fatalf("build intermediate: %v", err)
	}

	leaf, _, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.AddDate(0, -1, 0),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
	}, inter, interKey)
	if err != nil {
		t.Fatalf("build leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return chainFixture{root: root, inter: inter, leaf: leaf, roots: roots}
}

// TestACertificateNotValidForServerAuthFailsTheChain closes the one hole the
// enforcement matrix found: KeyUsages is declared in the Verify options and no
// test violated it, so the rejection was unproven. A client-authentication
// certificate presented as a server certificate must not pass.
func TestACertificateNotValidForServerAuthFailsTheChain(t *testing.T) {
	fixture := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	parsed := parseCertificate(fixture.leaf)
	verifyCertificateChain(fixture.leaf, []*x509.Certificate{fixture.inter}, parsed, fixture.roots)

	// Guard the fixture: everything else about this chain must be sound, or the
	// rejection could be coming from a condition this case is not about.
	if parsed.Expired || parsed.NotYetValid {
		t.Fatalf("fixture is wrong: the leaf must be current")
	}

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("a certificate carrying only clientAuth was accepted as a server "+
			"certificate: chainTrust=%v reason=%q", parsed.ChainTrust, parsed.ChainTrustReason)
	}
	if parsed.ChainTrustReason == "" {
		t.Error("the chain failed with no reason, so the report cannot say why")
	}
}

// TestAServerAuthCertificateStillPasses is the control for the case above. A
// verifier that rejected every extended key usage would satisfy it and break
// every real scan.
func TestAServerAuthCertificateStillPasses(t *testing.T) {
	fixture := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	parsed := parseCertificate(fixture.leaf)
	verifyCertificateChain(fixture.leaf, []*x509.Certificate{fixture.inter}, parsed, fixture.roots)

	if parsed.ChainTrust != types.CheckPassed {
		t.Errorf("a sound serverAuth chain did not pass: chainTrust=%v reason=%q",
			parsed.ChainTrust, parsed.ChainTrustReason)
	}
}

// TestAChainMissingItsIntermediateFails covers the Intermediates option. A
// server that serves only its leaf is a real and common misconfiguration, and
// it must not be reported as trusted just because the root is known.
func TestAChainMissingItsIntermediateFails(t *testing.T) {
	fixture := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	parsed := parseCertificate(fixture.leaf)
	// The intermediate is deliberately not supplied.
	verifyCertificateChain(fixture.leaf, nil, parsed, fixture.roots)

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("a chain served without its intermediate was not reported as failed: "+
			"chainTrust=%v reason=%q", parsed.ChainTrust, parsed.ChainTrustReason)
	}
}

// TestAnUntrustedRootFails covers the Roots option.
//
// The control-character assertion this test used to carry was vacuous: it built
// the fixture with the benign common name "localhost", so the check could not
// fail whatever the code did. An adversarial review pointed that out. The
// fixture now carries a hostile subject, which is what a scanned server would
// actually choose, so the assertion constrains something.
//
// Whether the RENDERED report is safe is a separate question, answered in the
// reporter package where the escaping is applied. This asserts only that the
// scanner does not build a reason around raw control characters of its own.
func TestAnUntrustedRootFails(t *testing.T) {
	fixture := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	parsed := parseCertificate(fixture.leaf)
	// An empty pool trusts nothing.
	verifyCertificateChain(fixture.leaf, []*x509.Certificate{fixture.inter}, parsed,
		x509.NewCertPool())

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("a chain to an untrusted root was not reported as failed: chainTrust=%v",
			parsed.ChainTrust)
	}
	if parsed.ChainTrustReason == "" {
		t.Error("a failed chain check must carry a reason the report can print")
	}
}

// TestAHostileSubjectDoesNotBreakTheChainVerdict is the case the vacuous
// assertion above was meant to be. The verdict itself must not change because a
// server chose an awkward name, and the scanner must not lose the reason.
func TestAHostileSubjectDoesNotBreakTheChainVerdict(t *testing.T) {
	now := time.Now()
	hostile := "Innocent CA\x1b[2K\r\x1b[32m  Chain trust: OK\x1b[0m\nStatus: VALID"

	leaf, _, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: hostile},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.AddDate(0, -1, 0),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build leaf: %v", err)
	}

	parsed := parseCertificate(leaf)
	verifyCertificateChain(leaf, nil, parsed, x509.NewCertPool())

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("a hostile subject changed the chain verdict: chainTrust=%v",
			parsed.ChainTrust)
	}
	if parsed.ChainTrustReason == "" {
		t.Error("the reason was lost for a certificate with a hostile subject")
	}
	if !strings.Contains(parsed.Subject, "Innocent CA") {
		t.Errorf("the parsed subject lost the server's text entirely, so the report cannot "+
			"show what was presented: %q", parsed.Subject)
	}
}
