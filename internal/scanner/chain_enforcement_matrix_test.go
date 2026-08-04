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
//	                 this one is declared in the options and was never tested,
//	                 so its enforcement was unproven rather than known-good.

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

// TestAnUntrustedRootFails covers the Roots option, and pins that the reason
// carries no attacker-chosen subject on this path. Go's message for this case is
// fixed text, which is why the escaping test focuses on the expired-chain path.
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
	for _, bad := range []string{"\x1b", "\n", "\r"} {
		if strings.Contains(parsed.ChainTrustReason, bad) {
			t.Errorf("a raw control character reached the chain reason: %q",
				parsed.ChainTrustReason)
		}
	}
}
