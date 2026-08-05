package scanner

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Two things about the production Verify call were unexercised, and they are
// different problems with the same shape: the tests all ran a configuration the
// tool never uses.

// TestTheServerAuthOptionMatchesGosDefault is the answer to a mutation that
// survives and should.
//
// Deleting `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}` from the
// production options leaves the whole scanner suite green, including
// TestACertificateNotValidForServerAuthFailsTheChain, which was written to prove
// that enforcement. That is not a hole in the tests: crypto/x509 documents an
// empty KeyUsages as meaning exactly ExtKeyUsageServerAuth, so no input
// distinguishes the two versions and no test can. The enforcement is real and
// tested; what is untestable is that the explicit option changes anything.
//
// The rule is to add the test that pins the distinction rather than delete the
// code, and here the distinction that matters is with the DEPENDENCY: the option
// is kept because it states the intent at the call site and because it stops a
// future change to Go's default from silently widening what this tool accepts.
// This asserts that equivalence directly, so if that default ever moves, this
// fails and says which way.
func TestTheServerAuthOptionMatchesGosDefault(t *testing.T) {
	fixture := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	intermediates := x509.NewCertPool()
	intermediates.AddCert(fixture.inter)

	_, explicitErr := fixture.leaf.Verify(x509.VerifyOptions{
		Roots:         fixture.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	_, defaultErr := fixture.leaf.Verify(x509.VerifyOptions{
		Roots:         fixture.roots,
		Intermediates: intermediates,
	})

	if explicitErr == nil {
		t.Fatal("a client-auth-only certificate verified with ExtKeyUsageServerAuth " +
			"required, so this fixture is not exercising the option at all")
	}
	if defaultErr == nil {
		t.Errorf("crypto/x509 no longer defaults to ExtKeyUsageServerAuth: with KeyUsages "+
			"unset a client-auth-only certificate now verifies, while the explicit option "+
			"still rejects it (%v). Every caller in this repository that omits KeyUsages "+
			"has just widened what it accepts.", explicitErr)
	}

	// And the opposite direction, so the assertion above cannot be satisfied by a
	// verifier that rejects everything.
	serverAuth := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	serverIntermediates := x509.NewCertPool()
	serverIntermediates.AddCert(serverAuth.inter)
	if _, err := serverAuth.leaf.Verify(x509.VerifyOptions{
		Roots:         serverAuth.roots,
		Intermediates: serverIntermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("a server-auth certificate on a trusted chain failed to verify, so the "+
			"rejections above prove nothing: %v", err)
	}
}

// TestTheChainCheckFailsClosedOnTheConfigurationProductionUses exercises the one
// configuration every real scan runs and no test did.
//
// All thirteen leaf.Verify call sites in this package pass an explicit non-nil
// *x509.CertPool. A real scan passes nil, and on darwin and windows a nil Roots
// routes Verify to the PLATFORM verifier rather than the pure-Go one. The two
// verifiers do not construct their errors the same way, which this tool has
// already been bitten by once: on darwin the platform verifier binds
// CertificateInvalidError.Cert to the LEAF whatever actually failed, so a fix
// that compares invalid.Cert against the leaf is inert on the platforms most
// operators run.
//
// A certificate from a one-off CA is not in any system trust store, so the
// verdict is the same on both verifiers and the assertion is portable: it must
// fail, and it must fail as NOT TRUSTED rather than by taking any of the
// carve-out paths.
func TestTheChainCheckFailsClosedOnTheConfigurationProductionUses(t *testing.T) {
	fixture := buildLeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	parsed := &types.Certificate{}
	// nil roots: exactly what scanCertificate passes, and what routes to the
	// platform verifier on darwin.
	verifyCertificateChainAt(fixture.leaf, []*x509.Certificate{fixture.inter}, parsed, nil, time.Now())

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("chainTrust = %q for a certificate signed by a CA no system trusts, on the "+
			"nil-Roots configuration every real scan uses. want %q. A chain check that does "+
			"not fail here fails open on the only configuration that ships.",
			parsed.ChainTrust, types.CheckFailed)
	}
	if parsed.ChainTrustReason == "" {
		t.Error("the chain failed with no reason recorded, so the report can say the chain " +
			"is not trusted and not say why")
	}

	// The acceptance control has to be the same code path, not a different one:
	// with the fixture's own CA supplied as Roots, the identical chain verifies.
	// Without this, a verifier that failed everything would satisfy the above.
	trusted := &types.Certificate{}
	verifyCertificateChainAt(fixture.leaf, []*x509.Certificate{fixture.inter}, trusted,
		fixture.roots, time.Now())
	if trusted.ChainTrust != types.CheckPassed {
		t.Errorf("chainTrust = %q with the issuing CA trusted, want %q; the failure above "+
			"is the verifier rejecting everything rather than rejecting this chain",
			trusted.ChainTrust, types.CheckPassed)
	}
}
