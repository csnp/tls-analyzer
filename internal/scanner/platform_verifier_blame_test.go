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

// Go has two certificate verifiers and only one of them says which certificate
// failed. Every test in this package passes an explicit root pool, and that is
// the ONLY configuration that reaches the pure-Go verifier. Every real scan
// passes a nil pool, which on darwin, windows and ios routes to the platform
// verifier instead (verify.go: "Use platform verifiers, where available, if
// Roots is from SystemCertPool").
//
// The platform verifiers build CertificateInvalidError with the certificate
// bound to the LEAF whatever actually failed:
//
//	root_darwin.go:65    return nil, CertificateInvalidError{c, Expired, err.Error()}
//	root_windows.go:99   return CertificateInvalidError{c, Expired, ""}
//
// Measured on go1.26.3 darwin/arm64 against a real chain evaluated past the
// leaf's notAfter with Roots nil: Reason=1, Cert.CN="github.com", isLeaf=true.
//
// A first version of the expired-intermediate fix compared the blamed
// certificate against the leaf, so on macOS and Windows the comparison always
// succeeded, the exemption always fired, and an expired intermediate still
// graded A 91/100 with zero findings. The suite stayed green because nothing
// exercised the platform shape.
//
// These tests drive the decision directly with each verifier's output shape, so
// the platform path is covered on any machine the suite runs on.

// TestAnExpiredIntermediateFailsEvenWhenTheVerifierBlamesTheLeaf is the
// reproduction of the platform-verifier gap.
func TestAnExpiredIntermediateFailsEvenWhenTheVerifierBlamesTheLeaf(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	parsed := parseCertificate(chain.leaf)

	// This is exactly what root_darwin.go hands back: the reason is Expired and
	// the certificate blamed is the leaf, which is current.
	applyValidityWindowVerdict(chain.leaf, chain.leaf, parsed)

	if parsed.Expired || parsed.NotYetValid {
		t.Fatalf("fixture is wrong: the leaf must be current for this to be the platform case")
	}
	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("the chain was not failed when the verifier blamed a leaf that is inside its "+
			"own window: chainTrust=%v reason=%q. On macOS and Windows this is every "+
			"expired-intermediate scan.", parsed.ChainTrust, parsed.ChainTrustReason)
	}

	// It must not name the leaf as the expired certificate. The report shows the
	// leaf's dates, and a reason naming it would contradict them.
	if strings.Contains(parsed.ChainTrustReason, chain.leaf.Subject.CommonName) {
		t.Errorf("the reason names the leaf %q as the certificate at fault, which the same "+
			"report shows as current: %q",
			chain.leaf.Subject.CommonName, parsed.ChainTrustReason)
	}
	if parsed.ChainTrustReason == "" {
		t.Error("a failed chain check must carry a reason the report can print")
	}
}

// TestTheGoVerifierShapeStillNamesTheOffender is the other half. When the
// verifier does identify the certificate, that detail must survive, because it
// is the only place the operator learns which one to replace.
func TestTheGoVerifierShapeStillNamesTheOffender(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	parsed := parseCertificate(chain.leaf)

	// This is what the pure-Go verifier hands back: the intermediate is blamed.
	applyValidityWindowVerdict(chain.leaf, chain.inter, parsed)

	if parsed.ChainTrust != types.CheckFailed {
		t.Errorf("chainTrust=%v, want failed", parsed.ChainTrust)
	}
	if !strings.Contains(parsed.ChainTrustReason, chain.inter.Subject.CommonName) {
		t.Errorf("the reason does not name the intermediate the verifier identified: %q",
			parsed.ChainTrustReason)
	}
}

// TestAnExpiredLeafIsStillLeftToTheExpiryFinding is the control, in both verifier
// shapes. Failing the chain for the leaf's own window states one defect twice.
func TestAnExpiredLeafIsStillLeftToTheExpiryFinding(t *testing.T) {
	now := time.Now()

	expiredLeaf, _, err := signedCert(&x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               subjectCN("expired leaf control"),
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(0, -1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build leaf: %v", err)
	}

	for _, tc := range []struct {
		name   string
		blamed *x509.Certificate
	}{
		{"platform verifier blames the leaf", expiredLeaf},
		{"go verifier blames the leaf", expiredLeaf},
		{"verifier names nothing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := parseCertificate(expiredLeaf)
			if !parsed.Expired {
				t.Fatal("fixture is wrong: the leaf must be expired")
			}

			applyValidityWindowVerdict(expiredLeaf, tc.blamed, parsed)

			if parsed.ChainTrust != types.CheckNotPerformed {
				t.Errorf("an expired leaf failed the chain check as well as raising its own "+
					"expiry finding, which deducts twice for one fact: chainTrust=%v",
					parsed.ChainTrust)
			}
		})
	}
}

// TestANotYetValidLeafIsAlsoLeftToItsOwnFinding covers the other end of the
// window, since x509 reports Expired for both.
func TestANotYetValidLeafIsAlsoLeftToItsOwnFinding(t *testing.T) {
	now := time.Now()

	futureLeaf, _, err := signedCert(&x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               subjectCN("not yet valid control"),
		NotBefore:             now.AddDate(0, 1, 0),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build leaf: %v", err)
	}

	parsed := parseCertificate(futureLeaf)
	if !parsed.NotYetValid {
		t.Fatal("fixture is wrong: the leaf must be not yet valid")
	}

	applyValidityWindowVerdict(futureLeaf, futureLeaf, parsed)

	if parsed.ChainTrust != types.CheckNotPerformed {
		t.Errorf("a not-yet-valid leaf failed the chain check as well as raising its own "+
			"finding: chainTrust=%v", parsed.ChainTrust)
	}
}

// TestTheVerdictDoesNotDependOnTheCallerPopulatingTheResult pins that this
// decision reads the leaf rather than the parsed result. Depending on the caller
// having called parseCertificate first would be a hidden ordering coupling, and
// the existing suite calls verifyCertificateChain with an empty result.
func TestTheVerdictDoesNotDependOnTheCallerPopulatingTheResult(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	// Deliberately NOT parseCertificate: an empty result, as the older tests use.
	empty := &types.Certificate{}
	applyValidityWindowVerdict(chain.leaf, chain.leaf, empty)

	if empty.ChainTrust != types.CheckFailed {
		t.Errorf("the verdict changed because the caller had not populated the result "+
			"first: chainTrust=%v", empty.ChainTrust)
	}
}

// bigOne and subjectCN keep the fixtures above readable.
func bigOne() *big.Int { return big.NewInt(1) }

func subjectCN(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
