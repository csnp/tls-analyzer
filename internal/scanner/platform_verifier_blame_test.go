package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
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
	applyValidityWindowVerdict(chain.leaf, chain.leaf, nil, time.Now(), parsed)

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
	applyValidityWindowVerdict(chain.leaf, chain.inter, nil, time.Now(), parsed)

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

			applyValidityWindowVerdict(expiredLeaf, tc.blamed, nil, time.Now(), parsed)

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

	applyValidityWindowVerdict(futureLeaf, futureLeaf, nil, time.Now(), parsed)

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
	applyValidityWindowVerdict(chain.leaf, chain.leaf, nil, time.Now(), empty)

	if empty.ChainTrust != types.CheckFailed {
		t.Errorf("the verdict changed because the caller had not populated the result "+
			"first: chainTrust=%v", empty.ChainTrust)
	}
}

// bigOne and subjectCN keep the fixtures above readable.
func bigOne() *big.Int { return big.NewInt(1) }

func subjectCN(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

// TestTheOffenderIsFoundFromThePresentedChainWhenTheVerifierWillNotSayIt is the
// case that makes the platform path useful rather than merely correct.
//
// The platform verifier blames the leaf whatever failed, so its answer is no
// answer. The server presented the rest of the chain on the same connection
// though, and a certificate outside its window is visible from the dates it
// carries. An earlier version printed "this platform's verifier does not report
// which one; inspect the chain with 'openssl s_client -showcerts'", sending the
// operator to fetch data the scanner was already holding.
func TestTheOffenderIsFoundFromThePresentedChainWhenTheVerifierWillNotSayIt(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))

	parsed := parseCertificate(chain.leaf)
	// Platform shape: the leaf is blamed, and the presented chain is supplied.
	applyValidityWindowVerdict(chain.leaf, chain.leaf,
		[]*x509.Certificate{chain.inter}, now, parsed)

	if parsed.ChainTrust != types.CheckFailed {
		t.Fatalf("chainTrust=%v, want failed", parsed.ChainTrust)
	}
	if !strings.Contains(parsed.ChainTrustReason, chain.inter.Subject.CommonName) {
		t.Errorf("the reason does not name the expired intermediate, though the server "+
			"presented it on this connection: %q", parsed.ChainTrustReason)
	}
	if strings.Contains(parsed.ChainTrustReason, "openssl") {
		t.Errorf("the reason sends the operator to another tool for data this scan "+
			"already holds: %q", parsed.ChainTrustReason)
	}
}

// TestNothingPresentedIsExpiredSaysSoRatherThanNamingTheLeaf covers the residual
// case: the platform verifier can reject on a certificate from its own store
// that the server never sent. Naming one would be a guess.
func TestNothingPresentedIsExpiredSaysSoRatherThanNamingTheLeaf(t *testing.T) {
	now := time.Now()
	// Every presented certificate is current.
	chain := buildThreeLevelChain(t, now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0))

	parsed := parseCertificate(chain.leaf)
	applyValidityWindowVerdict(chain.leaf, chain.leaf,
		[]*x509.Certificate{chain.inter}, now, parsed)

	if parsed.ChainTrust != types.CheckFailed {
		t.Fatalf("chainTrust=%v, want failed", parsed.ChainTrust)
	}
	if strings.Contains(parsed.ChainTrustReason, chain.leaf.Subject.CommonName) ||
		strings.Contains(parsed.ChainTrustReason, chain.inter.Subject.CommonName) {
		t.Errorf("a certificate was named although none presented is outside its "+
			"window: %q", parsed.ChainTrustReason)
	}
	// x509 reports the same reason for both ends of the window, and this is the
	// branch where nobody said which end, so the text must not claim "expired".
	if strings.Contains(parsed.ChainTrustReason, "expired") {
		t.Errorf("the reason asserts expiry in the one branch where the end of the "+
			"window is unknown: %q", parsed.ChainTrustReason)
	}
}

// TestAChainCertificateWithoutACommonNameIsStillIdentified covers chainCertName,
// which had no test at all: replacing its whole body with the pre-fix
// cert.Subject.CommonName left the suite green.
func TestAChainCertificateWithoutACommonNameIsStillIdentified(t *testing.T) {
	now := time.Now()
	noCN, _, err := signedCert(&x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			Organization:       []string{"Legacy Root Org"},
			OrganizationalUnit: []string{"Certification Authority"},
		},
		NotBefore:             now.AddDate(-2, 0, 0),
		NotAfter:              now.AddDate(0, -1, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("build certificate: %v", err)
	}
	if noCN.Subject.CommonName != "" {
		t.Fatal("fixture is wrong: this certificate must have no common name")
	}

	reason := chainCertOutsideValidityReason(noCN, now)
	if strings.Contains(reason, `""`) {
		t.Errorf("a certificate identified only by organization was named as the empty "+
			"string, which tells the operator nothing: %q", reason)
	}
	if !strings.Contains(reason, "Legacy Root Org") {
		t.Errorf("the reason does not carry any identifying detail: %q", reason)
	}
}

// TestAServerCannotPushTheVerdictOutOfTheChainReason pins the name cap.
//
// The report caps the rendered line, and the server-chosen name sits at the
// FRONT of the sentence, so without a bound of its own a long name pushes the
// tool's own words off the end. Measured before the cap: a 474-byte common name
// ending "and this certificate is valid; the chain builds to a trusted root"
// produced a line carrying that phrase and neither "expired" nor the date.
func TestAServerCannotPushTheVerdictOutOfTheChainReason(t *testing.T) {
	now := time.Now()
	padding := strings.Repeat("A", 420)
	forged := padding + " and this certificate is valid; the chain builds to a trusted root"

	cert, err := certificateWithSubject(forged, now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))
	if err != nil {
		t.Fatalf("build certificate: %v", err)
	}

	// Assert on the RENDERED form, not the raw reason. The tool's words are
	// appended after the name, so in the raw string they always survive and the
	// assertion would be vacuous. The layer the cap exists for is the report,
	// which applies its own budget on top.
	rendered := sanitize.ForReport(chainCertOutsideValidityReason(cert, now),
		sanitize.MaxReportDetail)

	for _, want := range []string{"expired on", "does not build to a trusted root"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the tool's own words %q were pushed out of the rendered line by a long "+
				"certificate name, so the server chose what the verdict says: %q",
				want, rendered)
		}
	}
	if strings.Contains(rendered, "the chain builds to a trusted root") {
		t.Errorf("the server's forged phrase survived in full: %q", rendered)
	}
}

// TestAControlHeavyNameCannotPushTheVerdictOutEither is the case the byte cap
// alone did not hold. The reason renders the name with %q, which expands one
// control byte into four printable ones, so a name capped at 120 raw bytes could
// still render as 473 and blow the report's own budget.
func TestAControlHeavyNameCannotPushTheVerdictOutEither(t *testing.T) {
	now := time.Now()
	cert, err := certificateWithSubject(strings.Repeat("\x01", 300),
		now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0))
	if err != nil {
		t.Fatalf("build certificate: %v", err)
	}

	rendered := sanitize.ForReport(chainCertOutsideValidityReason(cert, now),
		sanitize.MaxReportDetail)

	for _, want := range []string{"expired on", "does not build to a trusted root"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("a control-heavy certificate name pushed %q out of the rendered "+
				"line: %q", want, rendered)
		}
	}
}

// TestTheWalkFindsANotYetValidChainCertificateToo covers the other end of the
// window in the presented-chain walk. x509 reports the same reason for both
// ends, and a walk that only looked for expiry would pass every test above while
// missing a pre-staged intermediate.
func TestTheWalkFindsANotYetValidChainCertificateToo(t *testing.T) {
	now := time.Now()
	chain := buildThreeLevelChain(t, now.AddDate(0, 1, 0), now.AddDate(5, 0, 0))

	parsed := parseCertificateAt(chain.leaf, now)
	applyValidityWindowVerdict(chain.leaf, chain.leaf,
		[]*x509.Certificate{chain.inter}, now, parsed)

	if parsed.ChainTrust != types.CheckFailed {
		t.Fatalf("chainTrust=%v, want failed", parsed.ChainTrust)
	}
	if !strings.Contains(parsed.ChainTrustReason, chain.inter.Subject.CommonName) {
		t.Errorf("the walk did not find the not-yet-valid intermediate the server "+
			"presented: %q", parsed.ChainTrustReason)
	}
	if !strings.Contains(parsed.ChainTrustReason, "not valid until") {
		t.Errorf("the reason does not say which end of the window failed: %q",
			parsed.ChainTrustReason)
	}
}
