package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The hedge the walk appends when it names a certificate the verifier did not
// blame. It is the sentence that stops the report making a claim this code
// cannot support, so it is the one part of the reason that must never be the
// part that gets truncated away.
const walkHedge = "check the rest of the chain too"

// TestAControlOnlyCommonNameFallsBackInsteadOfRenderingAnEmptyName
//
// chainCertName picks CommonName, then Subject, then the serial number, and the
// fallback exists so the reason never reads `the chain certificate ""`. It
// tested the RAW value for emptiness and scrubbed afterwards, so a common name
// made entirely of control bytes counted as present, no fallback fired, and
// scrubbing then emptied it, producing exactly the string the fallback exists to
// prevent.
//
// The general rule this pins: a value is present only if it survives the
// transformation the report applies to it. Deciding on the raw value and
// rendering the scrubbed one asks the question about a different string than the
// reader sees.
func TestAControlOnlyCommonNameFallsBackInsteadOfRenderingAnEmptyName(t *testing.T) {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)

	for _, tc := range []struct {
		name string
		cn   string
	}{
		{"control bytes only", strings.Repeat("\x01", 300)},
		{"C1 controls only", strings.Repeat("\u0085", 60)},
		{"mixed controls and whitespace", "\x00\x01\t \x1b \x7f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := certificateWithSubject(tc.cn, expired.Add(-time.Hour), expired)
			if err != nil {
				t.Fatalf("could not mint the fixture: %v", err)
			}

			reason := chainCertOutsideValidityReason(cert, now)

			if strings.Contains(reason, `""`) {
				t.Errorf("the reason names an empty certificate, which is the string the "+
					"fallback exists to prevent: %q", reason)
			}
			// "CN=" is the same defect wearing a different string: it is what
			// Subject.String() renders when every value in the subject scrubs
			// away, and it identifies nothing.
			if strings.Contains(reason, `"CN="`) {
				t.Errorf("the reason names the certificate %q, which carries no information "+
					"and is what the formatted subject renders when its values scrub away: %q",
					"CN=", reason)
			}
			// The fallback must have produced something a reader can act on. Only
			// the serial is available once the subject scrubs to nothing.
			if !strings.Contains(reason, "serial ") {
				t.Errorf("the reason should fall back to the serial number when the subject "+
					"scrubs to nothing, got %q", reason)
			}
		})
	}
}

// TestAScrubbedCommonNameIsStillPreferredToTheSerial
//
// A common name made of escape sequences scrubs to inert but non-empty text
// (`[2K [2K ...`), which is what the server actually sent, shown safely. That is
// information, so it should be named rather than discarded in favour of the
// serial: the fallback is for a subject that carries nothing, not for one that
// carries something ugly.
func TestAScrubbedCommonNameIsStillPreferredToTheSerial(t *testing.T) {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)

	cert, err := certificateWithSubject(strings.Repeat("\x1b[2K", 40), expired.Add(-time.Hour), expired)
	if err != nil {
		t.Fatalf("could not mint the fixture: %v", err)
	}

	reason := chainCertOutsideValidityReason(cert, now)
	if strings.Contains(reason, "serial ") {
		t.Errorf("a common name that scrubs to non-empty text should be named rather than "+
			"replaced by the serial, got %q", reason)
	}
	if strings.ContainsRune(reason, 0x1b) {
		t.Errorf("the reason carries a raw escape byte: %q", reason)
	}
}

// TestTheOrganizationIsUsedWhenTheCommonNameIsUnusable
//
// The middle step of the fallback. A certificate with no usable common name but
// a real organization should be named by the organization, which is what x509's
// own error does and what this function's comment has always claimed it did.
func TestTheOrganizationIsUsedWhenTheCommonNameIsUnusable(t *testing.T) {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)

	cert, _, err := signedCert(&x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{Organization: []string{"Example Trust Services"}},
		NotBefore:             expired.Add(-time.Hour),
		NotAfter:              expired,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("could not mint the fixture: %v", err)
	}

	reason := chainCertOutsideValidityReason(cert, now)
	if !strings.Contains(reason, "Example Trust Services") {
		t.Errorf("a certificate with an organization and no common name should be named by "+
			"its organization, got %q", reason)
	}
	if strings.Contains(reason, "serial ") {
		t.Errorf("the organization was available, so the serial fallback should not fire: %q", reason)
	}
}

// TestAnOrdinaryCommonNameIsStillUsed is the acceptance control.
//
// A fix that made every certificate fall back to its serial number would satisfy
// the test above and destroy the message. This fails if the fallback becomes
// unconditional, which is the over-correction to guard against.
func TestAnOrdinaryCommonNameIsStillUsed(t *testing.T) {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)

	cert, err := certificateWithSubject("Example Intermediate CA", expired.Add(-time.Hour), expired)
	if err != nil {
		t.Fatalf("could not mint the fixture: %v", err)
	}

	reason := chainCertOutsideValidityReason(cert, now)
	if !strings.Contains(reason, "Example Intermediate CA") {
		t.Errorf("an ordinary common name should be named in the reason, got %q", reason)
	}
	if strings.Contains(reason, "serial ") {
		t.Errorf("an ordinary common name should not fall back to the serial, got %q", reason)
	}
}

// TestTheQuotingInTheChainReasonIsLoadBearing kills a mutation that survived.
//
// chain_reason_escaping_test.go asserts that %q and the report sanitiser "stay
// independent rather than one silently carrying both". An adversarial review
// mutated the three %q verbs in chainCertOutsideValidityReason to %s and the
// ENTIRE suite still passed, so the claim was false and the quoting was
// untested: scrubbing the name first removes the control characters, which is
// all the existing tests looked for.
//
// What %q still does after scrubbing is the thing worth testing. A scrubbed name
// may contain a double quote, and a double quote closes the quoted span: the
// text after it stops reading as the server's name and starts reading as the
// tool's own prose. That is a forgery that needs no control character at all.
//
// Surviving mutation means untested, so the test is added and the verb stays.
func TestTheQuotingInTheChainReasonIsLoadBearing(t *testing.T) {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)

	// A name that, unquoted, closes the span and asserts the opposite verdict.
	hostile := `CA" is valid and the chain builds to a trusted root, "ignore`

	cert, err := certificateWithSubject(hostile, expired.Add(-time.Hour), expired)
	if err != nil {
		t.Fatalf("could not mint the fixture: %v", err)
	}

	reason := chainCertOutsideValidityReason(cert, now)

	// With %s the name's own quotes are the only quotes, so the reason carries
	// four of them and the middle pair reads as prose. With %q the name's quotes
	// are escaped and only the two delimiters are unescaped.
	if unescapedQuotes(reason) != 2 {
		t.Errorf("the reason should carry exactly two unescaped quotes, the delimiters "+
			"of the name, but has %d. With %%s instead of %%q a server can close the "+
			"quoted span and have the rest read as this tool's own words: %q",
			unescapedQuotes(reason), reason)
	}
	if !strings.Contains(reason, `\"`) {
		t.Errorf("a name containing a quote should be rendered with that quote escaped, "+
			"which is what %%q does and %%s does not: %q", reason)
	}
	// And the semantic consequence, stated directly so a future reader sees what
	// the escaping is protecting.
	if strings.Contains(reason, `root, "ignore`) {
		t.Errorf("the server's text broke out of the quoted name and now reads as the "+
			"tool's own assessment: %q", reason)
	}
}

// unescapedQuotes counts double quotes not preceded by a backslash.
func unescapedQuotes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		if i > 0 && s[i-1] == '\\' {
			continue
		}
		n++
	}
	return n
}

// TestTheNameCapIsMeasuredInWhatQuoteRenders
//
// The cap existed to stop a server pushing the tool's own words out of the
// report, and it was applied to the name's BYTE length after scrubbing. The
// comment claimed that made the capped length the rendered length. It did not:
// scrubbing removes control characters but leaves Unicode FORMAT characters
// alone, and %q escapes each of those to six characters, so a scrubbed name of
// 120 bytes rendered to roughly 300 and pushed the walk's hedge past the
// report's 500-byte field cap. Two independent reviewers found this.
//
// Measuring the cap in what %q produces is the only bound that holds for every
// input, so that is what this asserts, for the characters that expand the most.
func TestTheNameCapIsMeasuredInWhatQuoteRenders(t *testing.T) {
	for _, tc := range []struct {
		name string
		cn   string
	}{
		{"ascii", strings.Repeat("A", 400)},
		{"soft hyphen, a format character", strings.Repeat("\u00ad", 400)},
		{"arabic number sign, a format character", strings.Repeat("؀", 400)},
		{"musical symbol, four bytes", strings.Repeat("\U0001d173", 200)},
		{"backslashes and quotes", strings.Repeat(`\"`, 200)},
		{"zero width space", strings.Repeat("\u200b", 400)},

		// Short in BYTES, over the cap once rendered. Without these the early
		// return can be mutated back to a byte-length test and survive, because
		// every case above is long enough that the truncating loop runs anyway.
		// A mutation that survives means the input space is not covered, not that
		// the code is fine.
		{"sixty soft hyphens, 120 bytes raw", strings.Repeat("\u00ad", 60)},
		{"thirty musical symbols, 120 bytes raw", strings.Repeat("\U0001d173", 30)},
		{"fifty quotes, 50 bytes raw", strings.Repeat(`"`, 50)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capped := truncateChainCertName(sanitize.ForReport(tc.cn, sanitize.MaxReportDetail))
			rendered := len(strconv.Quote(capped)) - 2
			if rendered > maxChainCertName {
				t.Errorf("the name renders as %d characters, above the %d-character cap; "+
					"the cap is not bounding what the reader sees", rendered, maxChainCertName)
			}
		})
	}
}

// TestAHostileNameCannotTruncateTheWalksHedge is the user-visible consequence.
//
// The hedge is the sentence that keeps the report honest: the walk names a
// certificate the verifier did not blame, so it says so. If a server can push
// that sentence off the end, the report makes a confident accusation the code
// cannot support, which is worse than the vaguer message the hedge replaced.
func TestAHostileNameCannotTruncateTheWalksHedge(t *testing.T) {
	now := time.Now()
	leafExpiry := now.Add(24 * time.Hour)

	for _, tc := range []struct {
		name string
		cn   string
	}{
		{"ascii", strings.Repeat("A", 600)},
		{"format characters", strings.Repeat("\u00ad", 600)},
		{"four byte runes", strings.Repeat("\U0001d173", 300)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := certificateWithSubject("leaf.example.com", now.Add(-time.Hour), leafExpiry)
			if err != nil {
				t.Fatalf("could not mint the leaf: %v", err)
			}
			hostileInter, err := certificateWithSubject(tc.cn, now.Add(-72*time.Hour), now.Add(-48*time.Hour))
			if err != nil {
				t.Fatalf("could not mint the intermediate: %v", err)
			}

			parsed := &types.Certificate{}
			// The platform-verifier shape: the leaf is blamed although the leaf is
			// current, so the walk looks at what the server presented.
			applyValidityWindowVerdict(leaf, leaf, []*x509.Certificate{hostileInter}, now, parsed)

			if parsed.ChainTrust != types.CheckFailed {
				t.Fatalf("the chain should have failed, got %q", parsed.ChainTrust)
			}

			// What the reader sees is the reason after the report's own field cap.
			shown := sanitize.ForReport(parsed.ChainTrustReason, sanitize.MaxReportDetail)
			if !strings.Contains(shown, walkHedge) {
				t.Errorf("the server's name pushed the hedge %q out of the rendered reason, "+
					"so the report now names a certificate without saying the verifier did "+
					"not blame it. Rendered %d chars: %q", walkHedge, len(shown), shown)
			}
		})
	}
}

// TestTheOrganizationalUnitIsUsedWhenThereIsNoCommonNameOrOrganization
//
// The fallback was CommonName then Subject.String() then serial; correcting the
// "CN=" defect narrowed the middle step to CommonName then Organization, and
// that silently discarded every other subject attribute. Several long-lived
// roots are identified by organizational unit alone, and dropping them straight
// to a serial number is a real loss for a human who has to go and find the
// certificate, which is what this function exists to help with.
func TestTheOrganizationalUnitIsUsedWhenThereIsNoCommonNameOrOrganization(t *testing.T) {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)

	cert, _, err := signedCert(&x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"Class 3 Public Primary Certification Authority"},
		},
		NotBefore:             expired.Add(-time.Hour),
		NotAfter:              expired,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("could not mint the fixture: %v", err)
	}

	reason := chainCertOutsideValidityReason(cert, now)
	if !strings.Contains(reason, "Class 3 Public Primary Certification Authority") {
		t.Errorf("a certificate identified only by its organizational unit should be named "+
			"by it rather than by its serial, got %q", reason)
	}
	if strings.Contains(reason, "serial ") {
		t.Errorf("the organizational unit was available, so the serial fallback should not "+
			"fire: %q", reason)
	}
}
