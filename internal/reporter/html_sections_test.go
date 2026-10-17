package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The graded HTML page rendered a score breakdown, protocol support, the quantum
// assessment, findings and recommendations, and nothing else. The CNSA 2.0
// timeline, the certificate, the cipher list and the scan-coverage notes were in
// the text report and in JSON and absent from the page, so a report of a host
// whose certificate failed the name check said nothing about the certificate.

func fullResult() *types.ScanResult {
	result := scannedResult()
	result.Certificate = healthyCert()
	result.CipherSuites = []types.CipherSuite{
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Protocol: "TLS 1.3", Bits: 128,
			ForwardSecrecy: true, Negotiated: true},
		{ID: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Protocol: "TLS 1.2", Bits: 112,
			Deprecated: true, DeprecatedReason: "3DES is vulnerable to SWEET32"},
	}
	result.KeyExchanges = []types.KeyExchange{
		{Name: "X25519", Type: "classical", Curve: "X25519", Bits: 253, Negotiated: true},
		{Name: "X25519MLKEM768", Type: "hybrid", QuantumSafe: true,
			PQCAlgorithm: "ML-KEM-768", HybridClassical: "X25519"},
	}
	result.CNSA2Timeline = &types.CNSA2Timeline{
		Scope:              "Milestone statuses describe what this scan observed against each CNSA 2.0 deadline.",
		CurrentPhase:       "Transition",
		TimelineScore:      40,
		DaysToNextDeadline: 77,
		NextAction:         "Prefer ML-KEM-1024 for key establishment",
		Milestones: []types.CNSA2Milestone{
			{Name: "Web browsers and servers support CNSA 2.0", Status: "non-compliant",
				Deadline: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				Gap:      []string{"No ML-KEM key exchange offered"}},
			{Name: "Exclusive use of CNSA 2.0 for web", Status: "not-applicable",
				Deadline: time.Date(2033, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
		Findings: []types.CNSA2Finding{
			{Category: "key-exchange", Algorithm: "X25519", Status: "deprecated",
				Replacement: "ML-KEM-1024"},
		},
	}
	result.ScanWarnings = []string{
		"cipher suite enumeration is limited to the suites this scanner's TLS stack can offer",
	}
	return result
}

// TestHTMLRendersWhatTheTextReportCarries asks for each section by its own id,
// so a value that appears elsewhere on the page cannot satisfy it.
func TestHTMLRendersWhatTheTextReportCarries(t *testing.T) {
	page := render(t, &HTMLReporter{IncludeCSS: true}, fullResult())

	checks := map[string][]string{
		"cnsa2-timeline": {
			"CNSA 2.0",
			"Transition",
			"40/100",
			"77",
			"Prefer ML-KEM-1024 for key establishment",
			"Milestone statuses describe what this scan observed",
			"Web browsers and servers support CNSA 2.0",
			"2025-01-01",
			"No ML-KEM key exchange offered",
			"not yet required", // the legend
			"key-exchange",
			"deprecated",
			"ML-KEM-1024",
		},
		"certificate": {
			"CN=example.com",
			"CN=Example CA",
			"ECDSA",
			"256-bit",
			"ECDSA-SHA256",
			"example.com",
			"Name check",
			"valid for example.com",
			"Chain trust",
			"chains to a root this host trusts",
			"Valid",
		},
		"cipher-suites": {
			"TLS_AES_128_GCM_SHA256",
			"negotiated by this scan",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"3DES is vulnerable to SWEET32",
			"X25519MLKEM768",
			"ML-KEM-768",
			"hybrid",
		},
		"scan-coverage": {
			"Scan coverage",
			"cipher suite enumeration is limited",
		},
	}
	for id, wants := range checks {
		section := htmlSection(t, page, id)
		for _, want := range wants {
			if !strings.Contains(section, want) {
				t.Errorf("section %q does not carry %q:\n%s", id, want, section)
			}
		}
	}

	t.Run("control: sections with nothing to show are omitted", func(t *testing.T) {
		page := render(t, &HTMLReporter{}, scannedResult())
		for _, id := range []string{"policy", "cnsa2-timeline", "certificate", "scan-coverage"} {
			if strings.Contains(page, `id="`+id+`"`) {
				t.Errorf("section %q is rendered for a result that carries nothing for it", id)
			}
		}
	})
}

// TestHTMLDoesNotDrawAStatusItDoesNotKnowAsMet guards the default arm. The text
// renderer used to start every milestone at a green check and only change it
// for the statuses it listed, so a status added later printed as met. The page
// must not do that: an unknown word is shown as the word.
func TestHTMLDoesNotDrawAStatusItDoesNotKnowAsMet(t *testing.T) {
	result := fullResult()
	result.CNSA2Timeline.Milestones = []types.CNSA2Milestone{{
		Name:     "A milestone with a status this page has never seen",
		Status:   "not-determined",
		Deadline: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}}
	result.CNSA2Timeline.Findings = []types.CNSA2Finding{{
		Category: "signature", Algorithm: "ECDSA-P256", Status: "under-review",
	}}

	section := htmlSection(t, render(t, &HTMLReporter{}, result), "cnsa2-timeline")

	milestone := htmlItemContaining(t, section, "A milestone with a status")
	if !strings.Contains(milestone, "not-determined") {
		t.Errorf("the unknown status is not shown as its own word: %s", milestone)
	}
	if strings.Contains(milestone, "✓") || strings.Contains(milestone, "status-good") {
		t.Errorf("an unknown milestone status is drawn as met: %s", milestone)
	}

	finding := htmlItemContaining(t, section, "ECDSA-P256")
	if !strings.Contains(finding, "under-review") {
		t.Errorf("the unknown finding status is not shown as its own word: %s", finding)
	}
	if strings.Contains(finding, "✓") || strings.Contains(finding, "status-good") {
		t.Errorf("an unknown finding status is styled as approved: %s", finding)
	}
}

// htmlItemContaining returns the <li> element of section that carries needle.
func htmlItemContaining(t *testing.T, section, needle string) string {
	t.Helper()
	i := strings.Index(section, needle)
	if i < 0 {
		t.Fatalf("%q is not rendered:\n%s", needle, section)
	}
	start := strings.LastIndex(section[:i], "<li")
	end := strings.Index(section[i:], "</li>")
	if start < 0 || end < 0 {
		t.Fatalf("%q is not inside a list item:\n%s", needle, section)
	}
	return section[start : i+end]
}

// TestHTMLCertificateChecksThatDidNotRunSaySo pins the third answer. A check
// whose result is absent from the report is a check the reader assumes passed.
func TestHTMLCertificateChecksThatDidNotRunSaySo(t *testing.T) {
	result := fullResult()
	result.Certificate.NameMatch = types.CheckNotPerformed
	result.Certificate.ChainTrust = types.CheckFailed
	result.Certificate.ChainTrustReason = "x509: certificate signed by unknown authority"

	section := htmlSection(t, render(t, &HTMLReporter{}, result), "certificate")

	if !strings.Contains(section, "not checked against any name") {
		t.Errorf("a name check that did not run is not reported as such:\n%s", section)
	}
	if !strings.Contains(section, "x509: certificate signed by unknown authority") {
		t.Errorf("the chain failure reason is missing:\n%s", section)
	}
	if !strings.Contains(section, "NOT TRUSTED") {
		t.Errorf("a certificate whose chain failed is not headed NOT TRUSTED:\n%s", section)
	}
	if strings.Contains(section, "valid for example.com") {
		t.Errorf("a name check that did not run reads as passed:\n%s", section)
	}
}

// TestTheGradedPageScrubsTheResultAtTheDoor closes the gap html.go recorded
// for this page and adds the fields that make it reachable.
//
// html/template escapes markup and leaves control characters alone, so a saved
// report could carry a raw cursor sequence that steers a terminal when somebody
// cats, greps or pages it. Nothing reached that gap only because the page drew
// no subject, issuer or SAN. Those are the server's own choice of text, and this
// page now draws them.
func TestTheGradedPageScrubsTheResultAtTheDoor(t *testing.T) {
	esc := string(rune(0x1b))
	lt := "<"
	img := lt + "img src=x onerror=alert(1)>"
	script := lt + "script>alert(2)" + lt + "/script>"

	result := fullResult()
	result.Certificate.Subject = "CN=" + esc + "[2JSUBJECT" + img + script
	result.Certificate.Issuer = "CN=" + esc + "[2JISSUER" + img + script
	result.Certificate.SANs = []string{"san" + esc + "[2JSAN" + img + script}
	result.PolicyResult = hybridVerdict()
	result.PolicyResult.PolicyName = "pol" + esc + "[1APOLICY" + script

	page := render(t, &HTMLReporter{IncludeCSS: true}, result)

	assertNoCursorControl(t, "html/graded", page)
	for _, tag := range []string{lt + "img", lt + "script"} {
		if strings.Contains(page, tag) {
			t.Errorf("the page carries a live %s tag from certificate text", tag)
		}
	}

	// Non-vacuous: the scrubbed text has to be on the page, or a page that drew
	// no certificate would satisfy every assertion above.
	cert := htmlSection(t, page, "certificate")
	for _, want := range []string{"[2JSUBJECT", "[2JISSUER", "[2JSAN", "&lt;img src=x onerror=alert(1)&gt;"} {
		if !strings.Contains(cert, want) {
			t.Errorf("the scrubbed certificate text %q is not visible:\n%s", want, cert)
		}
	}
	if !strings.Contains(htmlSection(t, page, "policy"), "[1APOLICY") {
		t.Error("the scrubbed policy name is not visible")
	}
}
