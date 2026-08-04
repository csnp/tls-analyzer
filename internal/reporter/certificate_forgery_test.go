package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// A scanned server chooses its own certificate subject, and the report prints
// it. macOS formats verifier errors as `x509: "<subject>" certificate is not
// trusted`, so the subject reaches the chain-trust reason as well as the
// Subject line.
//
// Measured before this fix, against a local server whose leaf carried an ANSI
// sequence in its common name, with --no-color set:
//
//	Chain trust: ✗ x509: “Innocent CA^[[2K^M^[[32m  Chain trust: OK   Status: VALID^[[0m” ...
//
// On a real terminal ESC[2K and CR clear and rewind the line, so that renders as
// a green "Chain trust: OK   Status: VALID" over the real verdict. It is the
// same forgery the policy-name fix in this release closed, on the path that fix
// did not reach, and it survived --no-color because the escape is in the data
// rather than in the colouring.

// hostileText is what an attacker puts in a common name: clear the line, return
// the cursor, print a passing verdict in green.
const hostileText = "Innocent CA\x1b[2K\r\x1b[32m  Chain trust: OK   Status: VALID\x1b[0m\nfake"

func reportFor(t *testing.T, cert *types.Certificate) string {
	t.Helper()
	var buf bytes.Buffer
	r := &TextReporter{NoColor: true}
	result := &types.ScanResult{
		Target:      "example.com",
		Host:        "example.com",
		Port:        443,
		Timestamp:   time.Unix(0, 0).UTC(),
		Certificate: cert,
		Grade:       types.Grade{Letter: "F", Score: 0, QuantumGrade: types.QuantumGradeNotAssessed},
	}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}
	return buf.String()
}

// TestAServerCannotForgeTheReportThroughItsCertificate is the reproduction.
func TestAServerCannotForgeTheReportThroughItsCertificate(t *testing.T) {
	cert := &types.Certificate{
		Subject:            "CN=" + hostileText,
		Issuer:             "CN=" + hostileText,
		RequestedName:      "example.com",
		SANs:               []string{hostileText},
		NameMatch:          types.CheckFailed,
		NameMismatchReason: "x509: certificate is valid for " + hostileText,
		ChainTrust:         types.CheckFailed,
		ChainTrustReason:   `x509: "` + hostileText + `" certificate is not trusted`,
		NotBefore:          time.Unix(0, 0).UTC(),
		NotAfter:           time.Unix(0, 0).UTC(),
	}

	out := reportFor(t, cert)

	// Guard the fixture: if the hostile text never reached the report at all,
	// this test would pass while proving nothing.
	if !strings.Contains(out, "Innocent CA") {
		t.Fatalf("the certificate text never reached the report, so this test is not "+
			"measuring what it says:\n%s", out)
	}

	for _, bad := range []struct {
		name string
		ch   string
	}{
		{"ESC", "\x1b"},
		{"carriage return", "\r"},
	} {
		if strings.Contains(out, bad.ch) {
			t.Errorf("a raw %s from the certificate reached the rendered report, so a "+
				"server can overprint the verdict line", bad.name)
		}
	}

	// The forged verdict must not appear as its own line. Collapsed to spaces it
	// is inert text inside a field; on its own line it reads as the tool's own
	// output.
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "Chain trust: OK   Status: VALID" {
			t.Errorf("the certificate's text produced a line that reads as the tool's own "+
				"verdict: %q", line)
		}
	}
}

// TestAnOrdinaryCertificateStillPrintsItsFieldsInFull is the control. Scrubbing
// everything, or truncating aggressively, would satisfy the test above while
// making the report useless for the ordinary case.
func TestAnOrdinaryCertificateStillPrintsItsFieldsInFull(t *testing.T) {
	cert := &types.Certificate{
		Subject:          "CN=example.com,O=Example Ltd,C=GB",
		Issuer:           "CN=Example Intermediate CA,O=Example Trust Services",
		RequestedName:    "example.com",
		SANs:             []string{"example.com", "www.example.com"},
		NameMatch:        types.CheckPassed,
		ChainTrust:       types.CheckFailed,
		ChainTrustReason: `the chain certificate "Example Intermediate CA" expired on 2026-07-04`,
		NotBefore:        time.Unix(0, 0).UTC(),
		NotAfter:         time.Unix(0, 0).UTC(),
	}

	out := reportFor(t, cert)

	for _, want := range []string{
		"CN=example.com,O=Example Ltd,C=GB",
		"CN=Example Intermediate CA,O=Example Trust Services",
		"www.example.com",
		`the chain certificate "Example Intermediate CA" expired on 2026-07-04`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("an ordinary certificate lost %q from the report", want)
		}
	}
}

// TestThePassedNameIsSanitisedToo covers the branch the forgery test could not
// reach. certCheckLine renders its "passed" argument only when the check
// PASSED, and that fixture sets NameMatch to failed, so the sanitise call on
// RequestedName was never exercised: mutating it away survived the whole suite.
//
// RequestedName comes from --sni or the target argument rather than from the
// server, but a name reaching the report should not depend on who typed it.
func TestThePassedNameIsSanitisedToo(t *testing.T) {
	cert := &types.Certificate{
		Subject:       "CN=example.com",
		Issuer:        "CN=Example CA",
		RequestedName: "example.com\x1b[2K\r\x1b[32m  Chain trust: OK\x1b[0m",
		NameMatch:     types.CheckPassed,
		ChainTrust:    types.CheckPassed,
		NotBefore:     time.Unix(0, 0).UTC(),
		NotAfter:      time.Unix(0, 0).UTC(),
	}

	out := reportFor(t, cert)

	if !strings.Contains(out, "example.com") {
		t.Fatalf("the requested name never reached the report, so this test is not "+
			"measuring what it says:\n%s", out)
	}
	if strings.ContainsAny(out, "\x1b\r") {
		t.Error("a raw control character from the requested name reached the rendered report")
	}
}

// TestSANsAreQuotedSoOneNameCannotReadAsTwo covers the per-item quoting, which
// shipped with no test: removing it survived the whole suite.
//
// Sanitising collapses control characters to spaces, so an unquoted comma join
// let a name containing a NUL read as two names, and a name that was entirely
// control characters became an empty entry between two commas.
func TestSANsAreQuotedSoOneNameCannotReadAsTwo(t *testing.T) {
	cert := &types.Certificate{
		Subject:       "CN=example.com",
		Issuer:        "CN=Example CA",
		RequestedName: "example.com",
		SANs: []string{
			"real.example.com",
			"evil.example\x00also.example.com",
			"a,b.example.com",
		},
		NameMatch:  types.CheckPassed,
		ChainTrust: types.CheckPassed,
		NotBefore:  time.Unix(0, 0).UTC(),
		NotAfter:   time.Unix(0, 0).UTC(),
	}

	out := reportFor(t, cert)

	var sansLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SANs:") {
			sansLine = line
			break
		}
	}
	if sansLine == "" {
		t.Fatal("no SANs line in the report, so this test measures nothing")
	}

	// Each name is one quoted token, so the boundaries are unambiguous however
	// the name itself renders.
	if strings.Count(sansLine, `"`) != 6 {
		t.Errorf("SANs are not individually quoted, so a name containing a separator or "+
			"a control character is indistinguishable from two names: %q", sansLine)
	}
	if !strings.Contains(sansLine, `"a,b.example.com"`) {
		t.Errorf("a name containing a comma is not bounded by its own quotes: %q", sansLine)
	}
}

// TestTheFindingsBlockCannotBeForgedEither covers the sibling of the certificate
// block. CERT_CHAIN_UNTRUSTED interpolates ChainTrustReason into its description
// and CERT_NAME_MISMATCH interpolates NameMismatchReason, which x509 builds by
// joining the certificate's DNS names raw. Both then reached the findings line
// unescaped while the certificate block above was already defended.
//
// This shipped once as a fix with no test: removing the sanitise call from the
// findings block survived the whole suite.
func TestTheFindingsBlockCannotBeForgedEither(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{NoColor: true}
	result := &types.ScanResult{
		Target:    "example.com",
		Host:      "example.com",
		Port:      443,
		Timestamp: time.Unix(0, 0).UTC(),
		Grade:     types.Grade{Letter: "F", Score: 0, QuantumGrade: types.QuantumGradeNotAssessed},
		Vulnerabilities: []types.Vulnerability{{
			ID:          "CERT_NAME_MISMATCH",
			Name:        "Certificate Name Mismatch" + hostileText,
			Severity:    types.SeverityHigh,
			Description: "The certificate served for example.com is not valid for that name (" + hostileText + ")",
			Remediation: "Install a certificate whose names include " + hostileText,
			CVE:         hostileText,
		}},
	}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Innocent CA") {
		t.Fatalf("the finding text never reached the report, so this test measures "+
			"nothing:\n%s", out)
	}
	for _, bad := range []struct {
		name string
		ch   string
	}{
		{"ESC", "\x1b"},
		{"carriage return", "\r"},
	} {
		if strings.Contains(out, bad.ch) {
			t.Errorf("a raw %s reached the findings block, so a server can overprint a "+
				"finding line with a passing verdict", bad.name)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "Chain trust: OK   Status: VALID" {
			t.Errorf("the finding text produced a line that reads as the tool's own "+
				"verdict: %q", line)
		}
	}
}

// TestAnOrdinaryFindingIsPrintedInFull is the control for the case above.
func TestAnOrdinaryFindingIsPrintedInFull(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{NoColor: true}
	result := &types.ScanResult{
		Target:    "example.com",
		Host:      "example.com",
		Port:      443,
		Timestamp: time.Unix(0, 0).UTC(),
		Grade:     types.Grade{Letter: "F", Score: 0, QuantumGrade: types.QuantumGradeNotAssessed},
		Vulnerabilities: []types.Vulnerability{{
			ID:          "CERT_CHAIN_UNTRUSTED",
			Name:        "Certificate Chain Not Trusted",
			Severity:    types.SeverityHigh,
			Description: `The presented chain does not build to a trusted root (the chain certificate "Example Intermediate CA" expired on 2026-07-04).`,
			Remediation: "Serve the full chain including every intermediate.",
		}},
	}
	if err := r.Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Certificate Chain Not Trusted",
		`the chain certificate "Example Intermediate CA" expired on 2026-07-04`,
		"Serve the full chain including every intermediate.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("an ordinary finding lost %q from the report", want)
		}
	}
}
