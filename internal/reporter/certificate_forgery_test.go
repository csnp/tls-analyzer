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
