package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Fixing the not-yet-valid certificate in the grade and the vulnerability list
// left three other readers of the same predicate untouched, found by sweeping
// every consumer of cert.Expired rather than the symptom that was reported:
// the policy evaluator, the recommendations, and this status line.
//
// The comment above the status switch already says "A certificate a client would
// refuse must not be headed Valid". A certificate whose validity has not started
// is refused by every client, and it was headed "✓ Valid".

func notYetValidCertificate() *types.Certificate {
	start := time.Now().Add(365 * 24 * time.Hour)
	return &types.Certificate{
		Subject:            "CN=future.example",
		Issuer:             "CN=Test CA",
		NotBefore:          start,
		NotAfter:           start.Add(90 * 24 * time.Hour),
		SignatureAlgorithm: "ECDSA-SHA256",
		PublicKeyAlgorithm: "ECDSA",
		PublicKeyBits:      256,
		DaysUntilExpiry:    455,
		NotYetValid:        true,
		NameMatch:          types.CheckPassed,
		ChainTrust:         types.CheckNotPerformed,
		RequestedName:      "example.com",
	}
}

func TestTextReporterDoesNotHeadANotYetValidCertificateAsValid(t *testing.T) {
	var out strings.Builder
	r := &TextReporter{NoColor: true}
	if err := r.Report(&out, certResult(notYetValidCertificate())); err != nil {
		t.Fatalf("report: %v", err)
	}
	text := out.String()

	line := ""
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "Status:") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("no certificate Status line in the report")
	}

	if strings.Contains(line, "Valid") && !strings.Contains(line, "NOT YET VALID") {
		t.Errorf("the certificate status reads %q for a certificate whose validity period "+
			"has not started. Every client refuses it, exactly as it refuses an expired "+
			"one, and the report must not head it as valid.", strings.TrimSpace(line))
	}
	if !strings.Contains(text, "NOT YET VALID") {
		t.Errorf("the report never says the certificate is not yet valid; status line was %q",
			strings.TrimSpace(line))
	}
}

// TestTextReporterStillHeadsAHealthyCertificateAsValid is the acceptance
// control: the new branch must not swallow the ordinary case.
func TestTextReporterStillHeadsAHealthyCertificateAsValid(t *testing.T) {
	cert := notYetValidCertificate()
	cert.NotYetValid = false
	cert.NotBefore = time.Now().Add(-24 * time.Hour)
	cert.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	cert.DaysUntilExpiry = 90
	cert.ChainTrust = types.CheckPassed

	var out strings.Builder
	r := &TextReporter{NoColor: true}
	if err := r.Report(&out, certResult(cert)); err != nil {
		t.Fatalf("report: %v", err)
	}
	if strings.Contains(out.String(), "NOT YET VALID") {
		t.Error("a healthy certificate was reported as not yet valid")
	}
	if !strings.Contains(out.String(), "Valid") {
		t.Error("a healthy certificate is no longer headed as valid; the fix has over-reached")
	}
}
