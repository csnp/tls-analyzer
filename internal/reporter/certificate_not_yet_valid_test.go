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

// TestCBOMDescribesTheValidityWindowHonestly covers the one human-readable
// string in the certificate component. It read "Expires in N days" whatever the
// window was, so a certificate dated to start next year described itself as a
// healthy long-lived one. The structured notValidBefore was always present, but
// the prose has to agree with it.
func TestCBOMDescribesTheValidityWindowHonestly(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*types.Certificate)
		wantContain string
		wantAbsent  string
	}{
		{
			name:        "not yet valid",
			mutate:      func(c *types.Certificate) {},
			wantContain: "Not yet valid",
			wantAbsent:  "Expires in",
		},
		{
			name: "expired",
			mutate: func(c *types.Certificate) {
				c.NotYetValid = false
				c.Expired = true
				c.NotBefore = time.Now().Add(-365 * 24 * time.Hour)
				c.NotAfter = time.Now().Add(-24 * time.Hour)
			},
			wantContain: "Expired on",
			wantAbsent:  "Expires in",
		},
		{
			name: "never valid, inverted window",
			mutate: func(c *types.Certificate) {
				// notAfter before notBefore: both flags set. Whichever branch is
				// tested first would otherwise describe it, and the text report
				// and the grade test Expired first, so the CBOM must not
				// disagree with them about the same certificate.
				c.Expired = true
				c.NotBefore = time.Now().Add(365 * 24 * time.Hour)
				c.NotAfter = time.Now().Add(-24 * time.Hour)
			},
			wantContain: "Never valid",
			wantAbsent:  "Expires in",
		},
		{
			name: "healthy",
			mutate: func(c *types.Certificate) {
				c.NotYetValid = false
				c.NotBefore = time.Now().Add(-24 * time.Hour)
				c.NotAfter = time.Now().Add(90 * 24 * time.Hour)
				c.DaysUntilExpiry = 90
			},
			wantContain: "Expires in 90 days",
			wantAbsent:  "Not yet valid",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cert := notYetValidCertificate()
			tt.mutate(cert)

			var out strings.Builder
			r := &CBOMReporter{}
			if err := r.Report(&out, certResult(cert)); err != nil {
				t.Fatalf("report: %v", err)
			}
			doc := out.String()

			if !strings.Contains(doc, tt.wantContain) {
				t.Errorf("the CBOM never says %q for a %s certificate", tt.wantContain, tt.name)
			}
			if strings.Contains(doc, tt.wantAbsent) {
				t.Errorf("the CBOM describes a %s certificate with %q", tt.name, tt.wantAbsent)
			}
		})
	}
}
