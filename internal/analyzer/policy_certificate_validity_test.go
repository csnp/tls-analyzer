package analyzer

import (
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Fixing the not-yet-valid certificate in the grade and the vulnerability list
// left the POLICY evaluator reading only cert.Expired, which is the surface that
// decides a compliance verdict and an exit code.
//
// It failed silently in the worst way: the validity check is an if/else chain,
// so a not-yet-valid certificate fell through to the minValidityDays branch,
// where DaysUntilExpiry is measured to a notAfter that is more than a year away
// and clears any threshold an author would write. No violation, no warning,
// COMPLIANT, exit 0.
//
// Found by sweeping every non-test reader of cert.Expired rather than the one
// consumer the report named.

func policyScanWithCertificate(cert *types.Certificate) *types.ScanResult {
	scan := scanForRuleValues()
	scan.Certificate = cert
	return scan
}

func notYetValidCert() *types.Certificate {
	start := time.Now().Add(365 * 24 * time.Hour)
	return &types.Certificate{
		Subject:            "CN=future.example",
		NotBefore:          start,
		NotAfter:           start.Add(90 * 24 * time.Hour),
		SignatureAlgorithm: "ECDSA-SHA256",
		PublicKeyAlgorithm: "ECDSA",
		PublicKeyBits:      256,
		DaysUntilExpiry:    455,
		NotYetValid:        true,
		NameMatch:          types.CheckPassed,
		ChainTrust:         types.CheckNotPerformed,
	}
}

func validityViolation(pr *types.PolicyResult) *types.PolicyViolation {
	for i, v := range pr.Violations {
		if v.Rule == "certificate.validity" {
			return &pr.Violations[i]
		}
	}
	return nil
}

func TestPolicyRaisesAViolationForANotYetValidCertificate(t *testing.T) {
	// A policy an operator would plausibly write: the certificate must have at
	// least 30 days left. A not-yet-valid certificate has 455, so the threshold
	// is cleared and only an explicit validity check can catch it.
	policy := &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{
			Certificate: types.CertificateRules{MinValidityDays: 30},
		},
	}

	pr := NewPolicyEvaluator().Evaluate(policyScanWithCertificate(notYetValidCert()), policy)

	v := validityViolation(pr)
	if v == nil {
		t.Fatalf("no certificate.validity violation for a certificate whose validity period "+
			"has not started. compliant=%v complete=%v violations=%d warnings=%d",
			pr.Compliant, pr.Complete, len(pr.Violations), len(pr.Warnings))
	}
	if v.Severity != types.SeverityCritical {
		t.Errorf("certificate.validity severity = %q, want %q", v.Severity, types.SeverityCritical)
	}
	if v.Remediation == "" {
		t.Error("the violation carries no remediation, so the finding is a dead end")
	}
	if pr.Compliant {
		t.Error("the verdict is COMPLIANT for a certificate every client refuses")
	}
}

// TestPolicyStillRaisesAViolationForAnExpiredCertificate guards the other end of
// the window, so widening the check cannot drop the case it already handled.
func TestPolicyStillRaisesAViolationForAnExpiredCertificate(t *testing.T) {
	cert := notYetValidCert()
	cert.NotYetValid = false
	cert.Expired = true
	cert.NotBefore = time.Now().Add(-365 * 24 * time.Hour)
	cert.NotAfter = time.Now().Add(-24 * time.Hour)
	cert.DaysUntilExpiry = -1

	pr := NewPolicyEvaluator().Evaluate(policyScanWithCertificate(cert), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Certificate: types.CertificateRules{MinValidityDays: 30}},
	})

	v := validityViolation(pr)
	if v == nil {
		t.Fatal("no certificate.validity violation for an expired certificate")
	}
	if v.Description != "Certificate has expired" {
		t.Errorf("expired certificate reported as %q; the two ends of the window must "+
			"not be described as one another", v.Description)
	}
}

// TestPolicyAcceptsACurrentCertificate is the acceptance control.
func TestPolicyAcceptsACurrentCertificate(t *testing.T) {
	cert := notYetValidCert()
	cert.NotYetValid = false
	cert.NotBefore = time.Now().Add(-24 * time.Hour)
	cert.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	cert.DaysUntilExpiry = 90
	cert.ChainTrust = types.CheckPassed

	pr := NewPolicyEvaluator().Evaluate(policyScanWithCertificate(cert), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Certificate: types.CertificateRules{MinValidityDays: 30}},
	})

	if v := validityViolation(pr); v != nil {
		t.Errorf("a certificate with 90 days left raised %q; the fix has over-reached",
			v.Description)
	}
}
