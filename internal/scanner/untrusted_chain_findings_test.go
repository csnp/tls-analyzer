package scanner

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// A chain that no client accepts has to cost the same whatever shape the
// certificate has, because the server chooses the shape.
//
// The untrusted-chain finding used to step aside for a self-signed certificate
// and the self-signed finding used to step aside for a CA, so a self-signed CA
// leaf satisfied both exclusions and produced NO finding at all. `openssl req
// -x509` emits CA:TRUE by default, so that is the ordinary shape of a
// hand-made certificate rather than an exotic one. Measured on the production
// path before the fix: self-signed CA:TRUE cost 0 points, self-signed CA:FALSE
// cost 5, an untrusted CA-issued chain cost 15. The worst posture scored best
// and the server picked its own row.

func untrustedCert(selfSigned, isCA bool) *types.Certificate {
	return &types.Certificate{
		Subject:            "CN=host.invalid",
		Issuer:             "CN=host.invalid",
		SignatureAlgorithm: "SHA256-RSA",
		PublicKeyAlgorithm: "RSA",
		PublicKeyBits:      2048,
		DaysUntilExpiry:    365,
		NameMatch:          types.CheckPassed,
		ChainTrust:         types.CheckFailed,
		ChainTrustReason:   "x509: certificate signed by unknown authority",
		IsSelfSigned:       selfSigned,
		IsCA:               isCA,
	}
}

// trustFindings returns only the findings about whether the chain is trusted,
// so the assertions below are not disturbed by unrelated certificate checks.
func trustFindings(vulns []types.Vulnerability) []types.Vulnerability {
	var out []types.Vulnerability
	for _, v := range vulns {
		if v.ID == "CERT_CHAIN_UNTRUSTED" || v.ID == "CERT_SELF_SIGNED" {
			out = append(out, v)
		}
	}
	return out
}

func TestEveryUntrustedChainShapeProducesExactlyOneHighFinding(t *testing.T) {
	s := New(nil)

	shapes := []struct {
		name       string
		selfSigned bool
		isCA       bool
		wantID     string
	}{
		// The shape that produced nothing at all. `openssl req -x509` default.
		{"self-signed with CA:TRUE", true, true, "CERT_SELF_SIGNED"},
		{"self-signed with CA:FALSE", true, false, "CERT_SELF_SIGNED"},
		{"issued by an untrusted CA", false, false, "CERT_CHAIN_UNTRUSTED"},
		// A CA certificate served as a leaf, not self-signed: an intermediate
		// presented directly. Nothing suppresses it now.
		{"CA certificate from an untrusted issuer", false, true, "CERT_CHAIN_UNTRUSTED"},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			result := &types.ScanResult{
				Target:      "host.invalid",
				Certificate: untrustedCert(shape.selfSigned, shape.isCA),
			}

			found := trustFindings(s.checkVulnerabilities(result))

			if len(found) != 1 {
				ids := make([]string, 0, len(found))
				for _, v := range found {
					ids = append(ids, string(v.Severity)+" "+v.ID)
				}
				t.Fatalf("a chain no client accepts produced %d findings %v, want exactly 1",
					len(found), ids)
			}
			if found[0].ID != shape.wantID {
				t.Errorf("finding is %s, want %s", found[0].ID, shape.wantID)
			}
			if found[0].Severity != types.SeverityHigh {
				t.Errorf("finding is %s, want HIGH: a client that verifies refuses all of "+
					"these the same way, so a certificate must not be able to lower its own "+
					"penalty by choosing its shape", found[0].Severity)
			}
			if !strings.Contains(found[0].Description, "x509: certificate signed by unknown authority") {
				t.Errorf("the finding does not carry the verifier's own reason: %q",
					found[0].Description)
			}
		})
	}
}

// TestNoUntrustedShapeScoresBetterThanAnother is the property the finding count
// exists to protect, asserted on the number the user actually reads.
//
// Before the fix the three rows graded C 66, C 61 and D 51 for the same
// verification failure. Asserting equal grades rather than equal finding counts
// is what makes a future exclusion that reintroduces the gradient fail here,
// whatever route it takes to the score.
func TestNoUntrustedShapeScoresBetterThanAnother(t *testing.T) {
	s := New(nil)

	shapes := []struct {
		name       string
		selfSigned bool
		isCA       bool
	}{
		{"self-signed with CA:TRUE", true, true},
		{"self-signed with CA:FALSE", true, false},
		{"issued by an untrusted CA", false, false},
		{"CA certificate from an untrusted issuer", false, true},
	}

	type scored struct {
		name  string
		grade types.Grade
	}
	var results []scored

	for _, shape := range shapes {
		result := &types.ScanResult{
			Target:      "host.invalid",
			Certificate: untrustedCert(shape.selfSigned, shape.isCA),
			Protocols:   []types.Protocol{{Version: "TLS 1.3", Supported: true}},
		}
		result.Vulnerabilities = s.checkVulnerabilities(result)
		results = append(results, scored{shape.name, s.calculateGrade(result)})
	}

	first := results[0]
	for _, r := range results[1:] {
		if r.grade.Score != first.grade.Score {
			t.Errorf("%q scores %d and %q scores %d for the same verification failure, "+
				"so the server chooses its own penalty",
				first.name, first.grade.Score, r.name, r.grade.Score)
		}
		if r.grade.VulnerabilityPenalty != first.grade.VulnerabilityPenalty {
			t.Errorf("%q is penalised %d and %q is penalised %d for the same verification "+
				"failure", first.name, first.grade.VulnerabilityPenalty,
				r.name, r.grade.VulnerabilityPenalty)
		}
	}

	// Non-vacuous in the other direction: a chain that fails verification must
	// cost something. Equal scores of zero penalty would satisfy the loop above.
	if first.grade.VulnerabilityPenalty == 0 {
		t.Error("a chain that no client accepts is penalised nothing at all, which is the " +
			"defect this test exists for rather than a fix for it")
	}
}

// TestAVerifiedSelfSignedCertificateIsStillReported covers the remaining
// combination: the chain built, and it built because this machine's trust store
// carries the certificate itself. That is a real configuration rather than a
// failure here, so it is reported at a lower severity, but it is reported: a
// client anywhere else refuses the same certificate.
func TestAVerifiedSelfSignedCertificateIsStillReported(t *testing.T) {
	s := New(nil)

	for _, isCA := range []bool{true, false} {
		cert := untrustedCert(true, isCA)
		cert.ChainTrust = types.CheckPassed
		cert.ChainTrustReason = ""

		found := trustFindings(s.checkVulnerabilities(&types.ScanResult{
			Target:      "host.invalid",
			Certificate: cert,
		}))

		if len(found) != 1 || found[0].ID != "CERT_SELF_SIGNED" {
			t.Fatalf("isCA=%v: got %d findings, want exactly one CERT_SELF_SIGNED", isCA, len(found))
		}
		if found[0].Severity != types.SeverityMedium {
			t.Errorf("isCA=%v: a certificate this machine does trust is reported %s, which "+
				"would make a working internal CA read as a failure", isCA, found[0].Severity)
		}
	}
}

// TestANotPerformedChainCheckIsNotReportedAsAVerification covers the third state
// of ChainTrust, which the first version of this switch had no case for.
//
// CheckNotPerformed is set by this scanner's own chain check when the
// certificate is outside its validity window. Without a case for it, a
// self-signed certificate in that state fell into the chain-verified arm and was
// described as having "verified only because this machine's trust store already
// carries it" — about a certificate that was never verified and that no trust
// store contains. Reachable with an expired self-signed certificate on the
// pure-Go verifier, which is what every Linux host runs.
//
// "Unknown" is a third state, and a finding must not collapse it into either of
// the other two.
func TestANotPerformedChainCheckIsNotReportedAsAVerification(t *testing.T) {
	s := New(nil)

	for _, isCA := range []bool{true, false} {
		cert := untrustedCert(true, isCA)
		cert.ChainTrust = types.CheckNotPerformed
		cert.ChainTrustReason = "not evaluated because the certificate is outside its " +
			"validity period"

		found := trustFindings(s.checkVulnerabilities(&types.ScanResult{
			Target:      "host.invalid",
			Certificate: cert,
		}))

		if len(found) != 1 {
			t.Fatalf("isCA=%v: got %d trust findings, want exactly one", isCA, len(found))
		}
		got := found[0]

		// Severity, ID and name are pinned because splitting this arm out moved
		// this input from under the only assertion that covered them. Measured:
		// with only the text assertions below, mutating this arm's severity to
		// LOW or to CRITICAL left the whole suite green, and LOW carries a
		// zero-point penalty, so an expired self-signed certificate would have
		// silently stopped costing anything on the pure-Go verifier.
		if got.Severity != types.SeverityMedium {
			t.Errorf("isCA=%v: severity is %s, want %s. A chain result that was not "+
				"established is not a measured failure, and it is not nothing either.",
				isCA, got.Severity, types.SeverityMedium)
		}
		if got.ID != "CERT_SELF_SIGNED" {
			t.Errorf("isCA=%v: finding ID is %q, want CERT_SELF_SIGNED", isCA, got.ID)
		}
		if got.Name != "Self-Signed Certificate" {
			t.Errorf("isCA=%v: finding name is %q", isCA, got.Name)
		}
		if got.Remediation == "" {
			t.Errorf("isCA=%v: the finding carries no remediation, so it is a dead end", isCA)
		}

		// The specific false claim, and the words that carry it.
		for _, forbidden := range []string{
			"verified only because",
			"trust store already carries it",
		} {
			if strings.Contains(got.Description, forbidden) {
				t.Errorf("isCA=%v: the finding claims a verification result for a check "+
					"that did not run: %q", isCA, got.Description)
			}
		}
		if !strings.Contains(got.Description, "was not established") {
			t.Errorf("isCA=%v: the finding does not say the chain result was not "+
				"established, so a reader cannot tell an unknown result from a measured "+
				"one: %q", isCA, got.Description)
		}
		// Nor may it swing the other way and assert a failure that was not
		// measured either.
		if strings.Contains(got.Description, "does not build to a root") {
			t.Errorf("isCA=%v: the finding asserts a chain failure that was never "+
				"measured: %q", isCA, got.Description)
		}
		// It must carry its OWN reason rather than pointing at another line. The
		// previous version said "see the line above for why", which is a claim
		// about the report's layout that is false on four of the five renderers.
		if !strings.Contains(got.Description, cert.ChainTrustReason) {
			t.Errorf("isCA=%v: the finding does not carry the reason the chain check "+
				"gave (%q), so on the surfaces that render no chain-trust line the "+
				"reader is told nothing: %q", isCA, cert.ChainTrustReason, got.Description)
		}
		for _, positional := range []string{"the line above", "above for why", "below"} {
			if strings.Contains(got.Description, positional) {
				t.Errorf("isCA=%v: the finding refers to its position in the report, which "+
					"is not true on every renderer: %q", isCA, got.Description)
			}
		}
	}
}

// TestATrustedChainProducesNoTrustFinding is the acceptance control. A guard
// that fires on everything is a false clean of the opposite kind, and the whole
// point of this change is that the finding follows the verification result.
func TestATrustedChainProducesNoTrustFinding(t *testing.T) {
	s := New(nil)

	cert := untrustedCert(false, false)
	cert.Subject = "CN=example.com"
	cert.Issuer = "CN=Example CA"
	cert.ChainTrust = types.CheckPassed
	cert.ChainTrustReason = ""

	found := trustFindings(s.checkVulnerabilities(&types.ScanResult{
		Target:      "example.com",
		Certificate: cert,
	}))
	if len(found) != 0 {
		t.Errorf("a chain that verified produced %d trust findings: %+v", len(found), found)
	}
}
