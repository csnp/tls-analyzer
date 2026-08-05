package scanner

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The pre-push adversarial review found that a certificate whose validity period
// has NOT STARTED scored the certificate dimension 25 of 25 and graded A+
// 100/100, indistinguishable from a healthy certificate.
//
// The cause is that Go's x509 verifier returns the same reason for both ends of
// the validity window (crypto/x509/verify.go: `now.Before(NotBefore)` and
// `now.After(NotAfter)` both give CertificateInvalidError{Reason: Expired}, and
// its own message reads "certificate has expired or is not yet valid"). The
// chain check steps aside for that reason on the grounds that the window is
// "reported on its own", but the scanner derived Expired from NotAfter only, so
// nothing reported this end of it: no finding, no failed check, no lost points.
//
// Clock skew and pre-staged certificates make this reachable without an
// adversary, and every client refuses such a certificate exactly as it refuses
// an expired one.
//
// HOW THIS FILE IS RED-PROVED, corrected in 0.4.1.
//
// It used to claim it named nothing new, so it could be built against the
// sources before the fix and would fail there on behaviour rather than on a
// build error. Checked rather than believed: copied into a pristine tree at
// a869357 it does not build (`undefined: issueLeaf`). 0.4.0 landed as one
// squashed commit, so there is no per-fix parent in this repository to build
// against instead, and a proof that needs objects only one machine has is not
// one anyone can repeat.
//
// The proof is mechanical and pins the production behaviour: set NotYetValid to
// false rather than deriving it from now.Before(NotBefore), which is the exact
// omission described above, and TestANotYetValidCertificateIsNotScoredAsHealthy
// and TestAShortNotYetValidWindowRaisesOneFindingNotTwo both fail. Run, and they
// did.

// notYetValidWindow is a validity period that starts a year from now.
func notYetValidWindow() (time.Time, time.Time) {
	start := time.Now().Add(365 * 24 * time.Hour)
	return start, start.Add(90 * 24 * time.Hour)
}

func TestANotYetValidCertificateIsNotScoredAsHealthy(t *testing.T) {
	notBefore, notAfter := notYetValidWindow()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	// Trust the one-off CA, so the chain verifies and the validity window is the
	// only thing wrong. Without this the dimension scores zero because the chain
	// is untrusted, and the test would pass without exercising the defect at all.
	cfg := localScanConfig()
	cfg.TrustRoots = iss.roots
	result := scanLocal(t, cfg, host, port)

	factor := certificateFactor(t, result)
	if factor.Score != 0 {
		t.Errorf("Certificate factor = %d/%d (%q), want 0. The certificate's validity "+
			"period has not started, so every client refuses it exactly as it refuses "+
			"an expired one, and the dimension that describes it must not award points.",
			factor.Score, factor.MaxScore, factor.Details)
	}

	if v := findVulnerability(result, "CERT_NOT_YET_VALID"); v == nil {
		t.Error("no CERT_NOT_YET_VALID finding. The chain check declines to run for a " +
			"certificate outside its validity window because the window is 'reported on " +
			"its own', so if nothing reports it the scan says nothing is wrong.")
	} else {
		if v.Severity != types.SeverityCritical {
			t.Errorf("CERT_NOT_YET_VALID severity = %q, want %q (an expired certificate is CRITICAL "+
				"and this is refused by clients for the same reason)", v.Severity, types.SeverityCritical)
		}
		if v.Remediation == "" {
			t.Error("CERT_NOT_YET_VALID carries no remediation, so the finding is a dead end")
		}
	}

	if result.Grade.Letter == "A+" {
		t.Errorf("grade = %s (%d/100) for a certificate that is not yet valid",
			result.Grade.Letter, result.Grade.Score)
	}

	// The recommendations are a separate reader of the same predicate. Fixing
	// the score and the finding while leaving this one behind is how the first
	// version of this fix missed three surfaces.
	found := false
	for _, rec := range result.Recommendations {
		if strings.Contains(strings.ToLower(rec.Title+" "+rec.Description), "not yet valid") ||
			strings.Contains(strings.ToLower(rec.Title), "valid now") {
			found = true
			break
		}
	}
	if !found {
		titles := make([]string, 0, len(result.Recommendations))
		for _, rec := range result.Recommendations {
			titles = append(titles, rec.Title)
		}
		t.Errorf("no recommendation tells the operator the certificate is not yet valid; "+
			"recommendations were %q", titles)
	}
}

// TestAValidCertificateOnTheSameChainIsUnaffected is the acceptance control. The
// two cases differ only in the validity window, so if this one moves the fix has
// reached past the case it was written for.
func TestAValidCertificateOnTheSameChainIsUnaffected(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	// Trust the one-off CA, so the chain verifies and the validity window is the
	// only thing wrong. Without this the dimension scores zero because the chain
	// is untrusted, and the test would pass without exercising the defect at all.
	cfg := localScanConfig()
	cfg.TrustRoots = iss.roots
	result := scanLocal(t, cfg, host, port)

	if v := findVulnerability(result, "CERT_NOT_YET_VALID"); v != nil {
		t.Error("a currently-valid certificate was reported as not yet valid")
	}

	factor := certificateFactor(t, result)
	if factor.Score == 0 {
		t.Errorf("Certificate factor = 0/%d (%q) for a currently-valid certificate on a "+
			"chain the scan trusts; the fix has over-reached", factor.MaxScore, factor.Details)
	}
}

// TestAnExpiredCertificateStillReportsExpiry guards the other end of the same
// window, so a change that fixes one end cannot silently drop the other.
func TestAnExpiredCertificateStillReportsExpiry(t *testing.T) {
	notBefore := time.Now().Add(-365 * 24 * time.Hour)
	notAfter := time.Now().Add(-24 * time.Hour)
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	// Trust the one-off CA, so the chain verifies and the validity window is the
	// only thing wrong. Without this the dimension scores zero because the chain
	// is untrusted, and the test would pass without exercising the defect at all.
	cfg := localScanConfig()
	cfg.TrustRoots = iss.roots
	result := scanLocal(t, cfg, host, port)

	if v := findVulnerability(result, "CERT_EXPIRED"); v == nil {
		t.Error("no CERT_EXPIRED finding for a certificate that expired yesterday")
	}
	if v := findVulnerability(result, "CERT_NOT_YET_VALID"); v != nil {
		t.Error("an expired certificate was also reported as not yet valid; the two ends " +
			"of the window must not be confused for one another")
	}
	if factor := certificateFactor(t, result); factor.Score != 0 {
		t.Errorf("Certificate factor = %d/%d for an expired certificate, want 0",
			factor.Score, factor.MaxScore)
	}
}

// TestAShortNotYetValidWindowRaisesOneFindingNotTwo covers the sibling predicate
// the first sweep missed. The `DaysUntilExpiry > 0` guard on "expiring soon"
// exists so an EXPIRED certificate is not also reported as expiring; a
// not-yet-valid certificate has a positive count and walked straight through it,
// producing two findings for one condition, a double penalty, and a "plan
// renewal" instruction that points the wrong way.
func TestAShortNotYetValidWindowRaisesOneFindingNotTwo(t *testing.T) {
	notBefore := time.Now().Add(24 * time.Hour)
	notAfter := notBefore.Add(19 * 24 * time.Hour) // inside the 30-day window
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	cfg := localScanConfig()
	cfg.TrustRoots = iss.roots
	result := scanLocal(t, cfg, host, port)

	if findVulnerability(result, "CERT_NOT_YET_VALID") == nil {
		t.Fatal("no CERT_NOT_YET_VALID finding for a certificate that starts tomorrow")
	}
	if v := findVulnerability(result, "CERT_EXPIRING"); v != nil {
		t.Errorf("the same certificate is also reported as expiring soon (%q, fix %q). "+
			"One condition, two findings, two penalties, and the remediation tells the "+
			"operator to renew a certificate that has not started yet.",
			v.Description, v.Remediation)
	}
}

// TestAnExpiringCertificateIsStillReported is the acceptance control for that
// guard: suppressing the pair must not suppress the ordinary case.
func TestAnExpiringCertificateIsStillReported(t *testing.T) {
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	cfg := localScanConfig()
	cfg.TrustRoots = iss.roots
	result := scanLocal(t, cfg, host, port)

	if findVulnerability(result, "CERT_EXPIRING") == nil {
		t.Error("a certificate with 10 days left is no longer reported as expiring soon")
	}
	if findVulnerability(result, "CERT_NOT_YET_VALID") != nil {
		t.Error("a currently-valid certificate was reported as not yet valid")
	}
}
