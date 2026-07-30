package scanner

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file holds the tests that name the fields and the config option added
// for certificate name and chain verification. They cannot compile against the
// pre-fix sources, so they cannot be red-proved at runtime, and they are kept
// apart from certificate_checks_test.go for exactly that reason: the
// behavioural tests there compile against the old code and fail in it.

// TestVerifyCertificateNameMatchingRules states the expected verdicts directly
// rather than deferring to the matcher the implementation calls, so the test
// can disagree with the implementation. A table that asked VerifyHostname what
// it thought would agree with any rule the implementation happened to apply,
// including a broken one.
//
// The expectations are the RFC 6125 name-matching rules: a wildcard replaces
// exactly one label, only in the leftmost position, and never matches the bare
// domain. wrong.host.badssl.com against *.badssl.com is the case that shipped.
func TestVerifyCertificateNameMatchingRules(t *testing.T) {
	notBefore, notAfter := validFrom()

	cases := []struct {
		name        string
		presented   []string
		ips         []net.IP
		requested   string
		wantMatched bool
		why         string
	}{
		{
			name:      "wildcard does not span two labels",
			presented: []string{"*.badssl.com", "badssl.com"},
			requested: "wrong.host.badssl.com",
			why:       "a wildcard replaces one label, so it cannot cover host.badssl.com plus wrong",
		},
		{
			name:        "wildcard covers exactly one label",
			presented:   []string{"*.badssl.com"},
			requested:   "foo.badssl.com",
			wantMatched: true,
			why:         "one label under the wildcard is what a wildcard is for",
		},
		{
			name:      "wildcard does not cover the bare domain",
			presented: []string{"*.example.com"},
			requested: "example.com",
			why:       "*.example.com carries no label in the wildcard position for example.com",
		},
		{
			name:        "bare domain listed alongside the wildcard does cover it",
			presented:   []string{"*.example.com", "example.com"},
			requested:   "example.com",
			wantMatched: true,
			why:         "the exact name is present in its own right",
		},
		{
			name:        "exact match is case insensitive",
			presented:   []string{"example.com"},
			requested:   "EXAMPLE.COM",
			wantMatched: true,
			why:         "DNS names are compared without regard to case",
		},
		{
			name:      "a different name entirely",
			presented: []string{"cloudflare.com"},
			requested: "example.com",
			why:       "--sni cloudflare.com against example.com reported a valid certificate for example.com",
		},
		{
			name:        "IP address in the SAN list",
			presented:   nil,
			ips:         []net.IP{net.ParseIP("127.0.0.1")},
			requested:   "127.0.0.1",
			wantMatched: true,
			why:         "a scan of an IP literal verifies against the IP SAN",
		},
		{
			name:      "IP address not in the SAN list",
			presented: []string{"example.com"},
			requested: "127.0.0.1",
			why:       "a DNS SAN does not authenticate an IP address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iss := issueLeaf(t, tc.presented, tc.ips, notBefore, notAfter)
			parsed := &types.Certificate{}
			verifyCertificateName(iss.leaf, parsed, tc.requested)

			want := types.CheckFailed
			if tc.wantMatched {
				want = types.CheckPassed
			}
			if parsed.NameMatch != want {
				t.Fatalf("presented %v/%v requested %q: got %q, want %q (%s)",
					tc.presented, tc.ips, tc.requested, parsed.NameMatch, want, tc.why)
			}
			if parsed.RequestedName != tc.requested {
				t.Fatalf("RequestedName = %q, want %q", parsed.RequestedName, tc.requested)
			}
			if want == types.CheckFailed && parsed.NameMismatchReason == "" {
				t.Fatal("a failed name check must carry a reason the report can print")
			}
		})
	}
}

// TestVerifyCertificateNameWithoutARequestedName covers the one input that has
// no answer. It must not report a pass.
func TestVerifyCertificateNameWithoutARequestedName(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, []string{"example.com"}, nil, notBefore, notAfter)

	parsed := &types.Certificate{}
	verifyCertificateName(iss.leaf, parsed, "")

	if parsed.NameMatch != types.CheckNotPerformed {
		t.Fatalf("NameMatch = %q, want %q: with no name requested there is nothing to verify, "+
			"and an unanswerable check must not read as a passing one",
			parsed.NameMatch, types.CheckNotPerformed)
	}
}

func TestVerifyCertificateChainTrust(t *testing.T) {
	notBefore, notAfter := validFrom()

	t.Run("chain to a root in the pool is trusted", func(t *testing.T) {
		iss := issueLeaf(t, []string{"example.com"}, nil, notBefore, notAfter)
		parsed := &types.Certificate{}
		verifyCertificateChain(iss.leaf, iss.chain, parsed, iss.roots)

		if parsed.ChainTrust != types.CheckPassed {
			t.Fatalf("ChainTrust = %q (%s), want %q. A guard that refuses a chain it should "+
				"accept is a false clean of the opposite kind: every host reads untrusted.",
				parsed.ChainTrust, parsed.ChainTrustReason, types.CheckPassed)
		}
	})

	t.Run("chain to a root outside the pool is not trusted", func(t *testing.T) {
		iss := issueLeaf(t, []string{"example.com"}, nil, notBefore, notAfter)
		other := issueLeaf(t, []string{"other.example"}, nil, notBefore, notAfter)

		parsed := &types.Certificate{}
		verifyCertificateChain(iss.leaf, iss.chain, parsed, other.roots)

		if parsed.ChainTrust != types.CheckFailed {
			t.Fatalf("ChainTrust = %q, want %q", parsed.ChainTrust, types.CheckFailed)
		}
		if parsed.ChainTrustReason == "" {
			t.Fatal("a failed chain check must carry a reason the report can print")
		}
	})

	t.Run("an expired certificate is left to the expiry finding", func(t *testing.T) {
		iss := issueLeaf(t, []string{"example.com"}, nil,
			time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

		parsed := &types.Certificate{}
		verifyCertificateChain(iss.leaf, iss.chain, parsed, iss.roots)

		if parsed.ChainTrust != types.CheckNotPerformed {
			t.Fatalf("ChainTrust = %q, want %q: expiry has its own finding and its own place "+
				"in the score, and restating it as a trust failure deducts twice for one fact",
				parsed.ChainTrust, types.CheckNotPerformed)
		}
		if !strings.Contains(parsed.ChainTrustReason, "validity period") {
			t.Fatalf("ChainTrustReason = %q, want it to say why the check did not run",
				parsed.ChainTrustReason)
		}
	})
}

// TestParsedChainCertificatesAreNotReportedAsChecked pins the polarity of the
// zero value. Every certificate starts as not checked, and only the leaf is
// given an answer, so an intermediate can never be read as having passed.
func TestParsedChainCertificatesAreNotReportedAsChecked(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, []string{"example.com"}, nil, notBefore, notAfter)

	parsed := parseCertificate(iss.chain[0])

	if parsed.NameMatch != types.CheckNotPerformed {
		t.Fatalf("chain certificate NameMatch = %q, want %q", parsed.NameMatch, types.CheckNotPerformed)
	}
	if parsed.ChainTrust != types.CheckNotPerformed {
		t.Fatalf("chain certificate ChainTrust = %q, want %q", parsed.ChainTrust, types.CheckNotPerformed)
	}
}

// TestScoreCertificateZeroOnAFailedCheck covers the full combination space of
// the two new inputs against the certificate score, rather than only the case
// each fix was written for.
func TestScoreCertificateZeroOnAFailedCheck(t *testing.T) {
	base := func() *types.Certificate {
		return &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      256,
			SignatureAlgorithm: "ECDSA-SHA256",
			DaysUntilExpiry:    90,
			NameMatch:          types.CheckPassed,
			ChainTrust:         types.CheckPassed,
			RequestedName:      "example.com",
		}
	}

	cases := []struct {
		name       string
		nameMatch  types.CheckResult
		chainTrust types.CheckResult
		wantZero   bool
	}{
		{"both passed", types.CheckPassed, types.CheckPassed, false},
		{"name failed", types.CheckFailed, types.CheckPassed, true},
		{"chain failed", types.CheckPassed, types.CheckFailed, true},
		{"both failed", types.CheckFailed, types.CheckFailed, true},
		{"name not performed", types.CheckNotPerformed, types.CheckPassed, false},
		{"chain not performed", types.CheckPassed, types.CheckNotPerformed, false},
		{"neither performed", types.CheckNotPerformed, types.CheckNotPerformed, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := base()
			cert.NameMatch = tc.nameMatch
			cert.ChainTrust = tc.chainTrust

			score, max := scoreCertificate(cert)
			if max != 25 {
				t.Fatalf("maxScore = %d, want 25", max)
			}
			if tc.wantZero && score != 0 {
				t.Fatalf("score = %d, want 0: a certificate a client refuses cannot carry "+
					"points in the dimension that describes it", score)
			}
			if !tc.wantZero && score == 0 {
				t.Fatalf("score = %d, want above 0: nothing about this certificate failed", score)
			}
		})
	}
}

// TestAQuantumAssessmentThatRanIsMarkedAsHavingRun is the acceptance control
// for every guard that now branches on that flag.
//
// If the scanner never set it, each of those guards would fire on every scan:
// the policy rule would be skipped always, the SARIF finding would never be
// published, and the HTML quantum section would never be drawn. Suppressing the
// tool's main output on every run is the failure mode on the other side of this
// fix, and it would be invisible to tests that only assert the unmeasured case.
func TestAQuantumAssessmentThatRanIsMarkedAsHavingRun(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	cfg := DefaultConfig()
	cfg.CheckQuantum = true

	result := scanLocal(t, cfg, host, port)
	if !result.QuantumRisk.Assessed {
		t.Fatal("a scan that ran the quantum assessment reports it as not having run, " +
			"which suppresses the quantum verdict in every output format")
	}
	if result.Grade.QuantumGrade == types.QuantumGradeNotAssessed {
		t.Fatalf("QuantumGrade = %q for a scan that assessed quantum readiness",
			result.Grade.QuantumGrade)
	}

	// And the negative half from the same scanner, so the flag tracks the config
	// rather than being hardcoded either way.
	cfg = DefaultConfig()
	cfg.CheckQuantum = false
	if skipped := scanLocal(t, cfg, host, port); skipped.QuantumRisk.Assessed {
		t.Fatal("a scan run with the quantum assessment disabled reports it as having run")
	}
}

// TestConfiguredTrustRootsDecideTheVerdict proves the injected pool is what the
// scanner actually consults, so the suite's own isolation from the host trust
// store is real rather than assumed.
func TestConfiguredTrustRootsDecideTheVerdict(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	cfg := DefaultConfig()
	cfg.CheckQuantum = false
	cfg.TrustRoots = iss.roots

	result := scanLocal(t, cfg, host, port)
	if result.Certificate.ChainTrust != types.CheckPassed {
		t.Fatalf("ChainTrust = %q (%s), want %q with the issuing CA supplied as the root pool",
			result.Certificate.ChainTrust, result.Certificate.ChainTrustReason, types.CheckPassed)
	}
	if result.Certificate.NameMatch != types.CheckPassed {
		t.Fatalf("NameMatch = %q, want %q for a certificate carrying the 127.0.0.1 IP SAN",
			result.Certificate.NameMatch, types.CheckPassed)
	}
}
