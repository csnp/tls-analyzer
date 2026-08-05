package analyzer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The release test that gated 0.4.0 found that the strict validation this
// release added covers policy KEYS only. Rule VALUES were never validated, and
// six declared rule FIELDS had no evaluator at all, so in both cases the rule
// silently vanished and the report read COMPLIANT 100/100 with exit 0.
//
// HOW THIS FILE IS RED-PROVED, corrected in 0.4.1.
//
// It used to claim it named nothing new, so it could be built against the
// sources before the fix and would fail there on behaviour. That was checked
// rather than believed: copied into a pristine tree at a869357, the release
// base, this file does not build at all (`undefined: types.CheckPassed`). The
// evidence the comment offered did not exist, which in a file whose whole
// subject is verdicts that were never measured is the wrong claim to leave
// standing.
//
// It cannot be repaired by pointing at an earlier parent either: 0.4.0 landed as
// a single squashed commit, so there is no per-fix parent in this repository's
// history to build against, and a proof that needs objects only one machine has
// is not a proof anyone can repeat.
//
// The proof is mechanical instead, and it is stronger, because it pins the
// production behaviour rather than a property of one historical tree. Reverting
// the validation these tests are named for kills them:
//
//	validateProtocolVersionValues stops checking its fields ->
//	  TestUnrecognisedProtocolVersionValuesAreRefused fails
//	validateAlgorithmValues stops checking its fields ->
//	  TestAnAlgorithmValueThatNormalizesToNothingIsRefused fails
//
// Both were run and both failed. Anyone changing these guards can rerun them by
// making the same one-line edits.

// scanForRuleValues is a well-formed scan of a host that offers TLS 1.0 through
// TLS 1.3, one AES-256 suite and one 3DES-SHA suite, a hybrid key exchange, and
// an ECDSA-SHA256 certificate with a 90 day lifetime.
func scanForRuleValues() *types.ScanResult {
	notBefore := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	return &types.ScanResult{
		Target: "example.com",
		Host:   "example.com",
		Port:   443,
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
			{Version: "TLS 1.2", Supported: true},
			{Version: "TLS 1.1", Supported: true},
			{Version: "TLS 1.0", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true, Encryption: "AES"},
			{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Bits: 112, Encryption: "3DES", MAC: "SHA1"},
		},
		KeyExchanges: []types.KeyExchange{
			{Name: "X25519MLKEM768", Type: "hybrid", PQCAlgorithm: "ML-KEM-768"},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      256,
			SignatureAlgorithm: "ECDSA-SHA256",
			DaysUntilExpiry:    60,
			NotBefore:          notBefore,
			NotAfter:           notBefore.AddDate(0, 0, 90),
			// A real scan always records both checks. Left at the zero value the
			// verdict is incomplete for a reason these tests are not about.
			NameMatch:  types.CheckPassed,
			ChainTrust: types.CheckPassed,
		},
		QuantumRisk: types.QuantumRiskAssessment{Assessed: true, Score: 64},
	}
}

func writePolicyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	return path
}

// TestUnrecognisedProtocolVersionValuesAreRefused is the reproduction of the
// release-test P1: `bannedVersions: ["TLSv1.2"]` reported COMPLIANT 100/100 and
// exit 0 against a server that does enable TLS 1.2, because the value matched no
// scanned protocol and the rule quietly left the verdict.
//
// minVersion had a sharper edge: an unknown key in a Go map reads back as 0,
// which is the rank of SSL 3.0, so `minVersion: garbage` was satisfied by any
// protocol at all.
func TestUnrecognisedProtocolVersionValuesAreRefused(t *testing.T) {
	e := NewPolicyEvaluator()

	badValues := []string{"TLSv1.2", "tls 1.2", "TLS1.2", "TLS 1.2 ", "nonsense", "TLS 9.9"}
	fields := []string{
		"    minVersion: %s\n",
		"    maxVersion: %s\n",
		"    bannedVersions:\n      - %q\n",
		"    requiredVersions:\n      - %q\n",
	}

	for _, field := range fields {
		for _, value := range badValues {
			name := strings.TrimSpace(strings.SplitN(field, ":", 2)[0]) + "/" + value
			t.Run(name, func(t *testing.T) {
				body := "name: t\nversion: \"1.0\"\nrules:\n  protocol:\n"
				if strings.Contains(field, "%q") {
					body += strings.Replace(field, "%q", "\""+value+"\"", 1)
				} else {
					body += strings.Replace(field, "%s", "\""+value+"\"", 1)
				}
				_, err := e.LoadPolicy(writePolicyFile(t, body))
				if err == nil {
					t.Fatalf("value %q was accepted. An unrecognised protocol version silently "+
						"matches nothing, so the rule leaves the verdict and the report reads "+
						"COMPLIANT for a policy that was never applied", value)
				}
				if !strings.Contains(err.Error(), value) {
					t.Errorf("the error does not quote the offending value %q, so the user "+
						"cannot see which entry to correct: %v", value, err)
				}
				if !strings.Contains(err.Error(), "TLS 1.2") {
					t.Errorf("the error does not list the accepted values, which is the only "+
						"way a user learns the right spelling: %v", err)
				}
			})
		}
	}
}

// TestLegitimateProtocolVersionValuesStillLoad is the acceptance control for the
// test above. A guard that refuses real input is a false clean of the opposite
// kind, and refusing "SSL 2.0" would break the financial-services example in
// this project's own docs/policies.md.
func TestLegitimateProtocolVersionValuesStillLoad(t *testing.T) {
	e := NewPolicyEvaluator()
	for _, value := range []string{"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"} {
		t.Run(value, func(t *testing.T) {
			body := "name: t\nversion: \"1.0\"\nrules:\n  protocol:\n    bannedVersions:\n      - \"" +
				value + "\"\n"
			if _, err := e.LoadPolicy(writePolicyFile(t, body)); err != nil {
				t.Fatalf("%q is a protocol version a user may legitimately ban, and it was "+
					"refused: %v", value, err)
			}
		})
	}
}

// TestBanningAnUnprobeableVersionIsNotEvaluated covers the sibling the value
// sweep turned up. Go's TLS stack cannot offer SSL 2.0 or SSL 3.0, so the
// scanner never reports them and a ban on one could never fire. Three of the
// five built-in policies banned SSL 3.0, so that rule had passed on every host
// ever scanned without being tested once.
//
// It is recorded as not evaluated rather than as a warning. A warning left the
// verdict complete and the exit code 0, which contradicts this tool's own
// documented contract that a policy which could not be fully evaluated exits 2,
// and was inconsistent with certificate.requireCt, an identical situation.
func TestBanningAnUnprobeableVersionIsNotEvaluated(t *testing.T) {
	e := NewPolicyEvaluator()
	policy := &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{
			Protocol: types.ProtocolRules{BannedVersions: []string{"SSL 3.0"}},
		},
	}

	pr := e.Evaluate(scanForRuleValues(), policy)

	if v := findViolation(pr, "protocol.bannedVersions"); v != nil {
		t.Fatalf("a version the scanner cannot probe must not be reported as a violation "+
			"either, since that would be an equally unfounded claim: %+v", v)
	}

	var skipped bool
	for _, s := range pr.SkippedRules {
		if s.Rule == "protocol.bannedVersions" {
			skipped = true
			if !strings.Contains(s.Reason, "SSL 3.0") {
				t.Errorf("the reason must name the version it could not test: %q", s.Reason)
			}
			// OpenSSL 3.x removed -ssl2 and -ssl3, so citing s_client here was a
			// command no reader could run.
			if strings.Contains(s.Reason, "s_client -ssl3") {
				t.Errorf("the reason cites a command that does not exist on OpenSSL 3.x: %q",
					s.Reason)
			}
		}
	}
	if !skipped {
		t.Error("banning SSL 3.0 was not recorded as unevaluated, so silence was counted " +
			"as compliance. The scanner never offers SSL 3.0, so the absence of a result " +
			"is not evidence the server has it disabled")
	}
	if pr.Complete {
		t.Error("a verdict carrying a rule that could not be tested must not be marked " +
			"complete, or the exit code claims a full evaluation that did not happen")
	}
}

// TestPreviouslyUnevaluatedRulesNowFire covers the six rule fields that were
// declared in the schema, documented in docs/policies.md, printed by
// print-policy and, in two cases, named by the built-in CNSA 2.0 policies, while
// having no evaluator at all.
//
// Every rule is asserted in BOTH directions. A rule that only ever fails is as
// broken as one that only ever passes, and the failing half alone cannot tell
// the difference.
func TestPreviouslyUnevaluatedRulesNowFire(t *testing.T) {
	tests := []struct {
		name          string
		rules         types.PolicyRules
		wantViolation string
	}{
		{
			name: "requiredSignatureAlgorithms not met",
			rules: types.PolicyRules{Certificate: types.CertificateRules{
				RequiredSignatureAlgorithms: []string{"ML-DSA-65"}}},
			wantViolation: "certificate.requiredSignatureAlgorithms",
		},
		{
			name: "requiredSignatureAlgorithms met",
			rules: types.PolicyRules{Certificate: types.CertificateRules{
				RequiredSignatureAlgorithms: []string{"ECDSA-SHA256"}}},
		},
		{
			name: "quantum.requiredKeyExchangeAlgorithms not met",
			rules: types.PolicyRules{Quantum: types.QuantumRules{
				RequiredKeyExchangeAlgorithms: []string{"ML-KEM-1024"}}},
			wantViolation: "quantum.requiredKeyExchangeAlgorithms",
		},
		{
			name: "quantum.requiredKeyExchangeAlgorithms met",
			rules: types.PolicyRules{Quantum: types.QuantumRules{
				RequiredKeyExchangeAlgorithms: []string{"ML-KEM-768"}}},
		},
		{
			name: "maxVersion exceeded",
			rules: types.PolicyRules{Protocol: types.ProtocolRules{
				MaxVersion: "TLS 1.1"}},
			wantViolation: "protocol.maxVersion",
		},
		{
			name: "maxVersion respected",
			rules: types.PolicyRules{Protocol: types.ProtocolRules{
				MaxVersion: "TLS 1.3"}},
		},
		{
			name: "maxValidityDays exceeded",
			rules: types.PolicyRules{Certificate: types.CertificateRules{
				MaxValidityDays: 30}},
			wantViolation: "certificate.maxValidityDays",
		},
		{
			name: "maxValidityDays respected",
			rules: types.PolicyRules{Certificate: types.CertificateRules{
				MaxValidityDays: 400}},
		},
		// The fixture certificate is valid for exactly 90 days, so these two
		// bracket the threshold. An extreme fixture on one side alone cannot tell
		// a correct cutoff from one that is off by one: a mutation loosening
		// "longer than the maximum" to "at least the maximum" survives 30 and 400
		// and is caught only here.
		{
			name: "maxValidityDays equal to the lifetime is allowed",
			rules: types.PolicyRules{Certificate: types.CertificateRules{
				MaxValidityDays: 90}},
		},
		{
			name: "maxValidityDays one day under the lifetime is a violation",
			rules: types.PolicyRules{Certificate: types.CertificateRules{
				MaxValidityDays: 89}},
			wantViolation: "certificate.maxValidityDays",
		},
		{
			name: "allowedCipherSuites excludes an offered suite",
			rules: types.PolicyRules{Cipher: types.CipherRules{
				AllowedCipherSuites: []string{"TLS_AES_256_GCM_SHA384"}}},
			wantViolation: "cipher.allowedCipherSuites",
		},
		{
			name: "allowedCipherSuites covers every offered suite",
			rules: types.PolicyRules{Cipher: types.CipherRules{
				AllowedCipherSuites: []string{
					"TLS_AES_256_GCM_SHA384", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}}},
		},
	}

	e := NewPolicyEvaluator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := e.Evaluate(scanForRuleValues(), &types.Policy{Name: "t", Rules: tt.rules})
			got := findViolation(pr, tt.wantViolation)

			if tt.wantViolation == "" {
				if len(pr.Violations) != 0 {
					t.Fatalf("a satisfied rule produced %d violation(s), the first being %q. "+
						"A rule that always fails is as broken as one that never fires",
						len(pr.Violations), pr.Violations[0].Rule)
				}
				return
			}
			if got == nil {
				t.Fatalf("rule %s produced no violation, so a stated requirement the host "+
					"does not meet was reported as satisfied with exit 0", tt.wantViolation)
			}
			if got.Expected == "" || got.Remediation == "" {
				t.Errorf("violation %s must say what was expected and what to do about it, "+
					"got Expected=%q Remediation=%q", tt.wantViolation, got.Expected, got.Remediation)
			}
		})
	}
}

// TestAnUnmetRequiredVersionIsAViolation covers a rule the docs describe as a
// MUST that only ever produced a warning, so the verdict read COMPLIANT with
// exit 0 while the same report printed "TLS 1.3  Not Supported" and
// "Fix: Enable TLS 1.3". Two built-in CNSA 2.0 policies require TLS 1.3, so a CI
// gate on either was green whatever the server did.
func TestAnUnmetRequiredVersionIsAViolation(t *testing.T) {
	e := NewPolicyEvaluator()
	scan := scanForRuleValues()
	for i := range scan.Protocols {
		if scan.Protocols[i].Version == "TLS 1.3" {
			scan.Protocols[i].Supported = false
		}
	}

	pr := e.Evaluate(scan, &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{RequiredVersions: []string{"TLS 1.3"}}},
	})

	if findViolation(pr, "protocol.requiredVersions") == nil {
		t.Fatal("a version the policy says MUST be supported, and that the scan shows is " +
			"not, produced no violation, so the verdict was compliant against a server " +
			"the tool knew did not satisfy it")
	}
	if pr.Compliant {
		t.Error("the verdict is compliant despite an unmet requirement")
	}
}

// TestAlgorithmSeparatorsDoNotDecideWhetherARuleApplies covers the half of the
// value problem that validation cannot reach. "SHA-256" is the spelling NIST
// uses and the one this tool's own remediation text teaches, while the
// certificate field reads "SHA256-RSA", so banning SHA-256 silently did nothing
// and reported COMPLIANT against a certificate signed with exactly that.
func TestAlgorithmSeparatorsDoNotDecideWhetherARuleApplies(t *testing.T) {
	e := NewPolicyEvaluator()
	scan := scanForRuleValues() // certificate signature is ECDSA-SHA256

	for _, spelling := range []string{"SHA256", "SHA-256", "sha-256", "sha_256", "Sha 256"} {
		t.Run(spelling, func(t *testing.T) {
			pr := e.Evaluate(scan, &types.Policy{
				Name: "t",
				Rules: types.PolicyRules{Certificate: types.CertificateRules{
					BannedSignatureAlgorithms: []string{spelling}}},
			})
			if findViolation(pr, "certificate.bannedSignatureAlgorithms") == nil {
				t.Fatalf("banning %q did not fire against ECDSA-SHA256, so whether the rule "+
					"applies depends on the separators a user happened to type", spelling)
			}
		})
	}

	// Acceptance control: normalising must not make unrelated names collide.
	pr := e.Evaluate(scan, &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{Certificate: types.CertificateRules{
			BannedSignatureAlgorithms: []string{"MD5", "SHA-1"}}},
	})
	if v := findViolation(pr, "certificate.bannedSignatureAlgorithms"); v != nil {
		t.Errorf("normalisation made an unrelated algorithm match ECDSA-SHA256: %+v", v)
	}
}

// TestAPolicyThatConstrainsNothingIsRefused covers three ways a document got
// past the "defines no rules" guard and produced COMPLIANT 100/100 against a
// host that satisfied nothing, plus the inverse: the guard refused
// `allowSelfSigned: false`, the restrictive setting every built-in uses, because
// Go cannot tell an unset field from one set to its zero value.
func TestAPolicyThatConstrainsNothingIsRefused(t *testing.T) {
	e := NewPolicyEvaluator()

	refused := map[string]string{
		"only a target year label": "name: t\nrules:\n  quantum:\n    cnsa2TargetYear: 2035\n",
		"an empty list":            "name: t\nrules:\n  protocol:\n    bannedVersions: []\n",
		"a list of one blank item": "name: t\nrules:\n  protocol:\n    bannedVersions:\n      -\n",
		// Every rule but allowSelfSigned is gated on a positive number or a true
		// boolean, so a zero or a false is a no-op by construction. An earlier
		// version of this test asserted the opposite, on the reasoning that a
		// value the user wrote is a rule they meant; that enshrined a policy which
		// can report nothing but compliance, which is what this guard exists to
		// prevent.
		"a zero minimum":       "name: t\nrules:\n  quantum:\n    minQuantumScore: 0\n",
		"a false requirement":  "name: t\nrules:\n  cipher:\n    requireForwardSecrecy: false\n",
		"a negative minimum":   "name: t\nrules:\n  certificate:\n    minRsaKeySize: -1\n",
		"an empty min version": "name: t\nrules:\n  protocol:\n    minVersion: \"\"\n",
		// The same shapes must not slip through as an overlay either: the guard
		// short-circuited on the presence of `extends`, so the exact document
		// refused standalone was accepted when it also disarmed a base rule.
		"a vacuous overlay": "name: t\nextends: strict\nrules:\n  protocol:\n    minVersion: \"\"\n" +
			"    bannedVersions: []\n    requiredVersions: []\n  cipher:\n    minKeySize: 0\n" +
			"    requireForwardSecrecy: false\n    bannedAlgorithms: []\n  certificate:\n" +
			"    minValidityDays: 0\n    minRsaKeySize: 0\n    minEccKeySize: 0\n" +
			"    bannedSignatureAlgorithms: []\n    allowSelfSigned: true\n  quantum:\n" +
			"    requireHybridKeyExchange: false\n    minQuantumScore: 0\n",
	}
	for name, body := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			if _, err := e.LoadPolicy(writePolicyFile(t, body)); err == nil {
				t.Fatal("a policy that constrains nothing was accepted, so it can only ever " +
					"report a compliant verdict that means nothing")
			}
		})
	}

	accepted := map[string]string{
		// allowSelfSigned is the one inversion in the schema: false is the
		// restrictive setting, and it is what every built-in policy uses.
		"a restrictive boolean": "name: t\nrules:\n  certificate:\n    allowSelfSigned: false\n",
		"a real minimum":        "name: t\nrules:\n  quantum:\n    minQuantumScore: 50\n",
		"a true requirement":    "name: t\nrules:\n  cipher:\n    requireForwardSecrecy: true\n",
		// Inheriting a base policy and adding nothing is legitimate: the merged
		// rules are the base's, which do constrain.
		"a bare extends":           "name: t\nextends: strict\n",
		"an extends that tightens": "name: t\nextends: modern\nrules:\n  cipher:\n    minKeySize: 256\n",
	}
	for name, body := range accepted {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := e.LoadPolicy(writePolicyFile(t, body)); err != nil {
				t.Fatalf("a rule set to its zero value is still a rule the user wrote, and it "+
					"was refused: %v", err)
			}
		})
	}
}

// TestMinVersionIsAFloorNotACapability covers a rule that asked only whether the
// server could REACH the minimum, never whether it still accepted anything
// below it. `minVersion: TLS 1.3` reported COMPLIANT 100/100 with exit 0 against
// a server that also accepted TLS 1.0, in the same report that listed TLS 1.0 as
// supported and raised a HIGH finding for it.
func TestMinVersionIsAFloorNotACapability(t *testing.T) {
	e := NewPolicyEvaluator()

	// The fixture offers TLS 1.0 through TLS 1.3.
	pr := e.Evaluate(scanForRuleValues(), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{MinVersion: "TLS 1.3"}},
	})
	if findViolation(pr, "protocol.minVersion") == nil {
		t.Fatal("a server that still accepts TLS 1.0 satisfied a TLS 1.3 minimum, so the " +
			"rule reported compliance for exactly the configuration it exists to forbid")
	}

	// Acceptance control: a floor the server genuinely meets must still pass, or
	// the rule has simply been inverted into always failing.
	pr = e.Evaluate(scanForRuleValues(), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{MinVersion: "TLS 1.0"}},
	})
	if v := findViolation(pr, "protocol.minVersion"); v != nil {
		t.Fatalf("a minimum the server meets, with nothing below it enabled, was reported "+
			"as a violation: %+v", v)
	}

	// The capability half must still fire: a server that cannot reach the
	// minimum at all is a violation for a different reason.
	lowScan := scanForRuleValues()
	for i := range lowScan.Protocols {
		if lowScan.Protocols[i].Version == "TLS 1.3" {
			lowScan.Protocols[i].Supported = false
		}
	}
	pr = e.Evaluate(lowScan, &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{MinVersion: "TLS 1.3"}},
	})
	if findViolation(pr, "protocol.minVersion") == nil {
		t.Error("a server that cannot reach the minimum at all produced no violation")
	}
}

// TestACertificateNoClientWouldAcceptFailsCertificatePolicy covers a policy
// verdict that contradicted the report it was printed in. A policy asking for
// key size, lifetime and a CA-issued certificate reported COMPLIANT 100/100
// against a certificate served for the wrong name, and against one chaining to
// an untrusted root, while the same report printed "NOT VALID FOR THIS NAME" and
// scored the certificate dimension 0 of 25. Each individual rule was satisfied,
// which is why this has to be its own check.
func TestACertificateNoClientWouldAcceptFailsCertificatePolicy(t *testing.T) {
	e := NewPolicyEvaluator()
	policy := &types.Policy{
		Name: "cert-hygiene",
		Rules: types.PolicyRules{Certificate: types.CertificateRules{
			MinValidityDays: 30,
			MinECCKeySize:   256,
			AllowSelfSigned: false,
		}},
	}

	cases := []struct {
		name    string
		mutate  func(*types.Certificate)
		wantsAt string
	}{
		{"served for the wrong name", func(c *types.Certificate) {
			c.NameMatch = types.CheckFailed
			c.NameMismatchReason = "x509: certificate is valid for other.example, not example.com"
		}, "certificate.nameMatch"},
		{"chain not trusted", func(c *types.Certificate) {
			c.ChainTrust = types.CheckFailed
		}, "certificate.chainTrust"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanForRuleValues()
			scan.Certificate.NameMatch = types.CheckPassed
			scan.Certificate.ChainTrust = types.CheckPassed
			tc.mutate(scan.Certificate)

			pr := e.Evaluate(scan, policy)
			if findViolation(pr, tc.wantsAt) == nil {
				t.Fatalf("%s produced no %s violation, so the policy verdict said the "+
					"certificate was acceptable while the rest of the report said no client "+
					"would accept it", tc.name, tc.wantsAt)
			}
			if pr.Compliant {
				t.Error("the verdict is compliant for a certificate no client would accept")
			}
		})
	}

	// Acceptance control: a certificate that passes both checks must not be
	// failed by them.
	scan := scanForRuleValues()
	scan.Certificate.NameMatch = types.CheckPassed
	scan.Certificate.ChainTrust = types.CheckPassed
	pr := e.Evaluate(scan, policy)
	for _, rule := range []string{"certificate.nameMatch", "certificate.chainTrust"} {
		if v := findViolation(pr, rule); v != nil {
			t.Errorf("a certificate that passed both checks was failed by %s: %+v", rule, v)
		}
	}

	// A check that did not run must not be read as a failure either.
	scan.Certificate.ChainTrust = types.CheckNotPerformed
	pr = e.Evaluate(scan, policy)
	if v := findViolation(pr, "certificate.chainTrust"); v != nil {
		t.Errorf("a chain check that did not run was reported as a failed one: %+v", v)
	}
}

// TestAPolicyFileCannotForgeTheReportItAppearsIn covers untrusted input reaching
// the rendered verdict. A policy file arrives from a vendor, a repository or a
// colleague, and its name is printed into a human-readable report. A name
// containing newlines printed its own "Status: COMPLIANT / Score: 100/100" block
// and pushed the real verdict off the screen; an ANSI escape survived
// --no-color. The exit code and the JSON stayed honest throughout, which is
// exactly why the text report had to be fixed rather than relied upon.
func TestAPolicyFileCannotForgeTheReportItAppearsIn(t *testing.T) {
	e := NewPolicyEvaluator()

	forged := "acme\nStatus: COMPLIANT\nScore: 100/100\n\n\n#"
	body := "name: " + strconv.Quote(forged) + "\nrules:\n  protocol:\n    minVersion: TLS 1.2\n"
	policy, err := e.LoadPolicy(writePolicyFile(t, body))
	if err != nil {
		t.Fatalf("the fixture must load, or this tests nothing: %v", err)
	}
	if strings.ContainsAny(policy.Name, "\n\r") {
		t.Errorf("the policy name still carries newlines, so it can print its own "+
			"verdict block into the report: %q", policy.Name)
	}

	escaped := "red\x1b[31mALERT\x1b[0m"
	body = "name: " + strconv.Quote(escaped) + "\nrules:\n  protocol:\n    minVersion: TLS 1.2\n"
	policy, err = e.LoadPolicy(writePolicyFile(t, body))
	if err != nil {
		t.Fatalf("the fixture must load: %v", err)
	}
	if strings.ContainsRune(policy.Name, 0x1b) {
		t.Errorf("an ANSI escape survived into the policy name, so a policy file can "+
			"colour the report and --no-color cannot stop it: %q", policy.Name)
	}

	long := strings.Repeat("A", 4000)
	body = "name: " + strconv.Quote(long) + "\nrules:\n  protocol:\n    minVersion: TLS 1.2\n"
	policy, err = e.LoadPolicy(writePolicyFile(t, body))
	if err != nil {
		t.Fatalf("the fixture must load: %v", err)
	}
	if len(policy.Name) > 120 {
		t.Errorf("a policy name of %d characters is rendered in full, so it can still "+
			"push the verdict out of view", len(policy.Name))
	}

	// Acceptance control: an ordinary name must survive untouched.
	body = "name: acme-baseline\ndescription: Our TLS floor\nrules:\n  protocol:\n    minVersion: TLS 1.2\n"
	policy, err = e.LoadPolicy(writePolicyFile(t, body))
	if err != nil {
		t.Fatalf("an ordinary policy must still load: %v", err)
	}
	if policy.Name != "acme-baseline" || policy.Description != "Our TLS floor" {
		t.Errorf("sanitising damaged an ordinary name or description: %q / %q",
			policy.Name, policy.Description)
	}
}

// TestAnUnprobeableRequiredVersionIsNotEvaluated is the mirror of the banned
// case. Reporting that SSL 3.0 is "not detected" is as unfounded as reporting it
// absent, when the scanner cannot offer it in the first place.
func TestAnUnprobeableRequiredVersionIsNotEvaluated(t *testing.T) {
	e := NewPolicyEvaluator()
	pr := e.Evaluate(scanForRuleValues(), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{RequiredVersions: []string{"SSL 3.0"}}},
	})

	if v := findViolation(pr, "protocol.requiredVersions"); v != nil {
		t.Fatalf("a version the scanner cannot offer was reported as missing: %+v", v)
	}
	var skipped bool
	for _, s := range pr.SkippedRules {
		if s.Rule == "protocol.requiredVersions" {
			skipped = true
		}
	}
	if !skipped {
		t.Error("no skipped-rule entry, so the requirement was silently treated as met")
	}

	// Acceptance control: a version the scanner CAN probe still reports normally.
	pr = e.Evaluate(scanForRuleValues(), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{RequiredVersions: []string{"TLS 1.3"}}},
	})
	for _, s := range pr.SkippedRules {
		if s.Rule == "protocol.requiredVersions" {
			t.Errorf("a probeable version was recorded as not evaluated: %+v", s)
		}
	}
}

// TestAPolicyWithAMinimumVersionIsStillComplete pins the decision NOT to record
// the unmeasurable sub-TLS-1.0 region as a skipped rule for minVersion. Every
// policy sets a minimum, so doing so would mark every evaluation incomplete
// forever and make "complete" mean nothing. The probe range is disclosed in the
// scan coverage notes instead, and a policy that NAMES SSL 2.0 or SSL 3.0 still
// gets a skipped rule.
func TestAPolicyWithAMinimumVersionIsStillComplete(t *testing.T) {
	e := NewPolicyEvaluator()
	pr := e.Evaluate(scanForRuleValues(), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Protocol: types.ProtocolRules{MinVersion: "TLS 1.2"}},
	})
	for _, s := range pr.SkippedRules {
		if s.Rule == "protocol.minVersion" {
			t.Fatalf("a plain minimum-version rule was recorded as not evaluated, which "+
				"marks every policy incomplete and makes the flag meaningless: %+v", s)
		}
	}
	if !pr.Complete {
		t.Error("a policy whose rules were all evaluated is not marked complete")
	}
}

// TestAnAlgorithmValueThatNormalizesToNothingIsRefused covers a fail-open the
// normalization itself introduced. Names are compared on their letters and
// digits, so a value with none reduces to the empty string, and
// strings.Contains(s, "") is true: a required-algorithm rule written that way
// was satisfied by any input, and a banned-algorithm rule written that way
// matched every input. The fullwidth spelling of an algorithm name renders
// identically to the ASCII one in the report, so the policy looked strict.
func TestAnAlgorithmValueThatNormalizesToNothingIsRefused(t *testing.T) {
	e := NewPolicyEvaluator()

	degenerate := []string{"ＭＬ－ＤＳＡ－６５", "—", "***", "-", "  ", "·•·"}
	for _, value := range degenerate {
		t.Run(value, func(t *testing.T) {
			body := "name: t\nrules:\n  certificate:\n    requiredSignatureAlgorithms:\n      - " +
				strconv.Quote(value) + "\n"
			if _, err := e.LoadPolicy(writePolicyFile(t, body)); err == nil {
				t.Fatalf("%q was accepted. It normalizes to nothing, so as a requirement it is "+
					"satisfied by any input and as a ban it matches every input", value)
			}
		})
	}

	// Acceptance control: real names must still load.
	for _, value := range []string{"ML-DSA-65", "SHA-256", "sha_256", "ECDSA-SHA384"} {
		t.Run("accepted/"+value, func(t *testing.T) {
			body := "name: t\nrules:\n  certificate:\n    requiredSignatureAlgorithms:\n      - " +
				strconv.Quote(value) + "\n"
			if _, err := e.LoadPolicy(writePolicyFile(t, body)); err != nil {
				t.Fatalf("a real algorithm name was refused: %v", err)
			}
		})
	}

	// And the matcher itself must not treat an empty needle as a match, so a
	// value reaching it by any other route still cannot pass unconditionally.
	if containsFold("TLS_AES_256_GCM_SHA384", "—") {
		t.Error("containsFold matched an empty needle, so a ban on it flags every suite")
	}
	if equalFoldAlgorithm("", "") {
		t.Error("equalFoldAlgorithm matched two empty values, so an unset scanned field " +
			"satisfies a requirement")
	}
	if !containsFold("SHA256-RSA", "SHA-256") {
		t.Error("a real name stopped matching, so the guard broke the fix it protects")
	}
}

// TestRuleValuesCannotForgeTheReport covers the half of the forgery fix that
// sanitising the name and description missed. A rule value is interpolated into
// Expected, Actual and Remediation, and the same renderer prints those, so an
// ANSI cursor-up sequence in an allowed-suite list rewrote the line above it and
// could overprint a NON-COMPLIANT verdict with a COMPLIANT one, surviving
// --no-color.
func TestRuleValuesCannotForgeTheReport(t *testing.T) {
	e := NewPolicyEvaluator()
	forged := "\x1b[1A\x1b[2K    Status:     COMPLIANT\n    Score: 100/100"

	pr := e.Evaluate(scanForRuleValues(), &types.Policy{
		Name: "t",
		Rules: types.PolicyRules{Cipher: types.CipherRules{
			AllowedCipherSuites: []string{forged},
		}},
	})

	if len(pr.Violations) == 0 {
		t.Fatal("the fixture must produce a violation, or this tests nothing")
	}
	for _, v := range pr.Violations {
		for field, s := range map[string]string{
			"Description": v.Description, "Expected": v.Expected,
			"Actual": v.Actual, "Remediation": v.Remediation,
		} {
			if strings.ContainsRune(s, 0x1b) {
				t.Errorf("%s carries an ANSI escape from the policy file: %q", field, s)
			}
			if strings.ContainsAny(s, "\n\r") {
				t.Errorf("%s carries a newline from the policy file, so it can print its "+
					"own verdict line: %q", field, s)
			}
		}
	}
}

// TestRequireCTIsRecordedAsNotEvaluated covers the one rule in the schema with
// no scanned input behind it. This scanner collects no SCTs and queries no CT
// log, so reporting the rule as satisfied would be the same fail-open as reading
// an unmeasured quantum score as a zero.
func TestRequireCTIsRecordedAsNotEvaluated(t *testing.T) {
	e := NewPolicyEvaluator()
	pr := e.Evaluate(scanForRuleValues(), &types.Policy{
		Name:  "t",
		Rules: types.PolicyRules{Certificate: types.CertificateRules{RequireCT: true}},
	})

	var skipped bool
	for _, s := range pr.SkippedRules {
		if s.Rule == "certificate.requireCt" {
			skipped = true
			if s.Reason == "" {
				t.Error("a skipped rule with no reason tells the reader nothing")
			}
		}
	}
	if !skipped {
		t.Fatal("certificate.requireCt was not recorded as unevaluated, so a Certificate " +
			"Transparency requirement was reported as met by a scanner that never looked")
	}
	if pr.Complete {
		t.Error("a verdict that skipped a rule is about a smaller set than the policy " +
			"defines, so it must not be marked complete")
	}
}

// TestAlgorithmMatchingIsCaseInsensitive covers the half of the value problem
// that cannot be fixed by validation, because algorithm names are a free-form
// space rather than a closed set. "sha1" banned nothing while "SHA1" banned two
// suites on the same host, and nothing in the output said which had happened.
func TestAlgorithmMatchingIsCaseInsensitive(t *testing.T) {
	e := NewPolicyEvaluator()
	scan := scanForRuleValues()

	cases := []struct {
		name  string
		rules types.PolicyRules
		rule  string
	}{
		{"bannedAlgorithms lowercase", types.PolicyRules{Cipher: types.CipherRules{
			BannedAlgorithms: []string{"3des"}}}, "cipher.bannedAlgorithms"},
		{"bannedAlgorithms uppercase", types.PolicyRules{Cipher: types.CipherRules{
			BannedAlgorithms: []string{"3DES"}}}, "cipher.bannedAlgorithms"},
		{"bannedCipherSuites lowercase", types.PolicyRules{Cipher: types.CipherRules{
			BannedCipherSuites: []string{"tls_rsa_with_3des_ede_cbc_sha"}}}, "cipher.bannedCipherSuites"},
		{"bannedSignatureAlgorithms lowercase", types.PolicyRules{Certificate: types.CertificateRules{
			BannedSignatureAlgorithms: []string{"ecdsa"}}}, "certificate.bannedSignatureAlgorithms"},
		{"bannedSignatureAlgorithms uppercase", types.PolicyRules{Certificate: types.CertificateRules{
			BannedSignatureAlgorithms: []string{"ECDSA"}}}, "certificate.bannedSignatureAlgorithms"},
		{"requiredKeyExchange lowercase", types.PolicyRules{Cipher: types.CipherRules{
			RequiredKeyExchange: []string{"ml-kem-768"}}}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr := e.Evaluate(scan, &types.Policy{Name: "t", Rules: tc.rules})
			got := findViolation(pr, tc.rule)
			if tc.rule == "" {
				// requiredKeyExchange is satisfied by X25519MLKEM768/ML-KEM-768,
				// so the lowercase spelling must find it rather than report it missing.
				if v := findViolation(pr, "cipher.requiredKeyExchange"); v != nil {
					t.Fatalf("a lowercase spelling of a key exchange the host does offer was " +
						"reported as missing, which fails the scan in the other direction")
				}
				return
			}
			if got == nil {
				t.Fatalf("%s did not fire for this spelling, so whether a rule applies "+
					"depends on the case a user happened to type", tc.rule)
			}
		})
	}
}
