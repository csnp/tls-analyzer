package analyzer

import (
	"os"
	"path/filepath"
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
// This file names nothing that did not already exist in the schema, so it
// compiles against the pre-fix sources and fails there on behaviour.

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

// TestBanningAnUnprobeableVersionWarnsRatherThanPasses covers the sibling the
// value sweep turned up. Go's TLS stack cannot offer SSL 2.0 or SSL 3.0, so the
// scanner never reports them and a ban on one could never fire. The built-in
// "modern" policy bans SSL 3.0, so that rule had passed on every host ever
// scanned without being tested once.
func TestBanningAnUnprobeableVersionWarnsRatherThanPasses(t *testing.T) {
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

	var warned bool
	for _, w := range pr.Warnings {
		if w.Rule == "protocol.bannedVersions" && strings.Contains(w.Actual, "not tested") {
			warned = true
			if !strings.Contains(w.Remediation, "openssl") {
				t.Errorf("the warning has to say how to check it another way, or it is a "+
					"dead end: %q", w.Remediation)
			}
		}
	}
	if !warned {
		t.Error("banning SSL 3.0 produced no warning, so silence was counted as compliance. " +
			"The scanner never offers SSL 3.0, so the absence of a result is not evidence " +
			"the server has it disabled")
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
