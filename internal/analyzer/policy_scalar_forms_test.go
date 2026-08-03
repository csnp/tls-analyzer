package analyzer

import (
	"strings"
	"testing"
)

// The pre-push adversarial review found that the guard which refuses a policy
// that cannot fail was judging the WRITTEN text with strconv rather than the
// value yaml.v3 actually decodes. `strconv.ParseFloat` rejects `0x0` (Go hex
// floats need a `p` exponent) while yaml.v3 decodes it to the integer 0, so the
// two disagreed about the same value:
//
//	minKeySize: 0     -> refused, "defines no rules"
//	minKeySize: 0x0   -> loaded, COMPLIANT 100/100, exit 0
//
// Through `extends` that is verbatim the defect this release already closed
// once: an overlay zeroing every inherited rule loads under its own name and
// reports a clean verdict against a server that satisfies nothing. One
// character reopened it.
//
// This file names nothing new, so it compiles against the pre-fix sources and
// fails there on behaviour.

// everySpellingOfZero lists the ways YAML can write the integer 0. Each decodes
// to the same value, so each must reach the same verdict: a rule set to zero
// constrains nothing and cannot fail a scan.
var everySpellingOfZero = []string{"0", "00", "+0", "-0", "0.0", "0x0", "0X0", "0o0", "0b0"}

func TestEverySpellingOfZeroIsRefusedAsANonRule(t *testing.T) {
	e := NewPolicyEvaluator()
	for _, form := range everySpellingOfZero {
		t.Run(form, func(t *testing.T) {
			path := writePolicyFile(t, "name: t\nversion: \"1.0\"\nrules:\n  cipher:\n    minKeySize: "+form+"\n")
			_, err := e.LoadPolicy(path)
			if err == nil {
				t.Fatalf("minKeySize: %s loaded as a policy. It decodes to 0, which no scan can "+
					"fail, so a compliant verdict from it would mean nothing. The decimal "+
					"spelling of the same value is refused.", form)
			}
			if !strings.Contains(err.Error(), "defines no rules") {
				t.Errorf("minKeySize: %s was refused, but not as a ruleless policy: %v", form, err)
			}
		})
	}
}

// TestEverySpellingOfANonZeroMinimumIsAccepted is the acceptance control. A
// guard that refuses real input is the same defect mirrored, and this release
// has shipped that twice.
func TestEverySpellingOfANonZeroMinimumIsAccepted(t *testing.T) {
	// 128 written as decimal, hex, octal and binary.
	forms := []string{"128", "0x80", "0o200", "0b10000000"}

	e := NewPolicyEvaluator()
	for _, form := range forms {
		t.Run(form, func(t *testing.T) {
			path := writePolicyFile(t, "name: t\nversion: \"1.0\"\nrules:\n  cipher:\n    minKeySize: "+form+"\n")
			policy, err := e.LoadPolicy(path)
			if err != nil {
				t.Fatalf("minKeySize: %s is a real constraint and must load: %v", form, err)
			}
			if policy.Rules.Cipher.MinKeySize != 128 {
				t.Errorf("minKeySize: %s decoded to %d, want 128", form, policy.Rules.Cipher.MinKeySize)
			}
		})
	}
}

// TestSpellingOfAValueNeverChangesTheVerdict states the invariant the defect
// broke, and states it through `extends`, which is the path that matters: two
// spellings of the same decoded value must reach the same outcome.
//
// This is deliberately not "the overlay is refused". An overlay that leaves a
// real inherited constraint in place SHOULD load: dropping minVersion from the
// overlay leaves `modern`'s TLS 1.2 floor intact, and that policy still raises
// two protocol.minVersion violations against a host offering TLS 1.0. Asserting
// refusal there would pin the wrong behaviour. What must never happen is the
// same policy being refused when written `0` and accepted when written `0x0`.
func TestSpellingOfAValueNeverChangesTheVerdict(t *testing.T) {
	overlay := `name: Vendor Baseline
version: "1.0"
extends: modern
rules:
  protocol:
    minVersion: TLS 1.0
    bannedVersions: []
  cipher:
    minKeySize: %s
    requireForwardSecrecy: false
    bannedAlgorithms: []
    bannedCipherSuites: []
  certificate:
    minRsaKeySize: %s
    minEccKeySize: %s
    allowSelfSigned: true
  quantum:
    minQuantumScore: %s
    requireHybridKeyExchange: false
    requirePqcCertificates: false
`
	e := NewPolicyEvaluator()

	baselinePath := writePolicyFile(t, strings.ReplaceAll(overlay, "%s", "0"))
	_, baselineErr := e.LoadPolicy(baselinePath)
	baselineLoaded := baselineErr == nil

	for _, form := range everySpellingOfZero {
		t.Run(form, func(t *testing.T) {
			path := writePolicyFile(t, strings.ReplaceAll(overlay, "%s", form))
			_, err := e.LoadPolicy(path)
			loaded := err == nil
			if loaded != baselineLoaded {
				t.Errorf("writing zero as %q gives loaded=%v while the decimal 0 gives "+
					"loaded=%v. The same decoded value must reach the same verdict; "+
					"before this fix 0x0, 0o0 and 0b0 slipped past the guard that 0 trips.",
					form, loaded, baselineLoaded)
			}
		})
	}
}

// TestAllowSelfSignedKeepsItsInversionAcrossSpellings pins the one field where
// false is the restrictive setting. Judging the decoded value must not lose it.
func TestAllowSelfSignedKeepsItsInversionAcrossSpellings(t *testing.T) {
	cases := []struct {
		written    string
		constrains bool
	}{
		{"false", true}, // restrictive: this is what every built-in sets
		{"true", false}, // permissive: constrains nothing
		{"False", true}, // YAML decodes this to the boolean false
		{"TRUE", false}, // and this to the boolean true
	}

	e := NewPolicyEvaluator()
	for _, tt := range cases {
		t.Run(tt.written, func(t *testing.T) {
			path := writePolicyFile(t,
				"name: t\nversion: \"1.0\"\nrules:\n  certificate:\n    allowSelfSigned: "+tt.written+"\n")
			_, err := e.LoadPolicy(path)
			loaded := err == nil
			if loaded != tt.constrains {
				t.Errorf("allowSelfSigned: %s loaded=%v, want loaded=%v (err=%v)",
					tt.written, loaded, tt.constrains, err)
			}
		})
	}
}
