package analyzer

import (
	"reflect"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
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
// HOW THIS FILE IS RED-PROVED, corrected in 0.4.1.
//
// It used to claim it named nothing new, so it could be built against the
// sources before the fix and would fail there on behaviour. Checked rather than
// believed: copied into a pristine tree at a869357 it does not build
// (`undefined: writePolicyFile`). 0.4.0 landed as one squashed commit, so there
// is no per-fix parent in this repository to build against instead.
//
// The proof is mechanical and pins the production behaviour rather than a
// property of one historical tree: make fieldConstrains return true without
// reading the decoded value, which is exactly the disagreement this file exists
// for, and TestEverySpellingOfZeroIsRefusedAsANonRule and
// TestAValueThatDecodesToANoOpIsRefusedHoweverItIsWritten both fail. Run, and
// they did.

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

// TestAValueThatDecodesToANoOpIsRefusedHoweverItIsWritten is the general form of
// the defect. The guard must judge the value the EVALUATOR will use, not a
// parallel reading of the same text, because two decoders do not agree:
//
//   - `requireForwardSecrecy: no` resolves to a string when read into `any`,
//     while yaml's struct decoder sets the bool field to false (YAML 1.1
//     compatibility). Judged as a string it looked like a constraint.
//   - `minKeySize: 0.4` is a positive float to `any` and truncates to 0 in the
//     int field. Judged as a float it looked like a constraint.
//
// The first of these was a REGRESSION introduced by the first attempt at this
// fix, which deleted an explicit `case "false", "no", "off"` and replaced it
// with a decode into `any`. It is listed first here for that reason.
func TestAValueThatDecodesToANoOpIsRefusedHoweverItIsWritten(t *testing.T) {
	cases := []struct {
		rule    string
		written string
	}{
		// Booleans that YAML 1.1 spells as false.
		{"cipher:\n    requireForwardSecrecy", "false"},
		{"cipher:\n    requireForwardSecrecy", "no"},
		{"cipher:\n    requireForwardSecrecy", "No"},
		{"cipher:\n    requireForwardSecrecy", "NO"},
		{"cipher:\n    requireForwardSecrecy", "off"},
		{"cipher:\n    requireForwardSecrecy", "Off"},
		{"cipher:\n    requireForwardSecrecy", "OFF"},
		{"quantum:\n    requireHybridKeyExchange", "no"},
		{"quantum:\n    requirePqcCertificates", "off"},
		{"certificate:\n    requireCt", "no"},
		{"cipher:\n    requireForwardSecrecy", "n"},
		{"cipher:\n    requireForwardSecrecy", "N"},
		// Numbers that decode to zero in an integer field.
		{"cipher:\n    minKeySize", "0"},
		{"cipher:\n    minKeySize", "0x0"},
		{"cipher:\n    minKeySize", "0.4"},
		{"cipher:\n    minKeySize", "0.9"},
		{"cipher:\n    minKeySize", "1e-9"},
		{"cipher:\n    minKeySize", "-1"},
		{"certificate:\n    minRsaKeySize", "0.5"},
		{"quantum:\n    minQuantumScore", "0.5"},
	}

	e := NewPolicyEvaluator()
	for _, tt := range cases {
		name := strings.ReplaceAll(tt.rule, "\n    ", ".") + "=" + tt.written
		t.Run(name, func(t *testing.T) {
			path := writePolicyFile(t,
				"name: t\nversion: \"1.0\"\nrules:\n  "+tt.rule+": "+tt.written+"\n")
			if _, err := e.LoadPolicy(path); err == nil {
				t.Fatalf("%s loaded as a policy. The evaluator decodes that value to a "+
					"no-op, so the policy can only ever report compliance.", name)
			}
		})
	}
}

// TestAValueThatDecodesToARealConstraintIsAccepted is the acceptance control for
// the same table. A guard that refuses real input is the same defect mirrored.
func TestAValueThatDecodesToARealConstraintIsAccepted(t *testing.T) {
	cases := []struct {
		rule    string
		written string
	}{
		{"cipher:\n    requireForwardSecrecy", "true"},
		{"cipher:\n    requireForwardSecrecy", "yes"},
		{"cipher:\n    requireForwardSecrecy", "on"},
		{"cipher:\n    requireForwardSecrecy", "y"},
		{"cipher:\n    requireForwardSecrecy", "Y"},
		{"quantum:\n    requireHybridKeyExchange", "true"},
		{"cipher:\n    minKeySize", "128"},
		{"cipher:\n    minKeySize", "0x80"},
		{"cipher:\n    minKeySize", "1"},
		{"certificate:\n    minRsaKeySize", "2048"},
		// The one inversion: false is the restrictive setting here, in every
		// spelling YAML gives it.
		{"certificate:\n    allowSelfSigned", "false"},
		{"certificate:\n    allowSelfSigned", "no"},
		{"certificate:\n    allowSelfSigned", "off"},
	}

	e := NewPolicyEvaluator()
	for _, tt := range cases {
		name := strings.ReplaceAll(tt.rule, "\n    ", ".") + "=" + tt.written
		t.Run(name, func(t *testing.T) {
			path := writePolicyFile(t,
				"name: t\nversion: \"1.0\"\nrules:\n  "+tt.rule+": "+tt.written+"\n")
			if _, err := e.LoadPolicy(path); err != nil {
				t.Fatalf("%s is a real constraint and must load: %v", name, err)
			}
		})
	}
}

// TestAnOverlayIsJudgedOnWhatSurvivesTheMerge covers the `extends` path.
//
// An earlier version of this test asserted that a disarming overlay is refused,
// with a fixture that also wrote `minVersion: TLS 1.0`. That made it vacuous: an
// inert floor is a non-empty string, which satisfies the guard on its own in
// both the old and the new implementation, so the assertion could never reach
// the branch it named and the test passed unmodified against the pre-fix code.
//
// What is actually true, and worth pinning, is that the merged view decides. An
// overlay that leaves a real inherited constraint in place loads; one that
// neutralises every inherited constraint and adds none of its own does not.
func TestAnOverlayIsJudgedOnWhatSurvivesTheMerge(t *testing.T) {
	e := NewPolicyEvaluator()

	// `modern` constrains protocol.minVersion, protocol.bannedVersions,
	// cipher.requireForwardSecrecy and cipher.bannedAlgorithms. Leaving its
	// minVersion floor inherited leaves a rule that can fail a scan.
	survives := `name: Vendor Baseline
version: "1.0"
extends: modern
rules:
  protocol:
    bannedVersions: []
  cipher:
    requireForwardSecrecy: no
    bannedAlgorithms: []
`
	if _, err := e.LoadPolicy(writePolicyFile(t, survives)); err != nil {
		t.Errorf("an overlay that leaves modern's minVersion floor inherited still has a "+
			"rule that can fail a scan and must load: %v", err)
	}

	// An overlay that disarms EVERY inherited rule, written entirely in the
	// YAML 1.1 boolean spellings, must be refused.
	//
	// This case is the whole point of the test and an earlier version did not
	// have it: the fixture left `modern`'s minVersion floor inherited, which
	// satisfies the merged view on its own, so the boolean was never consulted
	// and reintroducing the regression left the test green. Emptying minVersion
	// as well is what makes the boolean decide the outcome.
	for _, off := range []string{"false", "no", "off", "n", "N", "Off"} {
		disarmed := `name: Vendor Baseline
version: "1.0"
extends: strict
rules:
  protocol:
    minVersion: ""
    bannedVersions: []
    requiredVersions: []
  cipher:
    minKeySize: 0
    requireForwardSecrecy: ` + off + `
    bannedAlgorithms: []
    bannedCipherSuites: []
  certificate:
    minValidityDays: 0
    minRsaKeySize: 0
    minEccKeySize: 0
    bannedSignatureAlgorithms: []
    allowSelfSigned: yes
  quantum:
    requireHybridKeyExchange: ` + off + `
    requirePqcCertificates: ` + off + `
    minQuantumScore: 0
`
		if _, err := e.LoadPolicy(writePolicyFile(t, disarmed)); err == nil {
			t.Errorf("an overlay that neutralises every inherited rule, with the disabling "+
				"booleans written as %q, loaded as \"Vendor Baseline\". It can only ever "+
				"report compliance, and writing the same booleans as `false` is refused.", off)
		}
	}
}

// constrainableKind names the kinds fieldConstrains actually decides on. It is
// deliberately a second list rather than a call into fieldConstrains: a test
// that asked fieldConstrains which kinds it handles would agree with itself
// whatever it did.
func constrainableKind(k reflect.Kind) bool {
	switch k {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64,
		reflect.String,
		reflect.Slice, reflect.Array:
		return true
	default:
		return false
	}
}

// TestAnUnhandledKindIsNotCountedAsADeclaredRule pins the direction of the
// default arm in fieldConstrains.
//
// declaresARule accepts a policy as soon as one written key constrains, so
// returning true for a kind the function cannot evaluate accepts a policy whose
// only rule may enforce nothing. That is the fail-open direction and the exact
// shape of the ruleless policies the guard exists to refuse, and the comment on
// that arm claimed it was the safe one.
func TestAnUnhandledKindIsNotCountedAsADeclaredRule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"a map", map[string]string{"a": "b"}},
		{"a pointer", new(int)},
		{"a struct", struct{ A int }{A: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := reflect.ValueOf(tc.value)
			if constrainableKind(v.Kind()) {
				t.Fatalf("%s is a kind fieldConstrains handles, so this case does not reach "+
					"the arm under test", v.Kind())
			}
			if fieldConstrains("someRule", v) {
				t.Errorf("fieldConstrains counted a %s as a declared rule, so a policy whose "+
					"only rule is such a field loads while constraining nothing", v.Kind())
			}
		})
	}
}

// TestEveryRuleFieldResolvesThroughTheReflectionMapping guards the one direction
// the reflection lookup can fail open.
//
// declaresARule maps a written key to its decoded field by yaml struct tag, and
// treats an unmapped key as a rule so that a schema error is not reported as
// "defines no rules". yaml.v3 does not use tags exclusively: a field with no
// yaml tag is keyed on strings.ToLower(field.Name), so it would be accepted by
// the decoder and missed by the mapping, and a policy whose only rule was that
// field would load while constraining nothing.
//
// No rule field is written that way today. This fails the moment one is.
func TestEveryRuleFieldResolvesThroughTheReflectionMapping(t *testing.T) {
	rules := reflect.ValueOf(types.PolicyRules{})
	rulesType := rules.Type()

	checked := 0
	for i := 0; i < rulesType.NumField(); i++ {
		sectionTag, _, _ := strings.Cut(rulesType.Field(i).Tag.Get("yaml"), ",")
		if sectionTag == "" {
			t.Errorf("rule section %q has no yaml tag, so declaresARule cannot map keys "+
				"written under it and every such key counts as a rule",
				rulesType.Field(i).Name)
			continue
		}

		section := rules.Field(i)
		sectionType := section.Type()
		for j := 0; j < sectionType.NumField(); j++ {
			field := sectionType.Field(j)
			fieldTag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if fieldTag == "" {
				t.Errorf("%s.%s has no yaml tag. yaml.v3 would still accept it, keyed on the "+
					"lowercased field name, while declaresARule would not find it, so a "+
					"policy whose only rule is that field would load and constrain nothing.",
					sectionTag, field.Name)
				continue
			}
			resolved, ok := ruleField(rules, sectionTag, fieldTag)
			if !ok {
				t.Errorf("rules.%s.%s does not resolve through ruleField", sectionTag, fieldTag)
				continue
			}

			// Resolving is not enough: fieldConstrains decides on Kind, and its
			// default arm refuses to call an unhandled kind a rule, which refuses
			// the whole policy when it is the only rule written. Checking tags and
			// resolution alone left that arm reachable with the suite green, so a
			// rule field added as a *int or a map[string]string would have started
			// refusing legitimate policies with no test saying why.
			if !constrainableKind(resolved.Kind()) {
				t.Errorf("rules.%s.%s is a %s, which fieldConstrains does not handle, so it "+
					"falls to the default arm and is not counted as a declared rule. Add the "+
					"kind to fieldConstrains and to constrainableKind together.",
					sectionTag, fieldTag, resolved.Kind())
			}
			checked++
		}
	}

	if checked < 20 {
		t.Fatalf("only %d rule fields were checked; the walk is not reaching the schema", checked)
	}
}

// TestAMalformedScalarIsRefusedAsAParseErrorNotAsARulelessPolicy pins the
// ordering that keeps the decode-error branch in constrains unreachable.
//
// LoadPolicy decodes against the schema before it asks whether the document
// declares a rule, so a scalar with a bad tag is refused by the parser with a
// message naming the type problem. A mutation flipping that branch's return
// value survives today precisely because nothing reaches it. This test does not
// kill that mutation and is not meant to: it fails if the two steps are ever
// reordered, which is what would make the branch reachable and its answer
// matter. Recorded as a deliberate survivor rather than left implicit.
func TestAMalformedScalarIsRefusedAsAParseErrorNotAsARulelessPolicy(t *testing.T) {
	cases := []string{
		"!!int abc",
		"!!float xyz",
		"!!timestamp nope",
	}

	e := NewPolicyEvaluator()
	for _, form := range cases {
		t.Run(form, func(t *testing.T) {
			path := writePolicyFile(t,
				"name: t\nversion: \"1.0\"\nrules:\n  cipher:\n    minKeySize: "+form+"\n")
			_, err := e.LoadPolicy(path)
			if err == nil {
				t.Fatalf("minKeySize: %s loaded", form)
			}
			if strings.Contains(err.Error(), "defines no rules") {
				t.Errorf("minKeySize: %s was reported as a policy that defines no rules. "+
					"It defines one the parser could not read, and saying otherwise sends "+
					"the author looking for a missing rule instead of a bad value: %v",
					form, err)
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
