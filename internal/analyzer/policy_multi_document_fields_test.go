package analyzer

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names warningOnlyRuleKeys, which did not exist before the fix, so
// it cannot compile against the pre-fix sources. The behavioural assertions
// live in policy_multi_document_test.go, which does compile there and fails on
// behaviour, which is what makes the red proof meaningful.

// TestEveryWarningOnlyRuleIsListed stops warningOnlyRuleKeys from going stale.
//
// The list exists so the ruleless guard knows which rules cannot fail. If a rule
// is moved from Warnings to Violations, or a new warning-only rule is added, the
// list has to move with it: a stale entry silently refuses policies that could
// gate, and a missing one reopens this defect.
//
// The evaluator is driven with a scan that fails everything, and every rule that
// lands in Warnings must be listed, and every listed rule must actually be
// capable of landing there.
func TestEveryWarningOnlyRuleIsListed(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("cnsa-2.0-2035")
	if !ok {
		t.Fatal("built-in cnsa-2.0-2035 is missing, so this test would prove nothing")
	}

	// A host that satisfies as little as possible, so every rule that can report
	// does report.
	result := scanWithChainCheckResult(types.CheckPassed, types.CheckPassed)
	result.Certificate.DaysUntilExpiry = 1
	result.Certificate.QuantumSafe = false
	result.Certificate.PublicKeyBits = 256
	result.QuantumRisk = types.QuantumRiskAssessment{Assessed: true, Score: 1}

	pr := e.Evaluate(result, policy)

	if len(pr.Warnings) == 0 {
		t.Fatal("no warnings were raised at all, so this test cannot see which rules warn")
	}

	// Direction one: a rule that warns must be listed. A missing entry lets a
	// policy built only from that rule load as a gate, which is the defect.
	for _, w := range pr.Warnings {
		if !warningOnlyRuleKeys[w.Rule] {
			t.Errorf("%s reported a warning but is not in warningOnlyRuleKeys, so a policy "+
				"whose only rule is %s would load and could never fail", w.Rule, w.Rule)
		}
	}

	// Direction two: a listed rule must actually be one that warns, demonstrated
	// by it appearing in Warnings against a fixture built to trip it.
	//
	// Asserting only that a listed rule raises no VIOLATION is far too weak: a
	// rule that cannot fire at all against this fixture trivially raises no
	// violation, so a bogus entry like certificate.minRsaKeySize (a violation
	// rule, and one an ECDSA fixture never reaches) passed that check. A stale
	// entry silently refuses policies that could really gate, so it has to be
	// caught here.
	for rule := range warningOnlyRuleKeys {
		if findViolation(pr, rule) != nil {
			t.Errorf("%s is listed as warning-only but raised a violation, so the list is "+
				"stale and policies that could gate are being refused", rule)
		}
		if findWarning(pr, rule) == nil {
			t.Errorf("%s is listed as warning-only but did not warn against a fixture built "+
				"to trip every warning rule, so either it is not a warning rule at all or "+
				"this fixture no longer reaches it. Either way the list cannot be trusted.",
				rule)
		}
	}
}
