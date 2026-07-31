package analyzer

import (
	"testing"
)

// This file names identifiers that did not exist before the fix, so it cannot
// compile against the pre-fix sources. The behavioural assertions live in
// policy_rule_values_test.go, which does compile there and fails on behaviour,
// which is what makes the red proof meaningful.

// TestBuiltInPoliciesOnlyDeclareRulesThisScannerCanEvaluate keeps the built-ins
// honest. They banned SSL 3.0, which this scanner cannot probe, so every
// evaluation of modern, strict and cnsa-2.0-2030 carried an untested rule. A
// policy shipped with the tool should declare what the tool can actually check.
func TestBuiltInPoliciesOnlyDeclareRulesThisScannerCanEvaluate(t *testing.T) {
	e := NewPolicyEvaluator()
	for _, name := range e.ListPolicies() {
		policy, ok := e.GetPolicy(name)
		if !ok {
			t.Fatalf("built-in %q disappeared", name)
		}
		for _, banned := range policy.Rules.Protocol.BannedVersions {
			if _, cannotProbe := unprobeableProtocolVersions[banned]; cannotProbe {
				t.Errorf("built-in policy %q bans %q, which this scanner cannot probe, so "+
					"every evaluation of it carries a rule that was never tested", name, banned)
			}
		}
	}
}
