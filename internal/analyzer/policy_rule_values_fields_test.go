package analyzer

import (
	"testing"
)

// This file names identifiers that did not exist before the fix, so it cannot
// build against the sources before the fix.
//
// The second half of that claim, that policy_rule_values_test.go does build
// there and fails on behaviour, is false: measured in 0.4.1, it does not build
// there either, because 0.4.0 landed as one squashed commit and every part of it
// arrived at once. See docs/testing/red-proof.md.

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
