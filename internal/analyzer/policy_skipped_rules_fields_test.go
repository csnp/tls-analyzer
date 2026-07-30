package analyzer

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names QuantumRiskAssessment.Assessed, PolicyResult.SkippedRules and
// PolicyResult.Complete, none of which existed before, so it cannot compile
// against the pre-fix sources. The behavioural half is in
// policy_skipped_rules_test.go and does compile there, and fails.

func scanWithQuantumAssessment(score int) *types.ScanResult {
	r := scanWithoutQuantumAssessment()
	r.QuantumRisk = types.QuantumRiskAssessment{
		Assessed: true,
		Score:    score,
		Level:    types.RiskHigh,
	}
	return r
}

func findSkipped(pr *types.PolicyResult, rule string) *types.SkippedPolicyRule {
	for i := range pr.SkippedRules {
		if pr.SkippedRules[i].Rule == rule {
			return &pr.SkippedRules[i]
		}
	}
	return nil
}

// TestASkippedRuleIsRecordedWithItsReason requires the skip to be visible.
// Dropping the rule quietly would satisfy the behavioural test on its own and
// would leave a reader believing the whole policy had been evaluated.
func TestASkippedRuleIsRecordedWithItsReason(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, _ := e.GetPolicy("cnsa-2.0-2035")

	pr := e.Evaluate(scanWithoutQuantumAssessment(), policy)

	skipped := findSkipped(pr, "quantum.minQuantumScore")
	if skipped == nil {
		t.Fatalf("the rule was neither failed nor recorded as skipped, so nothing in the "+
			"result says it was not evaluated. Skipped rules: %+v", pr.SkippedRules)
	}
	if !strings.Contains(skipped.Reason, "--skip-quantum") {
		t.Errorf("skip reason = %q, want it to name the flag that caused it", skipped.Reason)
	}
	if pr.Complete {
		t.Error("the verdict claims to be a complete evaluation while a rule was skipped")
	}
}

// TestASkippedRuleDoesNotRaiseTheScoreSilently measures the laundering the skip
// introduces, so the disclosure cannot become decorative. The score is computed
// by deducting from 100, so a rule that is not evaluated cannot deduct, and the
// same host under the same policy scores higher for having been looked at less.
func TestASkippedRuleDoesNotRaiseTheScoreSilently(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, _ := e.GetPolicy("cnsa-2.0-2035")

	measured := e.Evaluate(scanWithQuantumAssessment(10), policy)
	skipped := e.Evaluate(scanWithoutQuantumAssessment(), policy)

	if skipped.Score <= measured.Score {
		t.Fatalf("skipped score %d is not above measured score %d, so this fixture no longer "+
			"demonstrates the raise the disclosure exists for and the assertion below "+
			"would pass for the wrong reason", skipped.Score, measured.Score)
	}
	if !measured.Complete {
		t.Error("a full evaluation is reported as incomplete")
	}
	if skipped.Complete {
		t.Errorf("the higher score (%d against %d) is reported as a complete evaluation",
			skipped.Score, measured.Score)
	}
}

// TestAMeasuredZeroIsStillAFailure is the case a naive fix breaks. A server can
// genuinely score 0 for quantum readiness, and that has to keep failing.
func TestAMeasuredZeroIsStillAFailure(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, _ := e.GetPolicy("cnsa-2.0-2035")

	pr := e.Evaluate(scanWithQuantumAssessment(0), policy)

	v := findViolation(pr, "quantum.minQuantumScore")
	if v == nil {
		t.Fatal("a measured quantum score of 0 did not fail a policy requiring 90. " +
			"Skipping unmeasured input must not also skip measured input.")
	}
	if v.Actual != "0" {
		t.Errorf("Actual = %q, want 0", v.Actual)
	}
	if findSkipped(pr, "quantum.minQuantumScore") != nil {
		t.Error("a measured rule was recorded as skipped")
	}
	if !pr.Complete {
		t.Error("an evaluation that skipped nothing is reported as incomplete")
	}
}

// TestAPolicyWithoutAQuantumMinimumSkipsNothing keeps the skip specific to the
// one rule that reads the unmeasured input.
func TestAPolicyWithoutAQuantumMinimumSkipsNothing(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, _ := e.GetPolicy("modern")
	if policy.Rules.Quantum.MinQuantumScore != 0 {
		t.Skip("modern now sets a minimum quantum score, so it is no longer this fixture")
	}

	pr := e.Evaluate(scanWithoutQuantumAssessment(), policy)

	if len(pr.SkippedRules) != 0 {
		t.Fatalf("rules were skipped for a policy that reads no unmeasured input: %+v",
			pr.SkippedRules)
	}
	if !pr.Complete {
		t.Fatal("an evaluation that skipped nothing is reported as incomplete")
	}
}
