package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// policyReport renders a report and returns only the policy section.
//
// The whole report carries a not-comparable label of its own on the grade
// headline whenever a dimension was skipped, so an assertion against the full
// document would match that instead and pass for the wrong reason.
func policyReport(t *testing.T, pr *types.PolicyResult) string {
	t.Helper()
	result := unassessedResult()
	result.PolicyResult = pr

	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}

	out := buf.String()
	start := strings.Index(out, "POLICY EVALUATION")
	if start < 0 {
		t.Fatalf("no policy section in the report:\n%s", out)
	}
	section := out[start:]
	if end := strings.Index(section, "CNSA 2.0 COMPLIANCE TIMELINE"); end > 0 {
		section = section[:end]
	}
	if end := strings.Index(section, "SCAN COVERAGE"); end > 0 {
		section = section[:end]
	}
	return section
}

func completeVerdict() *types.PolicyResult {
	return &types.PolicyResult{
		PolicyName: "cnsa-2.0-2035",
		Compliant:  false,
		Complete:   true,
		Score:      55,
		Violations: []types.PolicyViolation{{
			Rule:        "cipher.minKeySize",
			Severity:    types.SeverityHigh,
			Description: "Cipher suite key size below minimum",
			Expected:    ">= 256 bits",
			Actual:      "128 bits (TLS_AES_128_GCM_SHA256)",
			Remediation: "Remove TLS_AES_128_GCM_SHA256, use cipher with >= 256-bit key",
		}},
		Warnings: []types.PolicyViolation{{
			Rule:        "quantum.requirePqcCertificates",
			Severity:    types.SeverityMedium,
			Description: "PQC certificate required (future requirement)",
			Remediation: "Plan migration to PQC certificates when available from CAs",
		}},
	}
}

// TestPolicyVerdictCarriesTheRemediationJSONAlreadyHad pins the fix text in the
// default output. Every violation named a problem and no fix, while the same
// evaluation carried a remediation string in --format json all along, so the
// format most users see was the one with the dead ends.
func TestPolicyVerdictCarriesTheRemediationJSONAlreadyHad(t *testing.T) {
	out := policyReport(t, completeVerdict())

	if !strings.Contains(out, "Remove TLS_AES_128_GCM_SHA256") {
		t.Errorf("the violation's remediation is missing from the text report:\n%s", out)
	}
	if !strings.Contains(out, "Plan migration to PQC certificates") {
		t.Errorf("the warning's remediation is missing from the text report:\n%s", out)
	}
}

// TestPolicyVerdictLabelsAnIncompleteEvaluation requires the label beside both
// numbers a reader acts on, not only in a list further down the report.
func TestPolicyVerdictLabelsAnIncompleteEvaluation(t *testing.T) {
	pr := completeVerdict()
	pr.Complete = false
	pr.SkippedRules = []types.SkippedPolicyRule{{
		Rule:   "quantum.minQuantumScore",
		Reason: "the quantum risk assessment did not run in this scan",
	}}

	out := policyReport(t, pr)

	status := lineContaining(t, out, "Status:")
	if !strings.Contains(status, "not comparable") {
		t.Errorf("status line = %q, want the not-comparable label", status)
	}
	score := lineContaining(t, out, "Score:")
	if !strings.Contains(score, "not comparable") {
		t.Errorf("score line = %q, want the not-comparable label. The score is computed by "+
			"deducting from 100, so a rule that was not evaluated could only have raised it.",
			score)
	}

	if !strings.Contains(out, "Not evaluated") {
		t.Errorf("the report does not list the rules that were not evaluated:\n%s", out)
	}
	if !strings.Contains(out, "quantum.minQuantumScore") {
		t.Errorf("the skipped rule is not named:\n%s", out)
	}
	if !strings.Contains(out, "did not run in this scan") {
		t.Errorf("the reason the rule was skipped is not printed:\n%s", out)
	}
}

// TestPolicyVerdictDoesNotLabelACompleteEvaluation is the acceptance control. A
// label printed on every report is a label nobody reads.
func TestPolicyVerdictDoesNotLabelACompleteEvaluation(t *testing.T) {
	out := policyReport(t, completeVerdict())

	if strings.Contains(out, "not comparable") {
		t.Errorf("a complete evaluation is labelled not comparable:\n%s", out)
	}
	if strings.Contains(out, "Not evaluated") {
		t.Errorf("a complete evaluation lists rules as not evaluated:\n%s", out)
	}
}

func lineContaining(t *testing.T, report, needle string) string {
	t.Helper()
	for _, line := range strings.Split(report, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no line containing %q in:\n%s", needle, report)
	return ""
}
