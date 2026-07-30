package analyzer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/reporter"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// These tests assert on the rendered report, so they compile against the sources
// as they were before the scope fix and fail at runtime on the missing notes.

const textSeparator = "───────────────────────────────────────────────────────────────"

// hybridPQCWithWeakSuitesStillOffered is the configuration that produced two
// opposite CNSA 2.0 verdicts in one report: a hybrid ML-KEM group is available,
// which satisfies the timeline milestone, while 128-bit and non-forward-secret
// suites are also still accepted, which the policy counts as violations.
func hybridPQCWithWeakSuitesStillOffered() *types.ScanResult {
	return &types.ScanResult{
		Target: "mixed.example",
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true},
			{Version: "TLS 1.2", Supported: true},
		},
		KeyExchanges: []types.KeyExchange{
			{Name: "X25519MLKEM768", Type: "hybrid", PQCAlgorithm: "ML-KEM-768", QuantumSafe: true, Negotiated: true},
			{Name: "X25519", Type: "classical"},
		},
		CipherSuites: []types.CipherSuite{
			{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true, Encryption: "AES-GCM"},
			{Name: "TLS_AES_128_GCM_SHA256", Bits: 128, ForwardSecrecy: true, Encryption: "AES-GCM"},
			{Name: "TLS_RSA_WITH_AES_256_CBC_SHA", Bits: 256, ForwardSecrecy: false, KeyExchange: "RSA", Encryption: "AES-CBC"},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      256,
			SignatureAlgorithm: "ECDSA-SHA256",
			DaysUntilExpiry:    365,
		},
		QuantumRisk: types.QuantumRiskAssessment{Score: 65, Level: types.RiskMedium},
	}
}

func renderTextReport(t *testing.T, result *types.ScanResult) string {
	t.Helper()

	var buf bytes.Buffer
	if err := (&reporter.TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("rendering the text report failed: %v", err)
	}
	return buf.String()
}

// sectionBody returns the body of one report section, so an assertion about the
// policy verdict cannot be satisfied by text belonging to the timeline.
func sectionBody(t *testing.T, report, heading string) string {
	t.Helper()

	chunks := strings.Split(report, textSeparator)
	for i, chunk := range chunks {
		if strings.Contains(chunk, heading) && i+1 < len(chunks) {
			return chunks[i+1]
		}
	}

	t.Fatalf("the report has no %q section", heading)
	return ""
}

func findMilestone(t *testing.T, timeline *types.CNSA2Timeline, name string) types.CNSA2Milestone {
	t.Helper()

	for _, milestone := range timeline.Milestones {
		if milestone.Name == name {
			return milestone
		}
	}

	t.Fatalf("the timeline has no %q milestone", name)
	return types.CNSA2Milestone{}
}

// TestOppositeCNSA2VerdictsEachStateTheirScope guards the defect where one report
// answered the same question about the same standard and the same deadline twice,
// in opposite directions, with nothing to tell a reader why.
//
// "cnsa-2.0-2027: NON-COMPLIANT, 0/100, 16 violations" printed above
// "New NSS Systems (2027-01-01): compliant". Both are defensible, because they
// measure different things, so each verdict must say what it covers and point at
// the other.
func TestOppositeCNSA2VerdictsEachStateTheirScope(t *testing.T) {
	result := hybridPQCWithWeakSuitesStillOffered()

	timeline := NewCNSA2Analyzer().Analyze(result)
	result.CNSA2Timeline = timeline

	evaluator := NewPolicyEvaluator()
	policy, ok := evaluator.GetPolicy("cnsa-2.0-2027")
	if !ok {
		t.Fatal("the built-in cnsa-2.0-2027 policy is missing")
	}
	result.PolicyResult = evaluator.Evaluate(result, policy)

	// The fixture has to still produce the disagreement, or the assertions below
	// are checking scope notes on a report that no longer contradicts itself.
	milestone := findMilestone(t, timeline, "New NSS Systems")
	if milestone.Status != "compliant" {
		t.Fatalf("this fixture no longer demonstrates the defect: the New NSS Systems "+
			"milestone is %q rather than compliant, so there are no opposite verdicts to explain",
			milestone.Status)
	}
	if result.PolicyResult.Compliant {
		t.Fatalf("this fixture no longer demonstrates the defect: the cnsa-2.0-2027 policy " +
			"reports compliant, so it agrees with the milestone")
	}

	report := renderTextReport(t, result)
	policySection := sectionBody(t, report, "POLICY EVALUATION")
	timelineSection := sectionBody(t, report, "CNSA 2.0 COMPLIANCE TIMELINE")

	if !strings.Contains(policySection, "Scope:") {
		t.Error("the policy verdict states no scope, so a reader cannot tell why it " +
			"disagrees with the CNSA 2.0 timeline about the same deadline")
	}
	if !strings.Contains(timelineSection, "Scope:") {
		t.Error("the CNSA 2.0 timeline states no scope, so its compliant milestone " +
			"cannot be reconciled with a non-compliant policy verdict for the same year")
	}

	// Each note has to name the other analysis. A scope line that describes only
	// itself still leaves the reader with two answers and no way to relate them.
	if !strings.Contains(strings.ToLower(policySection), "timeline") {
		t.Error("the policy scope note does not refer to the CNSA 2.0 timeline section")
	}
	if !strings.Contains(strings.ToLower(timelineSection), "policy") {
		t.Error("the timeline scope note does not refer to the policy evaluation")
	}
}

// TestNewNSSMilestoneRequiresA256BitSuite guards the milestone reporting
// compliance against requirements it did not check.
//
// The milestone's own requirement list names AES-256, but an absent 256-bit suite
// recorded no gap at all, so a server offering only 128-bit encryption was
// reported compliant.
func TestNewNSSMilestoneRequiresA256BitSuite(t *testing.T) {
	result := hybridPQCWithWeakSuitesStillOffered()
	result.CipherSuites = []types.CipherSuite{
		{Name: "TLS_AES_128_GCM_SHA256", Bits: 128, ForwardSecrecy: true, Encryption: "AES-GCM"},
	}

	milestone := findMilestone(t, NewCNSA2Analyzer().Analyze(result), "New NSS Systems")

	if milestone.Status == "compliant" {
		t.Error("a server whose strongest cipher suite is 128-bit is reported compliant " +
			"against a milestone whose own requirements list AES-256 for symmetric encryption")
	}
	if len(milestone.Gap) == 0 {
		t.Error("no gap was recorded for the missing 256-bit suite, so the milestone " +
			"reports a verdict it did not derive from its own requirements")
	}

	// Acceptance control: the check must not simply always fail. With a 256-bit
	// suite present the same fixture has to reach compliant, or the assertion
	// above would pass for the wrong reason.
	withAES256 := hybridPQCWithWeakSuitesStillOffered()
	compliant := findMilestone(t, NewCNSA2Analyzer().Analyze(withAES256), "New NSS Systems")
	if compliant.Status != "compliant" {
		t.Errorf("a server offering a 256-bit suite and a hybrid ML-KEM group is reported %q, "+
			"so the milestone can no longer be met", compliant.Status)
	}
}

// TestReportKeysItsGlyphsAndQuantumGrades guards the defect where the milestone
// status glyphs and the Q / Q+ / Q- / QV quantum grades appeared with no key
// anywhere in the output or in --help, so a reader could not tell whether a given
// marker was a good result.
func TestReportKeysItsGlyphsAndQuantumGrades(t *testing.T) {
	result := hybridPQCWithWeakSuitesStillOffered()
	result.CNSA2Timeline = NewCNSA2Analyzer().Analyze(result)
	result.Grade = types.Grade{Letter: "B", Score: 75, QuantumGrade: "Q"}

	report := renderTextReport(t, result)

	timelineSection := sectionBody(t, report, "CNSA 2.0 COMPLIANCE TIMELINE")
	for _, want := range []string{"✓ met", "◐ partial", "✗ not met", "not yet required"} {
		if !strings.Contains(timelineSection, want) {
			t.Errorf("the milestone list has no key for %q, so the status glyphs beside each milestone are unexplained", want)
		}
	}

	gradeSection := sectionBody(t, report, "OVERALL GRADE")
	for _, want := range []string{"Q+", "Q-", "QV"} {
		if !strings.Contains(gradeSection, want) {
			t.Errorf("the grade block does not explain the %s quantum readiness grade", want)
		}
	}
}

// TestUnobservedCipherSuitesAreNotAMeasuredAbsence keeps the new gap from firing
// on a scan that enumerated no suites at all. An empty list is missing evidence,
// not evidence of weak encryption.
func TestUnobservedCipherSuitesAreNotAMeasuredAbsence(t *testing.T) {
	result := hybridPQCWithWeakSuitesStillOffered()
	result.CipherSuites = nil

	milestone := findMilestone(t, NewCNSA2Analyzer().Analyze(result), "New NSS Systems")

	for _, gap := range milestone.Gap {
		if strings.Contains(gap, "256-bit") {
			t.Errorf("a scan that observed no cipher suites reported %q, which turns "+
				"missing evidence into a measured failure", gap)
		}
	}
}
