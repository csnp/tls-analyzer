package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names QuantumRiskAssessment.Assessed, which did not exist before,
// so it cannot compile against the pre-fix sources. It holds the acceptance
// controls for the guards asserted in unmeasured_quantum_test.go: a fix that
// suppressed the quantum output unconditionally would satisfy every negative
// assertion over there and would delete the tool's main result.

func assessedResult() *types.ScanResult {
	r := unassessedResult()
	r.QuantumRisk = types.QuantumRiskAssessment{
		Assessed:        true,
		Score:           20,
		Level:           types.RiskHigh,
		KeyExchangeRisk: "HIGH - classical key exchange",
		CertificateRisk: "HIGH - classical signature",
		HNDLRisk:        "HIGH",
		TimeToAction:    "IMMEDIATE",
		Details:         []string{"Key exchange is classical"},
	}
	r.Grade.QuantumGrade = "QV"
	r.Grade.SkippedDimensions = nil
	return r
}

// TestEverySurfaceRendersAQuantumVerdictThatWasMeasured is the acceptance
// control. Guards that suppress the section unconditionally would satisfy every
// case above and would delete the tool's main output.
func TestEverySurfaceRendersAQuantumVerdictThatWasMeasured(t *testing.T) {
	result := assessedResult()

	t.Run("sarif", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&SARIFReporter{}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		if !strings.Contains(buf.String(), "QUANTUM_VULNERABLE") {
			t.Fatal("SARIF omits QUANTUM_VULNERABLE for a measured score of 20")
		}
	})

	t.Run("html", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&HTMLReporter{}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "quantum-metric-label\">Risk Level") {
			t.Fatal("HTML omits the quantum metrics for a measured assessment")
		}
		if !strings.Contains(out, "20/100") {
			t.Fatal("HTML omits the measured quantum score")
		}
	})

	t.Run("text", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		if !strings.Contains(buf.String(), "QUANTUM RISK ASSESSMENT") {
			t.Fatal("text report omits the quantum section for a measured assessment")
		}
	})
}

// TestEverySurfaceRendersAMeasuredWorstCase is the case that discriminates, fed
// to every surface rather than to one.
//
// {Assessed: true, Score: 0} is the only input that tells "the assessment ran
// and the result is the worst possible" from "the assessment never ran". Until
// 0.4.1 it was fed to the JSON reporter alone, and the consequence was
// measurable: adding `result.QuantumRisk.Score > 0 &&` to both SARIF guards
// suppressed the QUANTUM_VULNERABLE rule and result for a host measured at zero,
// the worst score there is, and the whole suite stayed green. A surviving
// mutation means the distinction is untested, not that it is unnecessary.
//
// A measured zero is not exotic: it is what a server offering only classical key
// exchange with a classical certificate scores.
func TestEverySurfaceRendersAMeasuredWorstCase(t *testing.T) {
	worst := assessedResult()
	worst.QuantumRisk.Score = 0
	worst.QuantumRisk.Level = types.RiskCritical
	worst.Grade.QuantumGrade = "QV"

	t.Run("sarif", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&SARIFReporter{}).Report(&buf, worst); err != nil {
			t.Fatalf("report: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "QUANTUM_VULNERABLE") {
			t.Fatalf("SARIF omits QUANTUM_VULNERABLE for a MEASURED score of 0, the worst "+
				"result there is, in the format a CI system acts on:\n%s", out)
		}
		// A rule with no result and a result with no rule are both invalid SARIF,
		// so both guards have to agree. Suppressing one of the two was exactly
		// what the surviving mutation did.
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID string `json:"id"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID string `json:"ruleId"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("SARIF is not valid JSON: %v", err)
		}
		var hasRule, hasResult bool
		for _, r := range doc.Runs[0].Tool.Driver.Rules {
			if r.ID == "QUANTUM_VULNERABLE" {
				hasRule = true
			}
		}
		for _, r := range doc.Runs[0].Results {
			if r.RuleID == "QUANTUM_VULNERABLE" {
				hasResult = true
			}
		}
		if hasRule != hasResult {
			t.Errorf("SARIF emits the QUANTUM_VULNERABLE rule=%v and result=%v; a rule with "+
				"no result and a result with no rule are both invalid", hasRule, hasResult)
		}
	})

	t.Run("html", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&HTMLReporter{}).Report(&buf, worst); err != nil {
			t.Fatalf("report: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "quantum-metric-label\">Risk Level") {
			t.Fatal("HTML omits the quantum metrics for a measured score of 0")
		}
		if !strings.Contains(out, "0/100") {
			t.Fatal("HTML omits the measured quantum score of 0")
		}
	})

	t.Run("text", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&TextReporter{NoColor: true}).Report(&buf, worst); err != nil {
			t.Fatalf("report: %v", err)
		}
		if !strings.Contains(buf.String(), "QUANTUM RISK ASSESSMENT") {
			t.Fatal("text report omits the quantum section for a measured score of 0")
		}
	})

	t.Run("cbom", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&CBOMReporter{}).Report(&buf, worst); err != nil {
			t.Fatalf("report: %v", err)
		}
		// CBOM is an inventory rather than a verdict, so it carries no quantum
		// grade. What it must not do is decline to inventory the host because the
		// score was zero.
		var doc struct {
			Components []any `json:"components"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("CBOM is not valid JSON: %v", err)
		}
		if len(doc.Components) == 0 {
			t.Fatal("CBOM inventories nothing for a host that was scanned and measured")
		}
	})
}

// TestJSONDistinguishesAnUnmeasuredAssessmentFromAMeasuredZero is what lets a
// consumer of the tool's own output tell the two apart. Without it, decoding
// score 0 gives no way to know whether the scan looked.
func TestJSONDistinguishesAnUnmeasuredAssessmentFromAMeasuredZero(t *testing.T) {
	decode := func(t *testing.T, result *types.ScanResult) (bool, int, string) {
		t.Helper()
		var buf bytes.Buffer
		if err := (&JSONReporter{}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		var doc struct {
			QuantumRisk struct {
				Assessed bool `json:"assessed"`
				Score    int  `json:"score"`
			} `json:"quantumRisk"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return doc.QuantumRisk.Assessed, doc.QuantumRisk.Score, buf.String()
	}

	unmeasured := unassessedResult()
	assessed, score, raw := decode(t, unmeasured)
	if assessed {
		t.Error("JSON reports an assessment that never ran as having run")
	}
	if score != 0 {
		t.Errorf("unmeasured score = %d, want the zero value", score)
	}
	if !strings.Contains(raw, `"assessed"`) {
		t.Fatal("JSON omits the assessed flag, so a consumer decoding score 0 " +
			"cannot tell an unmeasured assessment from a measured worst case")
	}

	// The measured worst case has to be distinguishable from it, and the only
	// thing that distinguishes them is the flag.
	worst := assessedResult()
	worst.QuantumRisk.Score = 0
	assessed, score, _ = decode(t, worst)
	if !assessed {
		t.Error("JSON reports a measured assessment as not having run")
	}
	if score != 0 {
		t.Errorf("measured worst-case score = %d, want 0", score)
	}
}
