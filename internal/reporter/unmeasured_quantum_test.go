package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// A scan that declined to assess quantum readiness leaves a zero-valued
// assessment, and 0 is a legal score. Four consumers read it as one:
//
//   - the policy evaluator raised "[HIGH] Quantum readiness score below
//     minimum, Expected: >= 90 | Actual: 0" in the same report that printed
//     "Quantum Ready: not assessed";
//   - the SARIF reporter emitted a QUANTUM_VULNERABLE finding with an empty
//     message, into the format a CI system acts on;
//   - the HTML report drew a Quantum Risk Assessment section with an empty risk
//     level badge styled as low risk and a score of 0 out of 100;
//   - the text report and the grade were already guarded, which is what made
//     the other three easy to miss.
//
// This test asserts across every output format at once, so a surface added
// later that reads Score without reading Assessed fails here rather than in a
// release test.
//
// The file names nothing that did not already exist, so it compiles against the
// pre-fix sources and fails there. The acceptance controls, which have to state
// that an assessment DID run, are in unmeasured_quantum_fields_test.go.

func unassessedResult() *types.ScanResult {
	return &types.ScanResult{
		Target:    "example.com",
		Host:      "example.com",
		Port:      443,
		Timestamp: time.Now(),
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
		},
		CipherSuites: []types.CipherSuite{
			{ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", Protocol: "TLS 1.3",
				Encryption: "AES", Bits: 256, ForwardSecrecy: true},
		},
		Certificate: healthyCert(),
		// The zero value: never assessed, so every field is unmeasured.
		QuantumRisk: types.QuantumRiskAssessment{},
		Grade: types.Grade{
			Letter:                  "B",
			Score:                   80,
			QuantumGrade:            types.QuantumGradeNotAssessed,
			SkippedDimensions:       []string{"Quantum Readiness"},
			VulnerabilitiesAssessed: true,
			Factors: []types.GradeFactor{
				{Category: "Protocol Support", Score: 25, MaxScore: 25, Details: "TLS 1.3 only"},
			},
		},
		ScanWarnings: []string{"quantum risk assessment was skipped and is excluded from the grade"},
	}
}

// TestNoSurfaceRendersAQuantumVerdictThatWasNotMeasured is the negative half.
func TestNoSurfaceRendersAQuantumVerdictThatWasNotMeasured(t *testing.T) {
	result := unassessedResult()

	t.Run("sarif", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&SARIFReporter{}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("SARIF is not valid JSON: %v", err)
		}
		if strings.Contains(buf.String(), "QUANTUM_VULNERABLE") {
			t.Fatalf("SARIF publishes a QUANTUM_VULNERABLE finding for an assessment that "+
				"never ran, into the format a CI system acts on:\n%s", buf.String())
		}
	})

	t.Run("html", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&HTMLReporter{}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		out := buf.String()
		// The class has to be matched where it is applied to an element, not
		// where it is defined in the stylesheet, which is present on every page.
		if strings.Contains(out, `class="badge risk-low"`) {
			t.Fatalf("HTML styles an unmeasured risk level as low risk:\n%s", quantumSection(out))
		}
		if strings.Contains(out, "quantum-metric-label\">Risk Level") {
			t.Fatalf("HTML draws the quantum metrics from an assessment that never ran:\n%s",
				quantumSection(out))
		}
		if !strings.Contains(out, "did not assess quantum readiness") {
			t.Fatal("HTML omits the quantum section without saying it was not assessed, " +
				"which reads as a report that had nothing to say rather than one that did not look")
		}
	})

	t.Run("text", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
			t.Fatalf("report: %v", err)
		}
		if strings.Contains(buf.String(), "QUANTUM RISK ASSESSMENT") {
			t.Fatalf("text report prints a quantum section for an assessment that never ran:\n%s",
				buf.String())
		}
	})

}

// TestRiskClassDoesNotDefaultToReassuring pins the polarity of the helper that
// styled the empty risk level green. A level the function does not recognise is
// an unknown risk, not a low one.
func TestRiskClassDoesNotDefaultToReassuring(t *testing.T) {
	known := map[types.RiskLevel]string{
		types.RiskCritical: "risk-critical",
		types.RiskHigh:     "risk-high",
		types.RiskMedium:   "risk-medium",
		types.RiskLow:      "risk-low",
	}
	for level, want := range known {
		if got := riskClass(level); got != want {
			t.Errorf("riskClass(%q) = %q, want %q", level, got, want)
		}
	}

	for _, unknown := range []types.RiskLevel{"", "UNKNOWN", "severe", "low"} {
		if got := riskClass(unknown); got == "risk-low" {
			t.Errorf("riskClass(%q) = %q: an unrecognised level is styled as the best "+
				"possible outcome", unknown, got)
		}
	}
}

func quantumSection(doc string) string {
	i := strings.Index(doc, "Quantum Risk Assessment")
	if i < 0 {
		return "(no quantum section)"
	}
	end := i + 1200
	if end > len(doc) {
		end = len(doc)
	}
	return doc[i:end]
}
