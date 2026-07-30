package scanner

import (
	"encoding/json"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The assertions in this file name fields added by the score-reconciliation fix,
// so they cannot compile against the code as it was before it. They are kept
// apart from grade_reconciliation_test.go for that reason: the behavioural test
// there must stay buildable against the old sources so it fails at runtime on
// the missing output rather than failing to build, which proves nothing.

// TestGradeRecordsThePenaltyItemisation checks the accounting behind the printed
// breakdown, so a formatter change cannot quietly stop the numbers agreeing.
func TestGradeRecordsThePenaltyItemisation(t *testing.T) {
	grade := New(nil).calculateGrade(penalisedResult())

	if grade.DimensionMaxPoints != 100 {
		t.Errorf("expected all four dimensions to be assessed (100 available points), got %d",
			grade.DimensionMaxPoints)
	}
	if grade.DimensionPoints != 100 || grade.DimensionScore != 100 {
		t.Errorf("expected 100 of 100 dimension points and a subtotal of 100, got %d points and %d",
			grade.DimensionPoints, grade.DimensionScore)
	}

	// HIGH x 1 at 15 points, MEDIUM x 2 at 5 points each.
	if grade.VulnerabilityPenalty != 25 {
		t.Errorf("expected a penalty of 25 (1 HIGH x 15 + 2 MEDIUM x 5), got %d",
			grade.VulnerabilityPenalty)
	}

	if grade.Score != grade.DimensionScore-grade.VulnerabilityPenalty {
		t.Errorf("the score (%d) is not the subtotal (%d) less the penalty (%d)",
			grade.Score, grade.DimensionScore, grade.VulnerabilityPenalty)
	}

	itemised := 0
	for _, penalty := range grade.Penalties {
		if penalty.PointsTotal != penalty.Count*penalty.PointsEach {
			t.Errorf("%s itemisation is inconsistent: %d x %d recorded as %d",
				penalty.Severity, penalty.Count, penalty.PointsEach, penalty.PointsTotal)
		}
		itemised += penalty.PointsTotal
	}
	if itemised != grade.VulnerabilityPenalty {
		t.Errorf("the itemised penalties total %d but the recorded penalty is %d",
			itemised, grade.VulnerabilityPenalty)
	}

	if !grade.VulnerabilitiesAssessed {
		t.Error("a scan that ran the vulnerability checks is recorded as not having assessed them")
	}
	if grade.PenaltyFloored {
		t.Error("a penalty smaller than the subtotal is recorded as floored")
	}
}

// TestGradeRecordsWhenThePenaltyIsFloored covers the case where the deduction
// exceeds the dimension subtotal. The printed arithmetic cannot close there, so
// the report has to say why rather than leave a reader to find the discrepancy.
func TestGradeRecordsWhenThePenaltyIsFloored(t *testing.T) {
	result := penalisedResult()
	result.Vulnerabilities = []types.Vulnerability{
		{ID: "C1", Severity: types.SeverityCritical},
		{ID: "C2", Severity: types.SeverityCritical},
		{ID: "C3", Severity: types.SeverityCritical},
		{ID: "C4", Severity: types.SeverityCritical},
	}

	grade := New(nil).calculateGrade(result)

	if grade.VulnerabilityPenalty != 120 {
		t.Errorf("expected a penalty of 120 (4 CRITICAL x 30), got %d", grade.VulnerabilityPenalty)
	}
	if grade.Score != 0 {
		t.Errorf("expected the score to be held at 0, got %d", grade.Score)
	}
	if !grade.PenaltyFloored {
		t.Error("a penalty larger than the subtotal is not recorded as floored, so the " +
			"printed subtotal minus the printed penalty will not equal the printed score " +
			"and nothing explains it")
	}
}

// TestGradeExcludesASkippedDimensionFromTheDenominator confirms the accounting
// the 0.3.0 --skip-quantum fix introduced is now visible to a reader, since four
// dimensions worth 25 each do not total 100 when one of them did not run.
func TestGradeExcludesASkippedDimensionFromTheDenominator(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CheckQuantum = false

	grade := New(cfg).calculateGrade(penalisedResult())

	if grade.DimensionMaxPoints != 75 {
		t.Errorf("expected 75 available points with the quantum dimension skipped, got %d",
			grade.DimensionMaxPoints)
	}
	if grade.DimensionScore != 100 {
		t.Errorf("expected 75 of 75 points to normalise to 100, got %d", grade.DimensionScore)
	}
	if len(grade.Factors) != 3 {
		t.Errorf("expected 3 dimension factors with the quantum dimension skipped, got %d",
			len(grade.Factors))
	}
}

// TestGradeMarksUnassessedVulnerabilities keeps the machine-readable formats in
// step with the text report: a consumer joining on the score needs to know the
// penalty was unmeasured rather than zero.
func TestGradeMarksUnassessedVulnerabilities(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CheckVulns = false

	result := penalisedResult()
	result.Vulnerabilities = nil
	result.Grade = New(cfg).calculateGrade(result)

	if result.Grade.VulnerabilitiesAssessed {
		t.Error("a scan run with the vulnerability checks disabled is recorded as having assessed them")
	}

	encoded, err := json.Marshal(result.Grade)
	if err != nil {
		t.Fatalf("marshalling the grade failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshalling the grade failed: %v", err)
	}

	for _, field := range []string{"dimensionScore", "vulnerabilityPenalty", "vulnerabilitiesAssessed"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("the JSON grade omits %q, so a machine consumer cannot reconcile the score either", field)
		}
	}
	if decoded["vulnerabilitiesAssessed"] != false {
		t.Errorf("expected vulnerabilitiesAssessed to be false in JSON, got %v",
			decoded["vulnerabilitiesAssessed"])
	}
}
