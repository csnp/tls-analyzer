package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Two defects in the CNSA 2.0 timeline section of the text report, which the
// HTML page shares:
//
// Run on 2026-10-18, the timeline printed "○ in progress: Preparation Phase
// (2025-12-31)" under "Current Phase: New NSS Systems". The analyzer marks that
// milestone in progress whenever a scan runs, and nothing said its deadline had
// passed.
//
// "Algorithm Status" printed one line per finding, and the analyzer makes one
// symmetric finding per cipher suite, so a server with 17 AES suites printed
// "[approved    ] symmetric: AES" 8 times and "[transitional] symmetric: AES"
// 9 times, with nothing to tell the lines apart.
//
// The mutation each test is written to catch:
//   - no word for a passed deadline, as before this change, in either format:
//     TestAMilestonePastItsDeadlineSaysSo.
//   - the deadline compared with the clock instead of the assessment date: the
//     control subtest whose assessment date is before the deadline.
//   - a timeline without an assessment date, or a milestone without a
//     deadline, said to be past its deadline: the other two control subtests.
//   - one line per finding, as before this change, in either format:
//     TestRepeatedAlgorithmStatusLinesAreCountedOnce.
//   - findings that differ in their status or replacement folded together: the
//     same test, whose approved and transitional AES lines must stay apart.

// timelineResult is fullResult with the timeline replaced by one assessed on
// 2026-10-18, the date of the report.
func timelineResult(milestones []types.CNSA2Milestone, findings []types.CNSA2Finding) *types.ScanResult {
	result := fullResult()
	result.CNSA2Timeline.AssessmentDate = time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	result.CNSA2Timeline.CurrentPhase = "New NSS Systems"
	result.CNSA2Timeline.Milestones = milestones
	if findings != nil {
		result.CNSA2Timeline.Findings = findings
	}
	return result
}

func textReport(t *testing.T, result *types.ScanResult) string {
	t.Helper()
	return render(t, &TextReporter{NoColor: true}, result)
}

// TestAMilestonePastItsDeadlineSaysSo is the reproduction of the first defect,
// with the milestones the analyzer produced on 2026-10-18 and two more for a
// met and an unmet milestone whose deadline has passed.
func TestAMilestonePastItsDeadlineSaysSo(t *testing.T) {
	milestones := []types.CNSA2Milestone{
		{Name: "Preparation Phase", Status: "in-progress",
			Deadline: time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)},
		{Name: "Met before the deadline", Status: "compliant",
			Deadline: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Name: "Missed deadline", Status: "non-compliant",
			Deadline: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		{Name: "New NSS Systems", Status: "partial",
			Deadline: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	cases := []struct {
		name string
		text string // the whole milestone line in the text report
		html string // the end of the page's mark and the name after it
	}{
		{"Preparation Phase", "○ in progress, deadline passed: Preparation Phase (2025-12-31)",
			"in progress, deadline passed</span>: Preparation Phase"},
		{"Met before the deadline", "✓ met: Met before the deadline (2026-01-01)",
			"met</span>: Met before the deadline"},
		{"Missed deadline", "✗ not met, deadline passed: Missed deadline (2026-06-01)",
			"not met, deadline passed</span>: Missed deadline"},
		{"New NSS Systems", "◐ partial: New NSS Systems (2027-01-01)",
			"partial</span>: New NSS Systems"},
	}

	result := timelineResult(milestones, nil)
	text := textReport(t, result)
	page := htmlSection(t, render(t, &HTMLReporter{}, result), "cnsa2-timeline")
	for _, tc := range cases {
		if got := strings.TrimSpace(lineContaining(t, text, tc.name+" (")); got != tc.text {
			t.Errorf("text milestone line = %q, want %q", got, tc.text)
		}
		if !strings.Contains(page, tc.html) {
			t.Errorf("the HTML page does not draw %q as %q:\n%s", tc.name, tc.html, page)
		}
	}

	// The deadline is compared with the assessment date the timeline carries,
	// not with the clock of whoever renders it, so a saved result reads the same
	// later. A timeline with no assessment date says nothing about deadlines.
	t.Run("control: a deadline after the assessment date has not passed", func(t *testing.T) {
		result := timelineResult(milestones, nil)
		result.CNSA2Timeline.AssessmentDate = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
		if got := lineContaining(t, textReport(t, result), "Preparation Phase ("); strings.Contains(got, "passed") {
			t.Errorf("a deadline after the assessment date is reported as passed: %q", got)
		}
	})
	t.Run("control: no assessment date", func(t *testing.T) {
		result := timelineResult(milestones, nil)
		result.CNSA2Timeline.AssessmentDate = time.Time{}
		text := textReport(t, result)
		page := render(t, &HTMLReporter{}, result)
		if strings.Contains(text, "deadline passed") || strings.Contains(page, "deadline passed") {
			t.Error("a timeline without an assessment date reports a deadline as passed")
		}
	})
	t.Run("control: a milestone without a deadline", func(t *testing.T) {
		result := timelineResult([]types.CNSA2Milestone{{Name: "No deadline", Status: "in-progress"}}, nil)
		if got := lineContaining(t, textReport(t, result), "No deadline ("); strings.Contains(got, "passed") {
			t.Errorf("a milestone without a deadline is reported as past it: %q", got)
		}
	})
}

// TestRepeatedAlgorithmStatusLinesAreCountedOnce is the reproduction of the
// second defect, with the findings of the report: 8 approved and 9
// transitional AES suites, and one ChaCha20 suite.
func TestRepeatedAlgorithmStatusLinesAreCountedOnce(t *testing.T) {
	var findings []types.CNSA2Finding
	for i := 0; i < 8; i++ {
		findings = append(findings, types.CNSA2Finding{Category: "symmetric", Algorithm: "AES",
			Status: "approved"})
	}
	findings = append(findings, types.CNSA2Finding{Category: "symmetric", Algorithm: "ChaCha20",
		Status: "approved"})
	for i := 0; i < 9; i++ {
		findings = append(findings, types.CNSA2Finding{Category: "symmetric", Algorithm: "AES",
			Status: "transitional", Deadline: "2030", Replacement: "AES-256"})
	}
	// The analyzer repeats no other finding, so a repeat of one is counted as
	// findings rather than as cipher suites, and its replacement is kept.
	for i := 0; i < 2; i++ {
		findings = append(findings, types.CNSA2Finding{Category: "signature-key", Algorithm: "RSA",
			Status: "deprecated", Replacement: "ML-DSA certificates (when available)"})
	}
	result := timelineResult(nil, findings)

	text := textReport(t, result)
	if n := strings.Count(text, "symmetric: AES"); n != 2 {
		t.Errorf("the text report prints %d AES lines, want 2, one per status:\n%s", n, text)
	}
	for _, want := range []string{
		"[approved    ] symmetric: AES (8 cipher suites)\n",
		"[approved    ] symmetric: ChaCha20\n",
		"[transitional] symmetric: AES (9 cipher suites)\n",
		"[deprecated  ] signature-key: RSA (2 findings)\n" +
			"               Replace with: ML-DSA certificates (when available)\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text report does not print %q:\n%s", strings.TrimSpace(want), text)
		}
	}

	page := htmlSection(t, render(t, &HTMLReporter{}, result), "cnsa2-timeline")
	if n := strings.Count(page, "symmetric, AES"); n != 2 {
		t.Errorf("the HTML page lists %d AES items, want 2, one per status:\n%s", n, page)
	}
	for _, want := range []string{
		"approved</span>: symmetric, AES (8 cipher suites)</li>",
		"approved</span>: symmetric, ChaCha20</li>",
		"transitional</span>: symmetric, AES (9 cipher suites)</li>",
		"deprecated</span>: signature-key, RSA (2 findings). Replace with ML-DSA certificates (when available)</li>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the HTML page does not list %q:\n%s", want, page)
		}
	}
}
