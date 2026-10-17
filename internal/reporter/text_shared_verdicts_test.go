package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The text report worded its own policy status and drew its own milestone
// marks, while the HTML page, SARIF and CBOM took theirs from verdict_marks.go.
// An evaluation that skipped a rule and found no violation was headed
// "✓ COMPLIANT" in the text report, beside a note that a rule was not
// evaluated, while the page headed the same result "? COMPLIANCE NOT
// ESTABLISHED" and SARIF and CBOM carried "compliance not established". A
// milestone status the text report did not list was drawn with the green check
// the page keeps for "met".

// TestTextHeadsAPolicyEvaluationAsTheHTMLPageDoes compares the text report's
// Status line with the words the HTML page heads the same result with.
func TestTextHeadsAPolicyEvaluationAsTheHTMLPageDoes(t *testing.T) {
	incompleteWithViolation := hybridVerdict()
	incompleteWithViolation.Complete = false
	incompleteWithViolation.SkippedRules = incompleteVerdict().SkippedRules

	cases := []struct {
		name  string
		pr    *types.PolicyResult
		glyph string
		label string
	}{
		{"a rule skipped and no violation", incompleteVerdict(), "?", "COMPLIANCE NOT ESTABLISHED"},
		{"a rule skipped and a violation", incompleteWithViolation, "✗", "NON-COMPLIANT"},
		{"complete with a violation", hybridVerdict(), "✗", "NON-COMPLIANT"},
		{"control: complete with no violation", compliantVerdict(), "✓", "COMPLIANT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := lineContaining(t, policyReport(t, tc.pr), "Status:")
			if want := tc.glyph + " " + tc.label; !strings.Contains(status, want) {
				t.Errorf("text status line = %q, want it to carry %q", status, want)
			}
			if !tc.pr.Complete {
				if strings.Contains(status, "✓") {
					t.Errorf("an evaluation that skipped a rule is given a pass mark: %q", status)
				}
				if m := standaloneCompliant.FindString(status); m != "" {
					t.Errorf("an evaluation that skipped a rule is called compliant (%q): %q", m, status)
				}
			}

			page := htmlSection(t, render(t, &HTMLReporter{}, withPolicy(tc.pr)), "policy")
			if !strings.Contains(page, tc.label) {
				t.Errorf("the HTML page does not head this result %q either, so this case no "+
					"longer compares the two formats:\n%s", tc.label, page)
			}
		})
	}
}

// TestTextDrawsMilestonesAsTheHTMLPageDoes renders one milestone of each status
// the legend lists and one status it does not, and requires the text report to
// draw each with the page's mark and words.
func TestTextDrawsMilestonesAsTheHTMLPageDoes(t *testing.T) {
	cases := []struct {
		status string
		text   string // the whole milestone line in the text report
		html   string // the end of the page's mark and the name after it
	}{
		{"compliant", "✓ met: M-compliant (2027-01-01)", "met</span>: M-compliant"},
		{"partial", "◐ partial: M-partial (2027-01-01)", "partial</span>: M-partial"},
		{"in-progress", "○ in progress: M-in-progress (2027-01-01)", "in progress</span>: M-in-progress"},
		{"non-compliant", "✗ not met: M-non-compliant (2027-01-01)", "not met</span>: M-non-compliant"},
		{"not-applicable", "— not yet required: M-not-applicable (2027-01-01)",
			"not yet required</span>: M-not-applicable"},
		// A status the legend does not list has no symbol: it is its own word.
		{"undetermined", "undetermined: M-undetermined (2027-01-01)", "undetermined</span>: M-undetermined"},
	}

	result := fullResult()
	result.CNSA2Timeline.Milestones = nil
	for _, tc := range cases {
		result.CNSA2Timeline.Milestones = append(result.CNSA2Timeline.Milestones, types.CNSA2Milestone{
			Name: "M-" + tc.status, Status: tc.status,
			Deadline: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		})
	}

	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}
	text := buf.String()
	page := htmlSection(t, render(t, &HTMLReporter{}, result), "cnsa2-timeline")

	for _, tc := range cases {
		got := strings.TrimSpace(lineContaining(t, text, "M-"+tc.status+" "))
		if got != tc.text {
			t.Errorf("text milestone line for %q = %q, want %q", tc.status, got, tc.text)
		}
		if !strings.Contains(page, tc.html) {
			t.Errorf("the HTML page does not draw %q as %q either, so this case no longer "+
				"compares the two formats:\n%s", tc.status, tc.html, page)
		}
	}

	legend := lineContaining(t, text, "legend:")
	if want := "legend: ✓ met, ◐ partial, ○ in progress, ✗ not met, — not yet required"; strings.TrimSpace(legend) != want {
		t.Errorf("text legend = %q, want %q", strings.TrimSpace(legend), want)
	}
}
