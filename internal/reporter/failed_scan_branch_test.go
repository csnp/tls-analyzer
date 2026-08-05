package reporter

import (
	"bytes"
	"strings"
	"testing"
)

// TestAnErrorThatScrubsToEmptyIsStillATargetThatWasNeverScanned
//
// Report decides whether the scan failed, and renders from a scrubbed copy of
// the result. Those must be two different values. Scrubbing collapses control
// characters and trims, so an Error made only of them scrubs to empty; deciding
// on the copy sent a target that was never reached down the fully-graded path
// and printed a grade for it, which is the exact defect the branch exists to
// prevent, reintroduced by the scrubbing that fixed a different one.
//
// No real value reaches it today, because the error is built from err.Error()
// and always carries prose. It is pinned anyway: the rule is that a decision
// taken on a transformed value is a decision about a different value, and the
// next person to move that assignment should fail here rather than in a review.
func TestAnErrorThatScrubsToEmptyIsStillATargetThatWasNeverScanned(t *testing.T) {
	for _, tc := range []struct {
		name  string
		error string
	}{
		{"control bytes only", "\x01\x02\x03\x07"},
		{"whitespace only", "   \t  "},
		{"escape sequences only", "\x1b[2K\x1b[1A"},
		// Written as escape sequences rather than as raw bytes. The raw form is
		// invisible in a diff, in a review and in most editors, and it is the
		// same class this release converted twelve other fixtures away from
		// before leaving one behind in its own final commit.
		{"C1 controls only", "\u009b\u0085"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := hostileScanResult(t, shapeScanned)
			result.Error = tc.error

			var buf bytes.Buffer
			if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
				t.Fatalf("report failed: %v", err)
			}
			out := buf.String()

			if !strings.Contains(out, "NOT SCANNED") {
				t.Errorf("a result carrying an error rendered no NOT SCANNED block, so a "+
					"target that was never reached was reported as scanned (%d bytes)", len(out))
			}
			if strings.Contains(out, "OVERALL GRADE") {
				t.Error("a target that was never reached was given a graded report, which is " +
					"the defect the failed-scan branch exists to prevent")
			}
		})
	}
}

// TestAnOrdinaryScanIsStillGraded is the acceptance control for the test above.
//
// Deciding the branch on a value that is always non-empty would satisfy it and
// stop every real scan being reported, so the reproduction alone is not enough.
func TestAnOrdinaryScanIsStillGraded(t *testing.T) {
	result := hostileScanResult(t, shapeScanned)

	var buf bytes.Buffer
	if err := (&TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "OVERALL GRADE") {
		t.Error("a result with no error did not render a grade, so the failed-scan branch " +
			"is now taken for every scan")
	}
	if strings.Contains(out, "NOT SCANNED") {
		t.Error("a result with no error rendered the NOT SCANNED block")
	}
}
