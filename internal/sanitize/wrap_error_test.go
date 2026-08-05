package sanitize

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// WrapError has to do two things at once and a test that asserts only one of
// them passes against a wrapper that does the other. Both halves are pinned
// here, and the call sites are pinned separately in the packages that use it,
// because a helper that exists and is not applied is the shape of a fix that
// ships inert.

type gateSentinel struct{ message string }

func (e *gateSentinel) Error() string { return e.message }

// TestWrapErrorKeepsTheChain is the half the exit code depends on. main
// distinguishes a policy-gate failure (exit 2) from a scan failure (exit 1) with
// errors.As, so a wrapper that rebuilt the message with %s would silently change
// the exit code this tool's own CI guidance documents.
func TestWrapErrorKeepsTheChain(t *testing.T) {
	gate := &gateSentinel{message: "policy not satisfied by example.com"}
	wrapped := fmt.Errorf("scan failed: %w", WrapError(gate))

	var found *gateSentinel
	if !errors.As(wrapped, &found) {
		t.Fatal("errors.As no longer finds the wrapped error through the scrubber, " +
			"so a policy failure would exit 1 instead of 2")
	}
	if found.message != gate.message {
		t.Errorf("unwrapping produced a different error: %q", found.message)
	}
	if !errors.Is(wrapped, error(gate)) {
		t.Error("errors.Is no longer reaches the original error")
	}
}

// TestWrapErrorScrubsTheMessage is the other half.
func TestWrapErrorScrubsTheMessage(t *testing.T) {
	hostile := errors.New(
		"invalid target: address \x1b[2K\x1b[1AFORGED TLS Security: A+ (100/100).invalid:443")

	got := WrapError(hostile).Error()

	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("a raw escape byte survived the wrapper: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("a newline survived the wrapper, so the payload can still stand alone: %q", got)
	}
	if !strings.Contains(got, "invalid target") {
		t.Errorf("scrubbing lost the tool's own words: %q", got)
	}
}

// TestWrapErrorBoundsTheLength pins the volume half, which the escaping does not
// solve: a scrubbed message that is still 200 KB long pushes the real verdict
// out of scrollback as effectively as a forged one.
//
// The bound sits between the two behaviours rather than above both: an unbounded
// wrapper returns 4,013 bytes for this input and a bounded one returns
// MaxReportDetail, so 1000 separates them. Asserting "under 200 KB" would pass
// against no cap at all.
func TestWrapErrorBoundsTheLength(t *testing.T) {
	raw := "open " + strings.Repeat("A", 4000) + ": no such file or directory"
	if len(raw) <= 1000 {
		t.Fatalf("the fixture no longer exceeds the bound it is measuring: %d bytes", len(raw))
	}

	got := WrapError(errors.New(raw)).Error()

	if len(got) > 1000 {
		t.Errorf("the wrapped message is %d bytes, so the length cap is not applied", len(got))
	}
	if len(got) > MaxReportDetail {
		t.Errorf("the wrapped message is %d bytes, above the %d budget every report field uses",
			len(got), MaxReportDetail)
	}
	if !strings.HasPrefix(got, "open ") {
		t.Errorf("truncation took the beginning of the message rather than the end: %q", got[:20])
	}
}

// TestBoundDoesNotTransformWhatItKeeps is why Bound is not ForReport with the
// collapsing removed by accident.
//
// It exists for the %q print sites, where Go escapes control characters already
// and trimming costs a real diagnostic: `minVersion: "TLS 1.2 "` echoed through
// ForReport reads `"TLS 1.2" is not the same value as "TLS 1.2"`, for the exact
// trailing-space typo that refusal is written to show. If someone later routes
// Bound through ForReport, this fails.
func TestBoundDoesNotTransformWhatItKeeps(t *testing.T) {
	for _, s := range []string{"TLS 1.2 ", " leading", "TLS\t1.2", "TLS 1.2\x1b"} {
		if got := Bound(s, MaxReportDetail); got != s {
			t.Errorf("Bound altered a value short enough to keep whole: %q -> %q", s, got)
		}
	}
}

// TestBoundCapsOnARuneBoundary pins the half Bound does do.
func TestBoundCapsOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 1000) // 2 bytes each, so a naive byte cut splits one
	got := Bound(long, MaxReportDetail)

	if len(got) > MaxReportDetail {
		t.Errorf("Bound returned %d bytes, above the %d budget", len(got), MaxReportDetail)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a truncated value does not say it was truncated: %q", got[len(got)-6:])
	}
	if !utf8.ValidString(got) {
		t.Error("truncation split a multi-byte rune and produced invalid UTF-8")
	}
}

// TestForReportStillTruncatesThroughBound guards the refactor that moved the
// truncation into Bound: ForReport must still do both halves.
func TestForReportStillTruncatesThroughBound(t *testing.T) {
	got := ForReport("\x1b[1A"+strings.Repeat("A", 4000), MaxReportDetail)

	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("ForReport stopped collapsing control characters: %q", got[:20])
	}
	if len(got) > MaxReportDetail {
		t.Errorf("ForReport stopped capping the length: %d bytes", len(got))
	}
}

// TestWrapErrorLeavesNilAlone keeps the helper from turning "no error" into a
// non-nil error, which would make every guarded call site fail closed on a
// success.
func TestWrapErrorLeavesNilAlone(t *testing.T) {
	if err := WrapError(nil); err != nil {
		t.Errorf("WrapError(nil) returned %v, so a successful call would read as a failure", err)
	}
}
