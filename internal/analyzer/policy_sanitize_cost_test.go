package analyzer

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The pre-push adversarial review found that truncation in sanitizeForReport was
// quadratic in the length of untrusted policy text:
//
//	for len(string(runes)) > budget && len(runes) > 0 {
//	    runes = runes[:len(runes)-1]
//	}
//
// Every iteration dropped one rune and rebuilt the whole string to measure it.
// Measured before the fix: 2.3 ms at 1 KB, 2.78 s at 50 KB, 46 s at 200 KB. End
// to end, a 300 KB policy name cost 100 seconds of CPU before any socket was
// opened, against 0.03 s for a 200-character name. A policy file arrives from a
// vendor, a repository or a colleague, and this tool is a CI gate.
//
// The name and description are not the whole surface: every violation's
// Description, Expected, Actual and Remediation goes through the same function,
// and an allowedCipherSuites value is interpolated once per offered suite.

func TestSanitizeForReportIsLinearInInputLength(t *testing.T) {
	// A quadratic implementation takes ~46 s at 200 KB and ~11 s at 100 KB; a
	// linear one takes microseconds. The bound is deliberately loose so it
	// cannot fail on a slow or loaded machine, while still being ~20x below the
	// pre-fix cost at this size.
	const size = 200_000
	const bound = 2 * time.Second

	input := strings.Repeat("a", size)

	start := time.Now()
	out := sanitizeForReport(input, 120)
	elapsed := time.Since(start)

	if elapsed > bound {
		t.Errorf("sanitizeForReport took %s for a %d character value, which is the "+
			"quadratic truncation returning: an untrusted policy file should not be "+
			"able to spend CPU proportional to the square of its own length", elapsed, size)
	}
	if len(out) > 120 {
		t.Errorf("output is %d bytes, want at most 120", len(out))
	}
}

// TestSanitizeForReportTruncatesCorrectly is the correctness half. Making the
// truncation fast must not change where it cuts, and it must never emit a
// partial UTF-8 sequence.
func TestSanitizeForReportTruncatesCorrectly(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		maxLen int
	}{
		{"ascii well under the cap", "a short name", 120},
		{"ascii exactly at the cap", strings.Repeat("a", 120), 120},
		{"ascii one over the cap", strings.Repeat("a", 121), 120},
		{"ascii far over the cap", strings.Repeat("a", 5000), 120},
		{"multi-byte runes over the cap", strings.Repeat("é", 5000), 120},
		{"four-byte runes over the cap", strings.Repeat("𝄞", 5000), 120},
		{"mixed widths over the cap", strings.Repeat("aé𝄞", 2000), 120},
		{"tiny budget, four-byte runes", strings.Repeat("𝄞", 100), 4},
		{"tiny budget, ascii", strings.Repeat("a", 100), 3},
		{"zero budget", strings.Repeat("a", 100), 0},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out := sanitizeForReport(tt.input, tt.maxLen)

			// The ellipsis is appended after the budget, and the budget has a
			// floor of one byte, so for a maxLen below 4 the function returns up
			// to 4 bytes. That is pre-existing behaviour, unchanged by making the
			// truncation linear, and no caller passes a maxLen under 120. The
			// bound is stated as the function actually behaves rather than as an
			// invariant it does not hold.
			limit := tt.maxLen
			if limit < 4 {
				limit = 4
			}
			if len(out) > limit {
				t.Errorf("output is %d bytes, want at most %d: %q", len(out), limit, out)
			}
			if !utf8.ValidString(out) {
				t.Errorf("output is not valid UTF-8, so truncation cut mid-sequence: %q", out)
			}
			if strings.ContainsRune(out, utf8.RuneError) && !strings.ContainsRune(tt.input, utf8.RuneError) {
				t.Errorf("truncation introduced U+FFFD: %q", out)
			}
		})
	}
}

// TestSanitizeForReportCostDoesNotGrowQuadratically compares two sizes rather
// than trusting one absolute number, so the check still means something on a
// machine much faster or slower than this one. Doubling the input must not
// quadruple the time.
func TestSanitizeForReportCostDoesNotGrowQuadratically(t *testing.T) {
	measure := func(n int) time.Duration {
		input := strings.Repeat("a", n)
		// Take the best of three, so a scheduling hiccup does not decide the test.
		best := time.Duration(1<<62 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			sanitizeForReport(input, 120)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	small := measure(50_000)
	large := measure(200_000)

	// Four times the input. Linear predicts ~4x; quadratic predicts ~16x. Allow
	// a very generous 8x before calling it quadratic, and put a floor under the
	// small measurement so timer granularity cannot produce a huge ratio.
	if small < time.Microsecond {
		small = time.Microsecond
	}
	if ratio := float64(large) / float64(small); ratio > 8 {
		t.Errorf("4x the input cost %.1fx the time (%s -> %s); linear predicts ~4x and "+
			"quadratic ~16x, so the truncation is scaling with the square of the input",
			ratio, small, large)
	}
}
