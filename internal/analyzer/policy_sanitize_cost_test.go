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
// machine much faster or slower than this one. Four times the input must not
// cost more than eight times the time.
func TestSanitizeForReportCostDoesNotGrowQuadratically(t *testing.T) {
	timeOf := func(n int) func() time.Duration {
		input := strings.Repeat("a", n)
		return func() time.Duration {
			start := time.Now()
			sanitizeForReport(input, 120)
			return time.Since(start)
		}
	}

	best := fastestOf(costRounds, costMinRounds, costBudget, timeOf(50_000), timeOf(200_000))
	small, large := best[0], best[1]

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

// The cost comparison above runs each size up to costRounds times and stops
// adding rounds once the time it has observed passes costBudget, after at
// least costMinRounds.
const (
	costRounds    = 15
	costMinRounds = 3
	costBudget    = 2 * time.Second
)

// fastestOf runs each timing up to rounds times and returns the fastest
// observation of each, in the order the timings were given.
//
// Each round runs every timing once, so the sizes take turns. Load from other
// processes only adds time, which makes the fastest run the closest reading of
// the work itself, but taking turns matters as much as repeating: when every
// small run came before every large one, load that arrived in between landed
// on the large side alone and read as superlinear growth.
//
// Once the observed time passes budget, no round starts after the first
// minRounds, so a slow implementation is timed minRounds times, not rounds.
func fastestOf(rounds, minRounds int, budget time.Duration, timings ...func() time.Duration) []time.Duration {
	best := make([]time.Duration, len(timings))
	for i := range best {
		best[i] = time.Duration(1<<62 - 1)
	}
	var spent time.Duration
	for round := 0; round < rounds; round++ {
		if round >= minRounds && spent > budget {
			break
		}
		for i, timing := range timings {
			d := timing()
			spent += d
			if d < best[i] {
				best[i] = d
			}
		}
	}
	return best
}

// TestFastestOfSeesThroughLoadThatStartsPartWay is the regression test for a
// cost comparison that failed under go test -race -p 4 on a loaded machine
// while the code it measures was unchanged: 4x the input cost 10.2x the time.
//
// The fake workload costs 1 ms at the small size and 4 ms at the large one on
// a fake clock, and a call that starts while load is on costs three times as
// much. The load arrives 3 ms in, once three small runs are done, and lasts
// until 60 ms. When every small run comes before every large one, that load
// lands on the large side alone and reads as 12x growth.
func TestFastestOfSeesThroughLoadThatStartsPartWay(t *testing.T) {
	const loadFrom, loadUntil = 3 * time.Millisecond, 60 * time.Millisecond
	var now time.Duration
	timing := func(cost time.Duration) func() time.Duration {
		return func() time.Duration {
			d := cost
			if now >= loadFrom && now < loadUntil {
				d *= 3
			}
			now += d
			return d
		}
	}

	best := fastestOf(costRounds, costMinRounds, time.Hour, timing(time.Millisecond), timing(4*time.Millisecond))

	if best[0] != time.Millisecond || best[1] != 4*time.Millisecond {
		t.Errorf("fastest observations are %s and %s, want 1ms and 4ms: load that "+
			"arrived part way through the measurement decided the result", best[0], best[1])
	}
}

// TestFastestOfStopsAtTheBudget keeps a quadratic regression from turning the
// cost comparison into a run that only ends at the test binary's timeout: at
// the pre-fix cost of 46 s per 200 KB call, fifteen rounds would take over
// eleven minutes.
func TestFastestOfStopsAtTheBudget(t *testing.T) {
	calls := []int{0, 0}
	slow := func(i int) func() time.Duration {
		return func() time.Duration {
			calls[i]++
			return 30 * time.Second
		}
	}

	fastestOf(costRounds, costMinRounds, costBudget, slow(0), slow(1))

	if calls[0] != costMinRounds || calls[1] != costMinRounds {
		t.Errorf("each timing ran %v times, want %d: past the budget only the minimum "+
			"number of rounds should run", calls, costMinRounds)
	}
}
