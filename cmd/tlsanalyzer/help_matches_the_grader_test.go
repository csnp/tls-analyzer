package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The defect these tests exist for was a false claim in --help: it said "Q+
// ready: hybrid or full PQC key exchange in place", which the grader does not
// do. A server with hybrid key exchange deployed scores 64 and grades Q, and Q+
// was never observed on a hybrid host.
//
// What was written for it, internal/scanner/quantum_grade_bands_test.go, pins
// the GRADER from both sides and reads no help text at all. It passes unchanged
// against the tree before the fix, because the grader never changed: the help
// text did. It guards the one direction that had not gone wrong.
//
// The bands and the weighting are now rendered into the help from the code that
// produces them, so a restatement cannot drift. These tests hold that wiring in
// place, from the other direction: they read the rendered help and check it
// against the grader.

// quantumBandLine and tlsBandLine pull the two rendered lines back out of the
// help, by their headings, so a test failure says which line moved.
func bandLineUnder(t *testing.T, heading string) string {
	t.Helper()

	lines := strings.Split(rootCmd.Long, "\n")
	for i, line := range lines {
		if strings.Contains(line, heading) && i+1 < len(lines) {
			return strings.TrimSpace(lines[i+1])
		}
	}
	t.Fatalf("--help has no %q section, so this test is reading the wrong text", heading)
	return ""
}

// TestTheHelpTextGradeBandsAreTheGradersBands walks every boundary the help
// prints and asks the grader what it actually returns there.
//
// Both sides of each boundary, because a band stated one point wide of the
// grader's is exactly the mistake the original help made.
func TestTheHelpTextGradeBandsAreTheGradersBands(t *testing.T) {
	// [A-Z]+ rather than [A-Z], because the letters are not all one character:
	// a single-letter pattern read "QV below 20" as the grade "V", and the test
	// failed against a help text that was correct.
	bandPattern := regexp.MustCompile(`([A-Z]+[+-]?) (\d+)-(\d+)|([A-Z]+[+-]?) below (\d+)`)

	cases := []struct {
		heading string
		grade   func(int) string
	}{
		{"Quantum Ready grades", scanner.QuantumGradeFor},
		{"TLS Security grades", func(score int) string {
			return scanner.LetterForTLSScore(score)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.heading, func(t *testing.T) {
			line := bandLineUnder(t, tc.heading)
			matches := bandPattern.FindAllStringSubmatch(line, -1)
			if len(matches) < 4 {
				t.Fatalf("only %d bands parsed out of %q, so this test is reading almost "+
					"nothing", len(matches), line)
			}

			for _, m := range matches {
				if m[1] != "" {
					letter, lo, hi := m[1], atoi(t, m[2]), atoi(t, m[3])
					// The bottom of the band, the top of it, and the point just
					// below it, which must belong to a different letter.
					for _, score := range []int{lo, hi} {
						if got := tc.grade(score); got != letter {
							t.Errorf("--help says %d grades %s, the grader returns %s",
								score, letter, got)
						}
					}
					if lo > 0 {
						if got := tc.grade(lo - 1); got == letter {
							t.Errorf("--help says %s starts at %d, but the grader still "+
								"returns %s at %d", letter, lo, got, lo-1)
						}
					}
					continue
				}

				letter, below := m[4], atoi(t, m[5])
				for _, score := range []int{0, below - 1} {
					if got := tc.grade(score); got != letter {
						t.Errorf("--help says %d grades %s, the grader returns %s",
							score, letter, got)
					}
				}
				if got := tc.grade(below); got == letter {
					t.Errorf("--help says %s is below %d, but the grader still returns %s "+
						"at %d", letter, below, got, below)
				}
			}
		})
	}
}

// TestTheHelpTextWeightingIsTheGradersWeighting checks the worked example the
// help gives, which is the sentence the original false claim lived in.
//
// The number comes from running a hybrid host through the GRADER, not from
// recomputing the expression the help uses. The first version of this test did
// the latter, which meant it compared `QuantumScoreFor(a, b)` against a help
// string built from `QuantumScoreFor(a, b)` and agreed with itself: raising the
// hybrid key exchange score inside assessQuantumRisk moved the grade to 76 and
// left both sides of this assertion at 64. An oracle has to be independent of
// the thing it checks.
func TestTheHelpTextWeightingIsTheGradersWeighting(t *testing.T) {
	// The posture the help's sentence is about: hybrid key exchange, classical
	// certificate. Scored by the grader, not by re-running its arithmetic.
	assessment := scanner.AssessQuantumRisk(&types.ScanResult{
		Host: "example.com", Port: 443,
		KeyExchanges: []types.KeyExchange{{
			Name: "X25519MLKEM768", Type: "hybrid",
			PQCAlgorithm: "ML-KEM-768", HybridClassical: "X25519", Negotiated: true,
		}},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA", SignatureAlgorithm: "ECDSA-SHA384",
		},
	})
	if !assessment.HybridPQCReady {
		t.Fatal("the fixture did not register as hybrid, so this test is not measuring " +
			"the posture the help text is about")
	}
	measured := assessment.Score
	grade := scanner.QuantumGradeFor(measured)

	want := fmt.Sprintf("scores %d", measured)
	if !strings.Contains(rootCmd.Long, want) {
		t.Errorf("--help does not say a hybrid host with a classical certificate %q, "+
			"which is what the grader computes", want)
	}
	if !strings.Contains(rootCmd.Long, fmt.Sprintf("and grades %s, not ", grade)) {
		t.Errorf("--help does not say that score grades %s", grade)
	}
	if !strings.Contains(rootCmd.Long,
		fmt.Sprintf("key exchange at %d and the certificate at %d",
			scanner.QuantumKeyExchangeWeight, scanner.QuantumCertificateWeight)) {
		t.Error("--help does not state the weighting the grader applies")
	}

	// The claim that started this: Q+ must not be reachable by hybrid key
	// exchange alone, which is what the help used to say it was.
	if grade == scanner.QuantumGradeBands()[0].Letter {
		t.Errorf("hybrid key exchange with a classical certificate now grades %s, the top "+
			"band, so the help text's whole explanation of why it does not is wrong", grade)
	}
}

// TestTheHelpBandLinesEqualTheRenderedBands catches drift on the whole line at
// once, including the spacing and the wording, rather than boundary by boundary.
//
// It does NOT detect that the help is rendered rather than restated, and it is
// named for what it does after the first name overclaimed: measured by replacing
// the render call with a hardcoded string of the same value, this passes. That
// is correct. A restatement that agrees with the grader is not a defect; a
// restatement that disagrees is, and the same mutation combined with moving a
// band in the code fails here and in the boundary walk above. Disagreement is
// the failure mode, and it is covered from both directions.
func TestTheHelpBandLinesEqualTheRenderedBands(t *testing.T) {
	if got, want := bandLineUnder(t, "Quantum Ready grades"),
		scanner.DescribeBands(scanner.QuantumGradeBands()); got != want {
		t.Errorf("the quantum band line is %q, not the rendered %q, so it is a "+
			"restatement that can drift", got, want)
	}
	if got, want := bandLineUnder(t, "TLS Security grades"),
		scanner.DescribeBands(scanner.TLSGradeBands()); got != want {
		t.Errorf("the TLS band line is %q, not the rendered %q, so it is a "+
			"restatement that can drift", got, want)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("parsing %q from the help text failed: %v", s, err)
	}
	return n
}
