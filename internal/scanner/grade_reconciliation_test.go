package scanner

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/reporter"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// These tests assert on the RENDERED REPORT rather than on the Grade struct, so
// that they compile against the code as it was before the fix and fail at
// runtime on the missing lines. A test that names a new struct field cannot fail
// against the old code, because it cannot build against it; those assertions
// live in grade_fields_test.go instead.

// penalisedResult is a configuration whose dimensions all score well and which
// then takes a real vulnerability penalty. That is the shape that made the
// printed breakdown irreconcilable: on cloudflare.com the four dimensions summed
// to 66 and printed under a headline of 21/100, with nothing to account for the
// difference.
func penalisedResult() *types.ScanResult {
	return &types.ScanResult{
		Target: "penalised.example",
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true},
			{Version: "TLS 1.2", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true, Encryption: "AES-GCM"},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			SignatureAlgorithm: "SHA256WithECDSA",
			DaysUntilExpiry:    365,
		},
		QuantumRisk: types.QuantumRiskAssessment{Score: 100, Level: types.RiskLow},
		Vulnerabilities: []types.Vulnerability{
			{ID: "TLS10", Name: "TLS 1.0 Enabled", Severity: types.SeverityHigh},
			{ID: "NOFS1", Name: "No Forward Secrecy", Severity: types.SeverityMedium},
			{ID: "NOFS2", Name: "No Forward Secrecy", Severity: types.SeverityMedium},
		},
	}
}

func renderTextReport(t *testing.T, result *types.ScanResult) string {
	t.Helper()

	var buf bytes.Buffer
	if err := (&reporter.TextReporter{NoColor: true}).Report(&buf, result); err != nil {
		t.Fatalf("rendering the text report failed: %v", err)
	}
	return buf.String()
}

// findPrintedInt pulls the first capture group of pattern out of text as an int.
func findPrintedInt(t *testing.T, text, pattern string) (int, bool) {
	t.Helper()

	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if match == nil {
		return 0, false
	}

	value, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("pattern %q captured %q, which is not a number", pattern, match[1])
	}
	return value, true
}

// TestTextReportReconcilesTheHeadlineScoreWithItsBreakdown guards the defect
// where the score breakdown could not be added up to the score it sat under.
//
// The dimensions, the vulnerability penalty and the final score must all be
// printed, and the arithmetic between them must close, so that a reader can see
// where the headline number came from instead of having to trust it.
func TestTextReportReconcilesTheHeadlineScoreWithItsBreakdown(t *testing.T) {
	s := New(nil)
	result := penalisedResult()
	result.Grade = s.calculateGrade(result)

	out := renderTextReport(t, result)

	subtotal, ok := findPrintedInt(t, out, `Dimension subtotal\s+(\d+)/100`)
	if !ok {
		t.Fatalf("the score breakdown prints no dimension subtotal, so the printed " +
			"dimensions cannot be related to the headline score")
	}

	penalty, ok := findPrintedInt(t, out, `Vulnerability penalty\s+-(\d+)`)
	if !ok {
		t.Fatalf("the score breakdown prints no vulnerability penalty, so the gap "+
			"between the dimension subtotal (%d) and the headline score (%d) is "+
			"unexplained", subtotal, result.Grade.Score)
	}

	final, ok := findPrintedInt(t, out, `TLS Security score\s+(\d+)/100`)
	if !ok {
		t.Fatalf("the score breakdown prints no final score line")
	}

	if subtotal-penalty != final {
		t.Errorf("the printed breakdown does not add up: subtotal %d - penalty %d = %d, but the report prints %d",
			subtotal, penalty, subtotal-penalty, final)
	}

	if final != result.Grade.Score {
		t.Errorf("the breakdown's final score (%d) disagrees with the graded score (%d)",
			final, result.Grade.Score)
	}

	// The dimension lines above the subtotal must themselves add up to it, or the
	// subtotal is an unrelated number rather than a total.
	dimensionSum, dimensionMax := 0, 0
	for _, match := range regexp.MustCompile(`\]\s+(\d+)/(\d+)\n`).FindAllStringSubmatch(out, -1) {
		score, _ := strconv.Atoi(match[1])
		max, _ := strconv.Atoi(match[2])
		dimensionSum += score
		dimensionMax += max
	}
	if dimensionMax == 0 {
		t.Fatal("no dimension lines were found in the breakdown")
	}
	if normalised := dimensionSum * 100 / dimensionMax; normalised != subtotal {
		t.Errorf("the printed dimensions total %d of %d points (%d/100), but the subtotal line says %d/100",
			dimensionSum, dimensionMax, normalised, subtotal)
	}

	// The deduction must be traceable to the findings that caused it, not just
	// asserted as a number.
	for _, want := range []string{"1 HIGH x 15", "2 MEDIUM x 5"} {
		if !strings.Contains(out, want) {
			t.Errorf("the penalty line does not itemise %q, so the deduction cannot be traced to the findings", want)
		}
	}
}

// TestSkippingVulnerabilityChecksIsNotPresentedAsABetterResult guards the
// direction defect where --skip-vulns RAISED the reported grade, because
// declining to run a check removed its penalties.
//
// The number itself cannot be fixed without redefining the score, so the fix is
// that a score computed without the checks must be labelled as an upper bound
// rather than presented as comparable with a full scan's.
func TestSkippingVulnerabilityChecksIsNotPresentedAsABetterResult(t *testing.T) {
	assessed := penalisedResult()
	assessed.Grade = New(nil).calculateGrade(assessed)

	skippedConfig := DefaultConfig()
	skippedConfig.CheckVulns = false

	// The checks did not run, so there are no findings to carry. This is exactly
	// what makes the penalty unmeasured rather than zero.
	skipped := penalisedResult()
	skipped.Vulnerabilities = nil
	skipped.Grade = New(skippedConfig).calculateGrade(skipped)

	if skipped.Grade.Score <= assessed.Grade.Score {
		t.Fatalf("this fixture no longer demonstrates the defect: skipping the "+
			"vulnerability checks gave %d/100 against %d/100 with them, so there is "+
			"nothing for the label to qualify",
			skipped.Grade.Score, assessed.Grade.Score)
	}

	out := renderTextReport(t, skipped)
	lower := strings.ToLower(out)

	if !strings.Contains(lower, "upper bound") {
		t.Errorf("a grade of %d/100 computed without the vulnerability checks, against "+
			"%d/100 with them, is printed with no indication that it is an upper bound "+
			"rather than a better result",
			skipped.Grade.Score, assessed.Grade.Score)
	}

	if !strings.Contains(lower, "not measured") {
		t.Error("the breakdown does not record the vulnerability penalty as unmeasured, " +
			"so a skipped check reads the same as a clean result")
	}

	// A label that is always printed says nothing. A full scan must not carry it.
	if assessedOut := strings.ToLower(renderTextReport(t, assessed)); strings.Contains(assessedOut, "upper bound") {
		t.Error("a full scan is also labelled an upper bound, which makes the label vacuous")
	}
}

// protocolCombination builds a protocol list from a set of supported versions.
func protocolCombination(supported map[string]bool) []types.Protocol {
	all := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	protocols := make([]types.Protocol, 0, len(all))
	for _, version := range all {
		protocols = append(protocols, types.Protocol{Version: version, Supported: supported[version]})
	}
	return protocols
}

// TestRetiringALegacyProtocolNeverLowersTheProtocolScore guards a scoring
// inversion: the model awarded points for TLS 1.3 and further points for TLS 1.2,
// so a TLS 1.3-only server was capped at 15 of 25 and turning TLS 1.2 off cost ten
// points.
//
// TLS 1.3-only is the configuration this tool's own `strict` and `cnsa-2.0-2030`
// policies require, so following its advice lowered its grade, and the best
// achievable protocol posture could not reach the top of the dimension. Same class
// as a skipped check raising the score: an action the tool recommends must not move
// the number the wrong way.
//
// Stated as the general property rather than as one expected value, over all
// sixteen combinations, so a future reweighting cannot reintroduce it in a shape
// this fixture did not anticipate.
func TestRetiringALegacyProtocolNeverLowersTheProtocolScore(t *testing.T) {
	versions := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}
	legacy := []string{"TLS 1.2", "TLS 1.1", "TLS 1.0"}

	for mask := 0; mask < 1<<len(versions); mask++ {
		supported := map[string]bool{}
		for i, version := range versions {
			if mask&(1<<i) != 0 {
				supported[version] = true
			}
		}

		// The property holds where TLS 1.3 is available. Without it, dropping
		// TLS 1.2 removes the only modern protocol and a lower score is correct.
		if !supported["TLS 1.3"] {
			continue
		}

		before, _ := scoreProtocols(protocolCombination(supported))

		for _, drop := range legacy {
			if !supported[drop] {
				continue
			}
			reduced := map[string]bool{}
			for k, v := range supported {
				reduced[k] = v
			}
			delete(reduced, drop)

			after, _ := scoreProtocols(protocolCombination(reduced))
			if after < before {
				t.Errorf("disabling %s lowered the protocol score from %d to %d (supported before: %v). "+
					"Retiring a legacy protocol is what the tool recommends; it must not cost points.",
					drop, before, after, supported)
			}
		}
	}
}

// TestTLS13OnlyReachesTheProtocolMaximum pins the best achievable posture at the
// top of its dimension. Without this, the invariant above is satisfied by any flat
// scoring function.
func TestTLS13OnlyReachesTheProtocolMaximum(t *testing.T) {
	score, max := scoreProtocols(protocolCombination(map[string]bool{"TLS 1.3": true}))
	if score != max {
		t.Errorf("a TLS 1.3-only server scores %d of %d on protocol support; the strictest "+
			"available configuration cannot reach the top of the dimension", score, max)
	}

	// And a server still offering deprecated versions must NOT reach it, or the
	// dimension has stopped discriminating.
	withLegacy, _ := scoreProtocols(protocolCombination(map[string]bool{
		"TLS 1.3": true, "TLS 1.2": true, "TLS 1.1": true, "TLS 1.0": true,
	}))
	if withLegacy >= score {
		t.Errorf("a server offering TLS 1.0 and 1.1 scores %d, not below the %d of a clean "+
			"TLS 1.3-only server", withLegacy, score)
	}
}

// TestSkippingADimensionIsNotPresentedAsABetterResult guards the second
// score-laundering path. Excluding a skipped dimension keeps the score honest
// about what it measured, but it also renormalises over the remaining dimensions,
// and quantum readiness is the one most servers score worst on. So
// --skip-quantum RAISED the reported grade: github.com moved from D (40/100) to
// C (61/100) and a well-configured host reached A+ (100/100), on a tool whose
// purpose is post-quantum readiness.
//
// --skip-vulns was already labelled. This asserts the same treatment here, since
// an asymmetry means one laundering path is disclosed and the other is not.
func TestSkippingADimensionIsNotPresentedAsABetterResult(t *testing.T) {
	// A configuration that scores well everywhere except quantum readiness, which
	// is what makes dropping the dimension raise the total.
	fixture := func() *types.ScanResult {
		result := penalisedResult()
		result.Vulnerabilities = nil
		result.QuantumRisk = types.QuantumRiskAssessment{Score: 0, Level: types.RiskCritical}
		return result
	}

	assessed := fixture()
	assessed.Grade = New(nil).calculateGrade(assessed)

	skippedConfig := DefaultConfig()
	skippedConfig.CheckQuantum = false
	skipped := fixture()
	skipped.Grade = New(skippedConfig).calculateGrade(skipped)

	if skipped.Grade.Score <= assessed.Grade.Score {
		t.Fatalf("this fixture no longer demonstrates the defect: skipping the quantum "+
			"dimension gave %d/100 against %d/100 with it, so there is nothing to qualify",
			skipped.Grade.Score, assessed.Grade.Score)
	}

	out := renderTextReport(t, skipped)
	lower := strings.ToLower(out)

	if !strings.Contains(lower, "not comparable") {
		t.Errorf("a grade of %d/100 with the quantum dimension dropped, against %d/100 "+
			"with it, is printed with no indication that it is not comparable with a full scan",
			skipped.Grade.Score, assessed.Grade.Score)
	}
	if !strings.Contains(out, "Quantum Readiness") {
		t.Error("the report does not name the dimension that was not assessed")
	}

	// The label must not be printed for a full scan, or it says nothing.
	if strings.Contains(strings.ToLower(renderTextReport(t, assessed)), "not comparable") {
		t.Error("a full scan is also labelled not comparable, which makes the label vacuous")
	}
}
