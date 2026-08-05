package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// A verdict fixed in one renderer of five is not fixed.
//
// 0.3.0 stopped the single-target path grading a host it never reached. 0.4.0
// did the same for batch mode and said so in its CHANGELOG, and that was true of
// the text renderer alone. HTML rendered an empty grade letter, "0/100", a full
// breakdown of zeros and a red grade-f class. SARIF emitted a valid run with no
// results, which is byte-for-byte the document a clean host produces. CBOM
// emitted an inventory listing no cryptography, with a service endpoint at
// "https://:0". Someone who passes --format html is not reading the text report.
//
// So this test does not name the renderers it knows about. It walks
// ValidFormats, which is what the CLI dispatches on, and fails if a format has
// no expectation registered here: a sixth format cannot be added without
// deciding what it says about a host that was never reached.

func unreachedResult() *types.ScanResult {
	return &types.ScanResult{
		Target:         "unreachable.invalid",
		Host:           "unreachable.invalid",
		Error:          "cannot resolve unreachable.invalid: no such host",
		Timestamp:      time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		ScannerVersion: "0.4.1",
	}
}

func scannedResult() *types.ScanResult {
	return &types.ScanResult{
		Target:         "example.com",
		Host:           "example.com",
		Port:           443,
		Timestamp:      time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC),
		ScannerVersion: "0.4.1",
		Protocols:      []types.Protocol{{Version: "TLS 1.3", Supported: true}},
		Grade: types.Grade{
			Letter: "A", Score: 91, QuantumGrade: "Q",
			Factors: []types.GradeFactor{{Category: "Protocol Support", Score: 25, MaxScore: 25}},
		},
		QuantumRisk: types.QuantumRiskAssessment{Assessed: true, Score: 64},
		Vulnerabilities: []types.Vulnerability{{
			ID: "NO_TLS13", Name: "TLS 1.3 Not Supported",
			Severity: types.SeverityMedium, Description: "d", Remediation: "r",
		}},
	}
}

// surfaceCheck states what a format must do with each of the two shapes.
type surfaceCheck struct {
	// unreached fails if the rendered output describes the host as measured.
	unreached func(t *testing.T, out string)
	// scanned is the acceptance control. Without it every check below is
	// satisfied by a renderer that emits nothing at all, for every input.
	scanned func(t *testing.T, out string)
}

func decodeJSON(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return doc
}

func sarifRunOf(t *testing.T, out string) map[string]any {
	t.Helper()
	doc := decodeJSON(t, out)
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("SARIF carries %v runs, want exactly 1", doc["runs"])
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("SARIF run is not an object")
	}
	return run
}

func sarifExecutionSuccessful(t *testing.T, run map[string]any) bool {
	t.Helper()
	invocations, ok := run["invocations"].([]any)
	if !ok || len(invocations) != 1 {
		t.Fatalf("SARIF carries %v invocations, want exactly 1: without one a consumer "+
			"cannot tell a clean host from one that was never contacted", run["invocations"])
	}
	inv, ok := invocations[0].(map[string]any)
	if !ok {
		t.Fatal("SARIF invocation is not an object")
	}
	success, ok := inv["executionSuccessful"].(bool)
	if !ok {
		t.Fatal("SARIF invocation has no executionSuccessful")
	}
	return success
}

var surfaceChecks = map[string]surfaceCheck{
	string(FormatText): {
		unreached: func(t *testing.T, out string) {
			if !strings.Contains(out, "NOT SCANNED") {
				t.Error("no NOT SCANNED block")
			}
			if strings.Contains(out, "OVERALL GRADE") {
				t.Error("a target that was never reached was given a graded report")
			}
			if !strings.Contains(out, "no such host") {
				t.Error("the report does not say why the target produced nothing")
			}
		},
		scanned: func(t *testing.T, out string) {
			if !strings.Contains(out, "OVERALL GRADE") {
				t.Error("a scanned host got no grade, so the branch is taken for every scan")
			}
		},
	},

	string(FormatJSON): {
		// JSON has carried the reason all along, in a named field, which is why
		// the batch path could be fixed by reading it. Pinned so it stays that way.
		unreached: func(t *testing.T, out string) {
			doc := decodeJSON(t, out)
			if msg, _ := doc["error"].(string); !strings.Contains(msg, "no such host") {
				t.Errorf("JSON does not carry the scan error: %v", doc["error"])
			}
		},
		scanned: func(t *testing.T, out string) {
			doc := decodeJSON(t, out)
			if _, present := doc["error"]; present {
				t.Error("a scanned host carries an error field")
			}
			grade, _ := doc["grade"].(map[string]any)
			if grade == nil || grade["letter"] != "A" {
				t.Errorf("a scanned host carries no grade: %v", doc["grade"])
			}
		},
	},

	string(FormatSARIF): {
		unreached: func(t *testing.T, out string) {
			run := sarifRunOf(t, out)
			if sarifExecutionSuccessful(t, run) {
				t.Error("SARIF reports a successful invocation for a host that was never " +
					"contacted, which is the document a clean host produces")
			}
			results, ok := run["results"].([]any)
			if !ok {
				t.Fatalf("SARIF results is %v, not an array", run["results"])
			}
			if len(results) != 0 {
				t.Errorf("SARIF carries %d results about a host nothing connected to", len(results))
			}
			notifications, _ := run["invocations"].([]any)[0].(map[string]any)["toolExecutionNotifications"].([]any)
			if len(notifications) == 0 {
				t.Error("SARIF says the run failed and nowhere says why")
			}
		},
		scanned: func(t *testing.T, out string) {
			run := sarifRunOf(t, out)
			if !sarifExecutionSuccessful(t, run) {
				t.Error("SARIF reports a failed invocation for a host that was scanned")
			}
			if results, _ := run["results"].([]any); len(results) == 0 {
				t.Error("SARIF carries no results for a host with a finding")
			}
		},
	},

	string(FormatCBOM): {
		unreached: func(t *testing.T, out string) {
			doc := decodeJSON(t, out)
			if components, _ := doc["components"].([]any); len(components) != 0 {
				t.Errorf("CBOM inventories %d components for a host nothing connected to",
					len(components))
			}
			if services, present := doc["services"]; present {
				t.Errorf("CBOM asserts a service at an endpoint it never reached: %v", services)
			}
			meta, _ := doc["metadata"].(map[string]any)
			props, _ := meta["properties"].([]any)
			var reached, reason string
			for _, p := range props {
				kv, _ := p.(map[string]any)
				switch kv["name"] {
				case "qramm:targetReached":
					reached, _ = kv["value"].(string)
				case "qramm:scanError":
					reason, _ = kv["value"].(string)
				}
			}
			if reached != "false" {
				t.Errorf("CBOM does not record that the target was never reached, so an "+
					"empty inventory reads as a host that uses no cryptography: %v", props)
			}
			if !strings.Contains(reason, "no such host") {
				t.Errorf("CBOM does not record why nothing was inventoried: %q", reason)
			}
		},
		scanned: func(t *testing.T, out string) {
			doc := decodeJSON(t, out)
			if components, _ := doc["components"].([]any); len(components) == 0 {
				t.Error("CBOM inventories nothing for a host that negotiated TLS 1.3")
			}
			meta, _ := doc["metadata"].(map[string]any)
			if props, present := meta["properties"]; present {
				t.Errorf("a scanned host carries the not-reached properties: %v", props)
			}
		},
	},

	string(FormatHTML): {
		unreached: func(t *testing.T, out string) {
			if !strings.Contains(out, "Not scanned") {
				t.Error("the page does not say the target was not scanned")
			}
			if !strings.Contains(out, "no such host") {
				t.Error("the page does not say why")
			}
			// The four things the page rendered for an unreached host before.
			for _, forbidden := range []string{
				"grade-box", "grade-letter", "0/100", "Score Breakdown",
			} {
				if strings.Contains(out, forbidden) {
					t.Errorf("the page still renders %q for a host that was never contacted",
						forbidden)
				}
			}
		},
		scanned: func(t *testing.T, out string) {
			for _, required := range []string{"grade-box", "grade-letter", "Score Breakdown"} {
				if !strings.Contains(out, required) {
					t.Errorf("a scanned host renders no %q, so the unreached branch is being "+
						"taken for every scan", required)
				}
			}
		},
	},
}

func TestNoSurfaceDescribesAHostItNeverReachedAsMeasured(t *testing.T) {
	// Every format the CLI can dispatch to, read from the same list --format
	// validates against, so a format added later is covered on the day it is
	// added rather than the day somebody remembers this file.
	for _, format := range ValidFormats() {
		check, ok := surfaceChecks[format]
		if !ok {
			t.Errorf("format %q has no expectation here: decide what it reports for a host "+
				"that was never reached before shipping it", format)
			continue
		}

		t.Run(format+"/unreached", func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(Format(format)).Report(&buf, unreachedResult()); err != nil {
				t.Fatalf("report failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Fatal("the renderer produced no output, so this case measured nothing")
			}
			check.unreached(t, buf.String())
		})

		t.Run(format+"/scanned", func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(Format(format)).Report(&buf, scannedResult()); err != nil {
				t.Fatalf("report failed: %v", err)
			}
			if buf.Len() == 0 {
				t.Fatal("the renderer produced no output, so this case measured nothing")
			}
			check.scanned(t, buf.String())
		})
	}
}

// TestTheUnreachedClassifierDecidesOnTheRawResult pins the shared predicate
// itself, in both directions.
//
// The text renderer scrubs its copy before printing, and scrubbing collapses
// control characters and trims, so an Error made only of them scrubs to empty.
// Deciding on the scrubbed copy would send a target that was never reached down
// the fully-graded path, which is the inverse of the defect, introduced by the
// scrubbing that fixed a different one.
func TestTheUnreachedClassifierDecidesOnTheRawResult(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want bool
	}{
		{"a real failure", "cannot resolve host: no such host", true},
		{"control bytes only", "\x01\x02\x03\x07", true},
		{"escape sequences only", "\x1b[2K\x1b[1A", true},
		{"whitespace only", "   \t  ", true},
		{"no error", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := unreachedResult()
			result.Error = tc.err
			if got := targetWasNeverReached(result); got != tc.want {
				t.Errorf("targetWasNeverReached(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}

	if targetWasNeverReached(nil) {
		t.Error("a nil result was classified as a target that was never reached")
	}
}

// TestSARIFEmitsListsRatherThanNulls is the assertion the official schema made
// and the unit tests did not.
//
// `"results": null` and `"rules": null` are not empty lists, they are the
// absence of a list, and the SARIF 2.1.0 schema rejects both. Validating an
// unreached host against the published schema returned `None is not of type
// 'array'` at runs[0].tool.driver.rules, in this release's own new branch, after
// the results half had already been fixed in the line above it. Pinned here so
// the next person does not need a network fetch to catch it.
func TestSARIFEmitsListsRatherThanNulls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result *types.ScanResult
	}{
		{"unreached", unreachedResult()},
		{"scanned", scannedResult()},
		// A host that was scanned and has nothing wrong with it: the shape that
		// produced `"results": null` before this release.
		{"scanned with no findings", func() *types.ScanResult {
			r := scannedResult()
			r.Vulnerabilities = nil
			r.QuantumRisk = types.QuantumRiskAssessment{Assessed: true, Score: 90}
			return r
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := (&SARIFReporter{}).Report(&buf, tc.result); err != nil {
				t.Fatalf("report failed: %v", err)
			}

			// Read as raw JSON, because Go's decoder turns both null and [] into a
			// nil slice and would not be able to tell them apart.
			if strings.Contains(buf.String(), `"results": null`) {
				t.Error(`SARIF emits "results": null, which the 2.1.0 schema rejects`)
			}
			if strings.Contains(buf.String(), `"rules": null`) {
				t.Error(`SARIF emits "rules": null, which the 2.1.0 schema rejects`)
			}

			run := sarifRunOf(t, buf.String())
			if _, ok := run["results"].([]any); !ok {
				t.Errorf("results is %T, not an array", run["results"])
			}
			driver := run["tool"].(map[string]any)["driver"].(map[string]any)
			if _, ok := driver["rules"].([]any); !ok {
				t.Errorf("rules is %T, not an array", driver["rules"])
			}
		})
	}
}

// TestTheUnreachedPageIsNotANewForgerySurface covers the page this release adds.
//
// html/template escapes markup and not control characters, so an HTML report can
// carry a raw cursor-up sequence that steers a terminal when the file is catted,
// grepped or paged. That gap exists in the GRADED page and is deferred to the
// next release; this page is new, and a surface added today should not ship as a
// second instance of a defect already waiting to be fixed.
func TestTheUnreachedPageIsNotANewForgerySurface(t *testing.T) {
	result := unreachedResult()
	// \u009b, properly encoded, NOT the bare \x9b byte. A bare 0x9B is invalid
	// UTF-8 and `range` decodes it to U+FFFD before assertNoCursorControl's C1 arm
	// can look at it, so that arm cannot fire and the payload silently tests
	// nothing on that axis. This file shipped with the bare form, which is the
	// same vacuity this release corrected in untrusted_field_sweep_test.go and
	// failed_scan_branch_test.go. Both forms are carried now.
	result.Error = "cannot resolve \x1b[2K\x1b[1AFORGED TLS Security: A+ (100/100)" +
		"\u009b1B\x9braw.invalid"
	result.Target = "host\x1b[1AFORGED.invalid"
	result.ScanWarnings = []string{"warning \x1b[1AFORGED"}

	var buf bytes.Buffer
	if err := (&HTMLReporter{IncludeCSS: true}).Report(&buf, result); err != nil {
		t.Fatalf("report failed: %v", err)
	}
	out := buf.String()

	assertNoCursorControl(t, "html/unreached", out)

	// Non-vacuous: the payload has to have reached the page at all, or an empty
	// page would satisfy the assertion above.
	if got := strings.Count(out, "FORGED"); got < 3 {
		t.Errorf("only %d payloads reached the page, so the check above measured almost "+
			"nothing; the target, the error and the warning should each carry one", got)
	}
}
