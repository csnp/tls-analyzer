package main

import (
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/reporter"
)

// The 0.4.0 release test found that `tlsanalyzer host -o report.txt`, run from a
// terminal, wrote 363 ANSI escape bytes into the saved file. The colour decision
// read os.Stdout's TTY-ness while the report was being written to a file, so
// every saved text report was corrupted for exactly the users who work in a
// terminal. Measured under a PTY before the fix: 363 escape bytes in the file.
//
// This file names identifiers introduced by the fix (useColorForTextReport,
// stdoutIsTTY), so it lives in a sibling _fields_test.go: a red proof against
// the pre-fix commit would otherwise report a build failure instead of the
// defect. The behavioural red proof for this one is the PTY measurement above,
// re-run as an A/B after the fix.

// TestUseColorForTextReportCoversTheInputSpace drives all eight combinations
// rather than the one that happens to occur locally. The destination decides:
// writing to a file is never coloured, whatever the terminal is doing.
func TestUseColorForTextReportCoversTheInputSpace(t *testing.T) {
	cases := []struct {
		name       string
		noColor    bool
		outputPath string
		isTerminal bool
		want       bool
	}{
		{"terminal, stdout, no flag: the only coloured case", false, "", true, true},
		{"terminal, -o file: the defect this fixes", false, "/tmp/report.txt", true, false},
		{"terminal, -o file, --no-color", true, "/tmp/report.txt", true, false},
		{"terminal, stdout, --no-color", true, "", true, false},
		{"not a terminal, stdout: piped or redirected", false, "", false, false},
		{"not a terminal, -o file", false, "/tmp/report.txt", false, false},
		{"not a terminal, -o file, --no-color", true, "/tmp/report.txt", false, false},
		{"not a terminal, stdout, --no-color", true, "", false, false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := useColorForTextReport(tt.noColor, tt.outputPath, tt.isTerminal)
			if got != tt.want {
				t.Errorf("useColorForTextReport(noColor=%v, outputPath=%q, isTerminal=%v) = %v, want %v",
					tt.noColor, tt.outputPath, tt.isTerminal, got, tt.want)
			}
		})
	}
}

// TestCreateReporterDisablesColourWhenWritingToAFile pins the composite, with
// the terminal check forced on. Without forcing it this test would pass before
// the fix, because `go test` never gives the suite a terminal on stdout.
func TestCreateReporterDisablesColourWhenWritingToAFile(t *testing.T) {
	origFormat, origNoColor, origOutput, origTTY := outputFormat, noColor, outputFile, stdoutIsTTY
	t.Cleanup(func() {
		outputFormat, noColor, outputFile, stdoutIsTTY = origFormat, origNoColor, origOutput, origTTY
	})

	stdoutIsTTY = func() bool { return true }
	outputFormat = "text"
	noColor = false
	outputFile = filepath.Join(t.TempDir(), "report.txt")

	r := createReporter()
	tr, ok := r.(*reporter.TextReporter)
	if !ok {
		t.Fatalf("expected a *reporter.TextReporter for the text format, got %T", r)
	}
	if !tr.NoColor {
		t.Error("a text report written to -o must not be coloured: the file is read " +
			"later by a pager, an editor or an auditor, and ANSI escapes corrupt it")
	}
}

// TestCreateReporterKeepsColourOnAnInteractiveTerminal is the acceptance
// control. Suppressing colour for files must not suppress it for the interactive
// case, which is the whole point of having colour.
func TestCreateReporterKeepsColourOnAnInteractiveTerminal(t *testing.T) {
	origFormat, origNoColor, origOutput, origTTY := outputFormat, noColor, outputFile, stdoutIsTTY
	t.Cleanup(func() {
		outputFormat, noColor, outputFile, stdoutIsTTY = origFormat, origNoColor, origOutput, origTTY
	})

	stdoutIsTTY = func() bool { return true }
	outputFormat = "text"
	noColor = false
	outputFile = ""

	tr, ok := createReporter().(*reporter.TextReporter)
	if !ok {
		t.Fatal("expected a *reporter.TextReporter for the text format")
	}
	if tr.NoColor {
		t.Error("colour was disabled for an interactive terminal with no -o and no " +
			"--no-color; the fix has over-reached into the case it must preserve")
	}
}
