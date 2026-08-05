package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// stderr shares the terminal with the report, and a sweep prints it after every
// report it produced, so every error this command emits is a forgery surface.
// The wrapper itself is pinned in internal/sanitize; what is pinned here is that
// the real call sites apply it, driven through the actual functions rather than
// through a copy of their composition. A test that rebuilds the composition by
// hand passes whether or not the production line was ever changed.

// forgery is the payload every case below uses: erase the line, move the cursor
// up one, and write a verdict where the real one was.
const forgery = "\x1b[2K\x1b[1AFORGED TLS Security: A+ (100/100)"

// forgeryPathSafe is the same payload without the slashes in "100/100", for the
// cases that have to create a real filesystem entry rather than merely fail to
// open one. The first version of this test used `forgery` for a directory name,
// so Mkdir failed with ENOENT, the case skipped, and the skip read as a pass:
// the mutation that removed the fix under test survived it. A fixture that
// cannot reach the code it is about measures nothing.
const forgeryPathSafe = "\x1b[2K\x1b[1AFORGED-TLS-Security-A-plus"

func assertNoSteering(t *testing.T, site, message string) {
	t.Helper()
	if strings.ContainsRune(message, 0x1b) {
		t.Errorf("%s: a raw escape byte reached stderr: %q", site, message)
	}
	if strings.Contains(message, "\n"+"FORGED") || strings.HasPrefix(message, "FORGED") {
		t.Errorf("%s: the payload stands on its own line: %q", site, message)
	}
}

// TestAFailedScanScrubsTheErrorAndStillUnwraps drives scanSingleTarget, which is
// the site itself, and asserts both halves. Asserting only the unwrapping would
// pass against a wrapper that does no scrubbing, and asserting only the
// scrubbing would pass against one that flattens the chain and changes the exit
// code from 2 to 1.
func TestAFailedScanScrubsTheErrorAndStillUnwraps(t *testing.T) {
	sentinel := errors.New("cannot resolve " + forgery + ".invalid")
	scan := func(context.Context, string) (*types.ScanResult, error) { return nil, sentinel }

	err := scanSingleTarget(context.Background(), scan,
		analyzer.NewCNSA2Analyzer(), analyzer.NewPolicyEvaluator(),
		"host.invalid", nil, io.Discard)
	if err == nil {
		t.Fatal("a failed scan returned no error")
	}

	assertNoSteering(t, "scanSingleTarget", err.Error())
	if !strings.Contains(err.Error(), "scan failed") {
		t.Errorf("scrubbing lost the tool's own words: %q", err.Error())
	}
	if !errors.Is(err, sentinel) {
		t.Error("the original error is no longer reachable through the chain, " +
			"so main can no longer classify the exit code")
	}
}

// TestATargetsFileThatCannotBeOpenedScrubsItsPath drives collectTargets. The os
// error quotes the path back, and the path came from the invocation.
func TestATargetsFileThatCannotBeOpenedScrubsItsPath(t *testing.T) {
	previous := targetsFile
	defer func() { targetsFile = previous }()

	targetsFile = filepath.Join(t.TempDir(), "missing"+forgery+".txt")

	_, err := collectTargets(nil)
	if err == nil {
		t.Fatal("opening a missing targets file returned no error")
	}
	assertNoSteering(t, "collectTargets open", err.Error())
	if !strings.Contains(err.Error(), "failed to open targets file") {
		t.Errorf("scrubbing lost the tool's own words: %q", err.Error())
	}
}

// TestATargetsFileThatCannotBeReadScrubsItsPath drives the other half of
// collectTargets. A directory opens and then fails on read, which is the only
// way to reach the scanner's error without racing a filesystem.
func TestATargetsFileThatCannotBeReadScrubsItsPath(t *testing.T) {
	previous := targetsFile
	defer func() { targetsFile = previous }()

	dir := filepath.Join(t.TempDir(), "targets"+forgeryPathSafe)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("the fixture could not be created, so this case would measure nothing: %v", err)
	}
	targetsFile = dir

	_, err := collectTargets(nil)
	if err == nil {
		t.Fatal("reading a directory as a targets file returned no error")
	}
	// Fail loudly if the path stops reaching the read error, rather than passing
	// on an error raised somewhere earlier that never quoted the path.
	if !strings.Contains(err.Error(), "failed to read targets file") {
		t.Fatalf("the fixture no longer reaches the read error under test: %v", err)
	}
	assertNoSteering(t, "collectTargets read", err.Error())
}

// TestAnOutputFileThatCannotBeCreatedScrubsItsPath drives runScan as far as the
// output setup, which is before any socket is opened.
func TestAnOutputFileThatCannotBeCreatedScrubsItsPath(t *testing.T) {
	previousOut, previousFormat := outputFile, outputFormat
	defer func() { outputFile, outputFormat = previousOut, previousFormat }()

	outputFormat = "text"
	// A parent directory that does not exist, so os.Create fails before the scan.
	outputFile = filepath.Join(t.TempDir(), "no-such-dir"+forgery, "report.txt")

	err := runScan(rootCmd, []string{"host.invalid"})
	if err == nil {
		t.Fatal("creating a report under a missing directory returned no error")
	}
	if !strings.Contains(err.Error(), "failed to create output file") {
		t.Fatalf("the run failed somewhere other than the site under test: %v", err)
	}
	assertNoSteering(t, "runScan output file", err.Error())
}

// TestAnUnknownFormatScrubsTheValueItEchoes drives validateFormat directly.
func TestAnUnknownFormatScrubsTheValueItEchoes(t *testing.T) {
	err := validateFormat("json" + forgery)
	if err == nil {
		t.Fatal("an unknown format was accepted")
	}
	assertNoSteering(t, "validateFormat", err.Error())
	if !strings.Contains(err.Error(), "supported:") {
		t.Errorf("scrubbing lost the list of accepted values: %q", err.Error())
	}
}

// TestThePolicyGateScrubsTheTargetItNames drives policyOutcome, whose sibling
// batchOutcome has scrubbed the same field since 0.4.0 with a comment saying
// why. One variable, two print sites, one protected is this release's own
// defect shape.
func TestThePolicyGateScrubsTheTargetItNames(t *testing.T) {
	results := []*types.ScanResult{
		{
			Target:       "host" + forgery + ".invalid",
			PolicyResult: &types.PolicyResult{Compliant: false, Complete: true},
		},
		{
			Target:       "other" + forgery + ".invalid",
			PolicyResult: &types.PolicyResult{Compliant: true, Complete: false},
		},
	}

	err := policyOutcome(results)
	if err == nil {
		t.Fatal("a failing policy produced no gate error")
	}
	assertNoSteering(t, "policyOutcome", err.Error())
	if !strings.Contains(err.Error(), "policy not satisfied") {
		t.Errorf("scrubbing lost the tool's own words: %q", err.Error())
	}

	// The exit code is decided by unwrapping to this type, so the scrubbing must
	// not have replaced the error with a plain one.
	var gate *policyGateError
	if !errors.As(err, &gate) {
		t.Error("the gate error type was lost, so a policy failure would exit 1 instead of 2")
	}
}

// TestAFlagErrorScrubsTheArgumentItQuotes drives the function cobra actually
// calls. pflag quotes the offending argument back, and the invocation is one of
// the three enumerated sources of untrusted text.
func TestAFlagErrorScrubsTheArgumentItQuotes(t *testing.T) {
	err := rootCmd.FlagErrorFunc()(rootCmd, errors.New("unknown flag: --"+forgery))
	if err == nil {
		t.Fatal("no flag error function is set")
	}
	if strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("a raw escape byte reached stderr: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "--help") {
		t.Errorf("scrubbing lost the next step this message exists to give: %q", err.Error())
	}
	// The tool-authored newline before "Run 'tlsanalyzer --help'" is the
	// distinction the whole class rests on: untrusted text loses its newlines,
	// tool-authored text keeps them.
	if !strings.Contains(err.Error(), "\nRun 'tlsanalyzer --help'") {
		t.Errorf("scrubbing collapsed the tool's own newline: %q", err.Error())
	}
}
