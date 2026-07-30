package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// batchTargets is deliberately more than a handful, so an ordering that happens
// to come out right by chance is vanishingly unlikely.
var batchTargets = []string{
	"a.example", "b.example", "c.example", "d.example", "e.example", "f.example",
}

// reverseCompletionScan finishes the targets in the exact reverse of the order
// they were given, by giving the first target the longest delay.
//
// This is the whole point of taking the scan as a function: a real scan finishes
// in whatever order the network allows, so nothing about it can prove an ordering
// fix. Forcing the worst case makes the pre-fix behaviour fail every time rather
// than most of the time.
func reverseCompletionScan(ctx context.Context, target string) (*types.ScanResult, error) {
	for i, name := range batchTargets {
		if name == target {
			time.Sleep(time.Duration(len(batchTargets)-i) * 15 * time.Millisecond)
			break
		}
	}
	return &types.ScanResult{Target: target}, nil
}

// runBatch collects a batch run's JSON output as the list of targets it
// reported, in the order they were reported, along with the run's outcome.
//
// The outcome is returned rather than fataled on, because a run containing a
// failed target is supposed to produce one, and swallowing it here is what let
// the JSON output path exit 0 on a failed target while the text path exited 1.
func runBatch(t *testing.T, targetConcurrency int, scan scanFunc) ([]string, error) {
	t.Helper()

	previousFormat, previousConcurrency, previousSkipCNSA2 := outputFormat, concurrency, skipCNSA2
	outputFormat, concurrency, skipCNSA2 = "json", targetConcurrency, true
	defer func() {
		outputFormat, concurrency, skipCNSA2 = previousFormat, previousConcurrency, previousSkipCNSA2
	}()

	var buf bytes.Buffer
	outcome := scanBatchTargets(context.Background(), scan,
		analyzer.NewCNSA2Analyzer(), analyzer.NewPolicyEvaluator(),
		batchTargets, nil, &buf)

	// Only the target is decoded, so a failure here is unambiguously about
	// ordering rather than about any other field's representation.
	var results []struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(buf.Bytes(), &results); err != nil {
		t.Fatalf("batch JSON output did not parse: %v", err)
	}

	reported := make([]string, 0, len(results))
	for _, result := range results {
		reported = append(reported, result.Target)
	}
	return reported, outcome
}

// TestBatchOutputFollowsInputOrder guards the defect where batch output was
// collected in completion order, so two identical runs produced different output
// and a --targets sweep could not be diffed in CI.
func TestBatchOutputFollowsInputOrder(t *testing.T) {
	reported, err := runBatch(t, len(batchTargets), reverseCompletionScan)
	if err != nil {
		t.Fatalf("batch scan failed with every target succeeding: %v", err)
	}

	if !reflect.DeepEqual(reported, batchTargets) {
		t.Errorf("batch output is in completion order, not input order:\n  got  %v\n  want %v",
			reported, batchTargets)
	}
}

// TestBatchOutputFollowsInputOrderAtConcurrencyOne covers the reported case
// specifically. --concurrency 1 reads as "do these one at a time in order" and
// did not preserve the order either, because the semaphore does not hand out its
// slot in the order goroutines queued for it.
func TestBatchOutputFollowsInputOrderAtConcurrencyOne(t *testing.T) {
	for run := 0; run < 3; run++ {
		reported, err := runBatch(t, 1, func(ctx context.Context, target string) (*types.ScanResult, error) {
			return &types.ScanResult{Target: target}, nil
		})
		if err != nil {
			t.Fatalf("run %d failed with every target succeeding: %v", run+1, err)
		}

		if !reflect.DeepEqual(reported, batchTargets) {
			t.Fatalf("run %d at --concurrency 1 returned a different order:\n  got  %v\n  want %v",
				run+1, reported, batchTargets)
		}
	}
}

// TestBatchOutputKeepsFailedTargetsInPlace checks that a target whose scan fails
// holds its slot, so an error row does not shuffle the rest of the report.
func TestBatchOutputKeepsFailedTargetsInPlace(t *testing.T) {
	reported, err := runBatch(t, len(batchTargets), func(ctx context.Context, target string) (*types.ScanResult, error) {
		if target == batchTargets[2] {
			return nil, context.DeadlineExceeded
		}
		return reverseCompletionScan(ctx, target)
	})

	// The JSON output path returned the encoder's error and nothing else, so a
	// sweep that could not reach a host exited 0 while the same sweep in text
	// format exited 1. Verified on released 0.3.0 (both formats exit 0) and on
	// this branch before the fix (text 1, JSON 0), so the batch fix landed on
	// one of the two output paths.
	if err == nil {
		t.Error("a batch run in --format json with an unreachable target reported success, " +
			"so 'tlsanalyzer --targets hosts.txt --format json && deploy' proceeds on a " +
			"scan that never reached the host")
	} else if !strings.Contains(err.Error(), batchTargets[2]) {
		t.Errorf("the error does not name the target that failed: %v", err)
	}

	if !reflect.DeepEqual(reported, batchTargets) {
		t.Errorf("a failed target moved the surrounding rows:\n  got  %v\n  want %v",
			reported, batchTargets)
	}
}

// TestBatchFailsWhenATargetCouldNotBeScanned guards the defect where a sweep
// exited 0 with nothing on stderr even when every target failed, so
// "tlsanalyzer --targets hosts.txt && deploy" proceeded on a scan that measured
// nothing. The single-target path has always exited non-zero for the same
// failure.
func TestBatchFailsWhenATargetCouldNotBeScanned(t *testing.T) {
	tests := []struct {
		name      string
		failing   map[string]bool
		wantError bool
		wantNames []string
	}{
		{"all succeed", nil, false, nil},
		{"one fails", map[string]bool{batchTargets[2]: true}, true, []string{batchTargets[2]}},
		{"all fail", map[string]bool{
			batchTargets[0]: true, batchTargets[1]: true, batchTargets[2]: true,
			batchTargets[3]: true, batchTargets[4]: true, batchTargets[5]: true,
		}, true, batchTargets},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := make([]*types.ScanResult, 0, len(batchTargets))
			for _, target := range batchTargets {
				result := &types.ScanResult{Target: target}
				if tt.failing[target] {
					result.Error = "cannot resolve " + target
				}
				results = append(results, result)
			}

			err := batchOutcome(results)
			if tt.wantError && err == nil {
				t.Fatalf("batchOutcome returned no error with %d failing targets", len(tt.failing))
			}
			if !tt.wantError {
				if err != nil {
					t.Fatalf("batchOutcome failed a run where every target succeeded: %v", err)
				}
				return
			}

			// The message has to name what failed, or an operator cannot act on it.
			for _, name := range tt.wantNames {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("the error does not name the failed target %q: %v", name, err)
				}
			}
		})
	}
}

// TestNumericFlagBoundsAreValidated pins the bounds on the flags that could take
// an unusable value. --concurrency 0 hung forever on an unbuffered semaphore with
// nothing on either stream, --concurrency -1 panicked out of make() with a stack
// trace that printed absolute source paths, and --timeout 0 or negative meant no
// timeout at all, so one unresponsive host wedged a whole sweep.
func TestNumericFlagBoundsAreValidated(t *testing.T) {
	previousConcurrency, previousTimeout := concurrency, timeout
	defer func() { concurrency, timeout = previousConcurrency, previousTimeout }()

	tests := []struct {
		name                 string
		concurrency, timeout int
		wantRefused          bool
	}{
		{"defaults accepted", 10, 30, false},
		{"minimum accepted", 1, 1, false},
		{"zero concurrency refused", 0, 30, true},
		{"negative concurrency refused", -1, 30, true},
		{"zero timeout refused", 10, 0, true},
		{"negative timeout refused", 10, -5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concurrency, timeout = tt.concurrency, tt.timeout

			// runScan reaches the bounds checks before any network work, so an
			// empty target list is enough to exercise them: a refused value must
			// fail on its own message, not on "no targets specified".
			err := runScan(rootCmd, nil)
			if err == nil {
				t.Fatal("runScan returned no error at all")
			}

			named := strings.Contains(err.Error(), "--concurrency") ||
				strings.Contains(err.Error(), "--timeout")
			if tt.wantRefused && !named {
				t.Errorf("concurrency %d / timeout %d was not refused by name; got: %v",
					tt.concurrency, tt.timeout, err)
			}
			if !tt.wantRefused && named {
				t.Errorf("a valid concurrency %d / timeout %d was refused: %v",
					tt.concurrency, tt.timeout, err)
			}
		})
	}
}
