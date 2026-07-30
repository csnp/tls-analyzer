package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
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

// runBatch collects a batch run's JSON output as the list of targets it reported,
// in the order they were reported.
func runBatch(t *testing.T, targetConcurrency int, scan scanFunc) []string {
	t.Helper()

	previousFormat, previousConcurrency, previousSkipCNSA2 := outputFormat, concurrency, skipCNSA2
	outputFormat, concurrency, skipCNSA2 = "json", targetConcurrency, true
	defer func() {
		outputFormat, concurrency, skipCNSA2 = previousFormat, previousConcurrency, previousSkipCNSA2
	}()

	var buf bytes.Buffer
	err := scanBatchTargets(context.Background(), scan,
		analyzer.NewCNSA2Analyzer(), analyzer.NewPolicyEvaluator(),
		batchTargets, nil, &buf)
	if err != nil {
		t.Fatalf("batch scan failed: %v", err)
	}

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
	return reported
}

// TestBatchOutputFollowsInputOrder guards the defect where batch output was
// collected in completion order, so two identical runs produced different output
// and a --targets sweep could not be diffed in CI.
func TestBatchOutputFollowsInputOrder(t *testing.T) {
	reported := runBatch(t, len(batchTargets), reverseCompletionScan)

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
		reported := runBatch(t, 1, func(ctx context.Context, target string) (*types.ScanResult, error) {
			return &types.ScanResult{Target: target}, nil
		})

		if !reflect.DeepEqual(reported, batchTargets) {
			t.Fatalf("run %d at --concurrency 1 returned a different order:\n  got  %v\n  want %v",
				run+1, reported, batchTargets)
		}
	}
}

// TestBatchOutputKeepsFailedTargetsInPlace checks that a target whose scan fails
// holds its slot, so an error row does not shuffle the rest of the report.
func TestBatchOutputKeepsFailedTargetsInPlace(t *testing.T) {
	reported := runBatch(t, len(batchTargets), func(ctx context.Context, target string) (*types.ScanResult, error) {
		if target == batchTargets[2] {
			return nil, context.DeadlineExceeded
		}
		return reverseCompletionScan(ctx, target)
	})

	if !reflect.DeepEqual(reported, batchTargets) {
		t.Errorf("a failed target moved the surrounding rows:\n  got  %v\n  want %v",
			reported, batchTargets)
	}
}
