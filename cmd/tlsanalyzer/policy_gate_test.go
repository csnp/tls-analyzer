package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// A compliance check that cannot fail a build is not a gate. --policy reported
// 35 HIGH violations and exited 0, so "tlsanalyzer host --policy strict &&
// deploy" deployed. These tests pin the outcome each combination produces, and
// that the failing ones are distinguishable from a scan that could not run.

func gateResult(target string, compliant, complete bool) *types.ScanResult {
	return &types.ScanResult{
		Target: target,
		PolicyResult: &types.PolicyResult{
			PolicyName: "cnsa-2.0-2035",
			Compliant:  compliant,
			Complete:   complete,
		},
	}
}

func TestPolicyOutcomeFailsOnlyWhenComplianceIsNotEstablished(t *testing.T) {
	tests := []struct {
		name       string
		results    []*types.ScanResult
		wantFail   bool
		wantNamed  []string
		wantReason string
	}{
		{
			name:    "no policy applied",
			results: []*types.ScanResult{{Target: "a.example"}},
		},
		{
			name:    "compliant and fully evaluated",
			results: []*types.ScanResult{gateResult("a.example", true, true)},
		},
		{
			name:       "not compliant",
			results:    []*types.ScanResult{gateResult("a.example", false, true)},
			wantFail:   true,
			wantNamed:  []string{"a.example"},
			wantReason: "not satisfied",
		},
		{
			name:    "compliant but not fully evaluated",
			results: []*types.ScanResult{gateResult("a.example", true, false)},
			// A verdict that skipped rules has not established compliance with
			// the policy, only with the part of it that ran, and the policy
			// score can only rise when a rule is not evaluated.
			wantFail:   true,
			wantNamed:  []string{"a.example"},
			wantReason: "compliance is not established",
		},
		{
			name: "one of each across a batch",
			results: []*types.ScanResult{
				gateResult("ok.example", true, true),
				gateResult("bad.example", false, true),
				gateResult("partial.example", true, false),
			},
			wantFail:  true,
			wantNamed: []string{"bad.example", "partial.example"},
		},
		{
			name: "a target that was never scanned carries no verdict",
			results: []*types.ScanResult{
				{Target: "unreachable.example", Error: "cannot resolve unreachable.example"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := policyOutcome(tt.results)

			if !tt.wantFail {
				if err != nil {
					t.Fatalf("the gate failed a run where compliance was established: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("the gate passed, so a pipeline gated on this command proceeds")
			}

			var gate *policyGateError
			if !errors.As(err, &gate) {
				t.Fatalf("the failure is not distinguishable from a scan failure, so it "+
					"cannot carry its own exit code: %T %v", err, err)
			}
			for _, name := range tt.wantNamed {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("the message does not name %q: %v", name, err)
				}
			}
			if tt.wantReason != "" && !strings.Contains(err.Error(), tt.wantReason) {
				t.Errorf("the message does not say %q: %v", tt.wantReason, err)
			}
		})
	}
}

// TestScanFailureOutranksThePolicyGate keeps the two failures in the right
// order. A target that was never reached has no policy verdict, and reporting
// it as non-compliant would be a verdict about nothing.
func TestScanFailureOutranksThePolicyGate(t *testing.T) {
	results := []*types.ScanResult{
		{Target: "unreachable.example", Error: "cannot resolve unreachable.example"},
		gateResult("bad.example", false, true),
	}

	err := batchOutcome(results)
	if err == nil {
		t.Fatal("a batch with an unreachable target reported success")
	}

	var gate *policyGateError
	if errors.As(err, &gate) {
		t.Fatalf("a run that could not scan a target reported a policy failure instead, "+
			"which would exit %d and tell an operator their configuration is wrong "+
			"rather than that the scan did not happen: %v", exitPolicyFailed, err)
	}
	if !strings.Contains(err.Error(), "unreachable.example") {
		t.Errorf("the error does not name the target that could not be scanned: %v", err)
	}
}

// TestSingleTargetPolicyGateReportsBeforeItFails covers the path a single-host
// run takes. The gate has to be applied there too, and the report has to be
// written first: an operator handed exit 2 with no findings cannot act on it.
func TestSingleTargetPolicyGateReportsBeforeItFails(t *testing.T) {
	previousFormat, previousSkipCNSA2 := outputFormat, skipCNSA2
	outputFormat, skipCNSA2 = "json", true
	defer func() { outputFormat, skipCNSA2 = previousFormat, previousSkipCNSA2 }()

	scan := func(ctx context.Context, target string) (*types.ScanResult, error) {
		return &types.ScanResult{
			Target: target,
			Protocols: []types.Protocol{
				{Version: "TLS 1.0", Supported: true},
			},
			QuantumRisk: types.QuantumRiskAssessment{Assessed: true},
		}, nil
	}

	evaluator := analyzer.NewPolicyEvaluator()
	policy, ok := evaluator.GetPolicy("modern")
	if !ok {
		t.Fatal("built-in modern is missing")
	}

	var buf bytes.Buffer
	err := scanSingleTarget(context.Background(), scan,
		analyzer.NewCNSA2Analyzer(), evaluator, "a.example", policy, &buf)

	if buf.Len() == 0 {
		t.Error("nothing was written to the report, so a failing gate gives an operator " +
			"an exit code and no findings")
	}

	var gate *policyGateError
	if !errors.As(err, &gate) {
		t.Fatalf("a single-target run against a policy the host fails did not fail the "+
			"gate: %v", err)
	}
}

// TestSingleTargetPolicyGatePassesACompliantHost is the acceptance control for
// the case above.
func TestSingleTargetPolicyGatePassesACompliantHost(t *testing.T) {
	previousFormat, previousSkipCNSA2 := outputFormat, skipCNSA2
	outputFormat, skipCNSA2 = "json", true
	defer func() { outputFormat, skipCNSA2 = previousFormat, previousSkipCNSA2 }()

	scan := func(ctx context.Context, target string) (*types.ScanResult, error) {
		return &types.ScanResult{
			Target: target,
			Protocols: []types.Protocol{
				{Version: "TLS 1.3", Supported: true, Preferred: true},
				{Version: "TLS 1.2", Supported: true},
			},
			CipherSuites: []types.CipherSuite{{
				Name: "TLS_AES_256_GCM_SHA384", Bits: 256,
				ForwardSecrecy: true, Encryption: "AES", KeyExchange: "ECDHE",
			}},
			Certificate: &types.Certificate{
				PublicKeyAlgorithm: "ECDSA", PublicKeyBits: 384,
				SignatureAlgorithm: "ECDSA-SHA384", DaysUntilExpiry: 90,
				// This host is meant to satisfy the policy outright, and a real
				// scan of such a host records both certificate checks as passed.
				NameMatch: types.CheckPassed, ChainTrust: types.CheckPassed,
			},
			QuantumRisk: types.QuantumRiskAssessment{Assessed: true, Score: 50},
		}, nil
	}

	evaluator := analyzer.NewPolicyEvaluator()
	policy, _ := evaluator.GetPolicy("modern")

	var buf bytes.Buffer
	if err := scanSingleTarget(context.Background(), scan,
		analyzer.NewCNSA2Analyzer(), evaluator, "a.example", policy, &buf); err != nil {
		t.Fatalf("a host that satisfies the policy failed the gate: %v", err)
	}
}

// TestTheTwoFailureExitCodesAreDistinct guards the contract documented in
// --help and the README. A single non-zero code would make a failed policy
// indistinguishable from an unreachable host in CI.
func TestTheTwoFailureExitCodesAreDistinct(t *testing.T) {
	if exitScanFailed == exitPolicyFailed {
		t.Fatal("the scan-failure and policy-failure exit codes are the same")
	}
	if exitScanFailed == 0 || exitPolicyFailed == 0 {
		t.Fatal("a failure exit code is 0, so the gate cannot fail a build")
	}
}
