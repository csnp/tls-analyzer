package analyzer

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names nothing that did not already exist, so it compiles against the
// pre-fix sources and fails there on behaviour.
//
// The defect: evaluateCertificate read certificate.nameMatch and
// certificate.chainTrust only for CheckFailed. CheckNotPerformed was neither a
// violation nor a skipped rule, here and in every other consumer, so a check
// that did not run was indistinguishable from one that passed, all the way to
// the exit code. That is the second half of the expired-intermediate CRITICAL:
// even with the chain result correct, the policy gate had no way to fail on it.

// scanWithChainCheckResult is a host that satisfies every rule a policy can
// state about it, with the two certificate checks supplied by the caller.
func scanWithChainCheckResult(nameMatch, chainTrust types.CheckResult) *types.ScanResult {
	return &types.ScanResult{
		Target: "example.com",
		Host:   "example.com",
		Port:   443,
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true, Preferred: true},
			{Version: "TLS 1.2", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true, Encryption: "AES"},
		},
		KeyExchanges: []types.KeyExchange{
			{Name: "X25519", Type: "classical"},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      384,
			SignatureAlgorithm: "ECDSA-SHA384",
			DaysUntilExpiry:    90,
			RequestedName:      "example.com",
			NameMatch:          nameMatch,
			ChainTrust:         chainTrust,
		},
		QuantumRisk: types.QuantumRiskAssessment{Assessed: true, Score: 64},
	}
}

func findSkippedRule(pr *types.PolicyResult, rule string) *types.SkippedPolicyRule {
	for i := range pr.SkippedRules {
		if pr.SkippedRules[i].Rule == rule {
			return &pr.SkippedRules[i]
		}
	}
	return nil
}

// TestAnUnperformedChainCheckMakesTheVerdictIncomplete is the reproduction.
// Before the fix this returned Compliant with Complete true, so the gate exited
// 0 on a scan that never established the chain builds to a trusted root.
func TestAnUnperformedChainCheckMakesTheVerdictIncomplete(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("modern")
	if !ok {
		t.Fatal("built-in modern is missing, so this test would prove nothing")
	}

	pr := e.Evaluate(scanWithChainCheckResult(types.CheckPassed, types.CheckNotPerformed), policy)

	if findSkippedRule(pr, "certificate.chainTrust") == nil {
		t.Errorf("a chain check that did not run was not recorded as a skipped rule; "+
			"skipped=%v", pr.SkippedRules)
	}
	if pr.Complete {
		t.Errorf("the verdict claims to be a complete evaluation while the chain check did " +
			"not run, so a compliant verdict here exits 0 without establishing compliance")
	}
}

// TestAnUnperformedNameCheckMakesTheVerdictIncomplete covers the sibling check.
// A fix reaching only chainTrust would leave the same hole one field over.
func TestAnUnperformedNameCheckMakesTheVerdictIncomplete(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("modern")
	if !ok {
		t.Fatal("built-in modern is missing, so this test would prove nothing")
	}

	pr := e.Evaluate(scanWithChainCheckResult(types.CheckNotPerformed, types.CheckPassed), policy)

	if findSkippedRule(pr, "certificate.nameMatch") == nil {
		t.Errorf("a name check that did not run was not recorded as a skipped rule; "+
			"skipped=%v", pr.SkippedRules)
	}
	if pr.Complete {
		t.Errorf("the verdict claims to be a complete evaluation while the name check did not run")
	}
}

// TestAnUnsetCheckResultIsNotReadAsAPass covers the zero value. CheckResult is a
// string and its zero value is "", not CheckNotPerformed, so a Certificate built
// by a consumer of pkg/types that never set these fields must not be read as
// having passed them. Listing CheckNotPerformed as the only skipping arm would
// pass both tests above and leave this open.
func TestAnUnsetCheckResultIsNotReadAsAPass(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("modern")
	if !ok {
		t.Fatal("built-in modern is missing, so this test would prove nothing")
	}

	var unset types.CheckResult
	if unset == types.CheckNotPerformed || unset == types.CheckPassed {
		t.Fatalf("the zero value of CheckResult is %q, so this test is not about what it says",
			unset)
	}

	pr := e.Evaluate(scanWithChainCheckResult(unset, unset), policy)

	// Assert each check separately. Complete is a single aggregate over both, so
	// asserting only that would still hold with one of the two arms broken, and a
	// mutation that made exactly one of them read "" as a pass survived this test
	// until it named them individually.
	for _, rule := range []string{"certificate.nameMatch", "certificate.chainTrust"} {
		if findSkippedRule(pr, rule) == nil {
			t.Errorf("%s was not recorded as skipped for a certificate whose check was never "+
				"set, so the zero value reads as a pass; skipped=%v", rule, pr.SkippedRules)
		}
	}
	if pr.Complete {
		t.Errorf("a certificate whose checks were never recorded produced a complete verdict, "+
			"so an unset field reads as a pass; skipped=%v", pr.SkippedRules)
	}
}

// TestBothCertificateChecksPassedSkipsNeither is the control. A fix that skipped
// unconditionally would pass every assertion above and make every healthy scan
// incomplete, which would fail the gate on every compliant host.
func TestBothCertificateChecksPassedSkipsNeither(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("modern")
	if !ok {
		t.Fatal("built-in modern is missing, so this test would prove nothing")
	}

	pr := e.Evaluate(scanWithChainCheckResult(types.CheckPassed, types.CheckPassed), policy)

	for _, rule := range []string{"certificate.nameMatch", "certificate.chainTrust"} {
		if s := findSkippedRule(pr, rule); s != nil {
			t.Errorf("%s was recorded as skipped for a scan that performed it: %q", rule, s.Reason)
		}
	}
	if !pr.Complete {
		t.Errorf("a scan that performed both certificate checks produced an incomplete "+
			"verdict; skipped=%v", pr.SkippedRules)
	}
}

// TestAFailedChainCheckIsStillAViolationNotASkip keeps the three states
// distinct. Turning CheckFailed into a skip would make the gate report "could
// not be fully evaluated" for a chain it evaluated and rejected, which is a
// weaker statement than the truth.
func TestAFailedChainCheckIsStillAViolationNotASkip(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("modern")
	if !ok {
		t.Fatal("built-in modern is missing, so this test would prove nothing")
	}

	result := scanWithChainCheckResult(types.CheckPassed, types.CheckFailed)
	result.Certificate.ChainTrustReason = `the chain certificate "Example Intermediate CA" ` +
		`expired on 2026-07-04, so the chain does not build to a trusted root`

	pr := e.Evaluate(result, policy)

	v := findViolation(pr, "certificate.chainTrust")
	if v == nil {
		t.Fatalf("a failed chain check raised no violation; violations=%v", pr.Violations)
	}
	if findSkippedRule(pr, "certificate.chainTrust") != nil {
		t.Errorf("a chain check that ran and failed was also recorded as not evaluated")
	}
	if pr.Compliant {
		t.Errorf("a scan whose chain check failed was reported compliant")
	}

	// The operator has to learn WHICH certificate failed. Every other field of
	// the report describes the leaf, and for an expired intermediate the leaf is
	// perfectly healthy, so this string is the only place it appears.
	if !strings.Contains(v.Actual, "Example Intermediate CA") {
		t.Errorf("the violation's Actual is %q, which discards the reason naming the "+
			"certificate at fault", v.Actual)
	}
}
