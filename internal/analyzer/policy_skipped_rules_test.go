package analyzer

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names nothing that did not already exist, so it compiles against
// the pre-fix sources and fails there. The assertions that have to name the new
// fields, including the acceptance controls, are in
// policy_skipped_rules_fields_test.go.

// scanWithoutQuantumAssessment is what --skip-quantum leaves behind: everything
// else measured, and a zero-valued quantum assessment that is not a measurement
// of zero.
func scanWithoutQuantumAssessment() *types.ScanResult {
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
			// A real scan always records both checks, and this fixture stands for
			// a host where everything except the quantum assessment was measured.
			// Leaving them at the zero value would make the verdict incomplete for
			// a reason this test is not about.
			NameMatch:  types.CheckPassed,
			ChainTrust: types.CheckPassed,
		},
		QuantumRisk: types.QuantumRiskAssessment{},
	}
}

func findViolation(pr *types.PolicyResult, rule string) *types.PolicyViolation {
	for i := range pr.Violations {
		if pr.Violations[i].Rule == rule {
			return &pr.Violations[i]
		}
	}
	return nil
}

// TestAnUnmeasuredQuantumScoreIsNotFailedAsZero is the reproduction of
// "tlsanalyzer google.com --skip-quantum --policy cnsa-2.0-2035 prints
// 'Quantum Ready: not assessed' and '[HIGH] Quantum readiness score below
// minimum, Expected: >= 90 | Actual: 0' in the same report", where a full scan
// of the same host reports 64.
func TestAnUnmeasuredQuantumScoreIsNotFailedAsZero(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, ok := e.GetPolicy("cnsa-2.0-2035")
	if !ok {
		t.Fatal("built-in cnsa-2.0-2035 is missing, so this test would prove nothing")
	}
	if policy.Rules.Quantum.MinQuantumScore == 0 {
		t.Fatal("cnsa-2.0-2035 sets no minimum quantum score, so this fixture cannot " +
			"reach the rule under test and the assertion below would be vacuous")
	}

	pr := e.Evaluate(scanWithoutQuantumAssessment(), policy)

	if v := findViolation(pr, "quantum.minQuantumScore"); v != nil {
		t.Fatalf("the quantum score rule was failed against an assessment that never ran: "+
			"Expected %q, Actual %q. A sentinel zero is not a measurement, and the same "+
			"report says the assessment was not run.", v.Expected, v.Actual)
	}
}

// TestRulesReadingMeasuredInputAreStillEvaluatedWithoutTheAssessment covers the
// rest of the quantum rule group. --skip-quantum stops the risk assessment; it
// does not stop the key exchange probe or the certificate parse, so the rules
// reading those still have real input and must still be evaluated. A fix that
// skipped the whole group would pass the test above and gut the policy.
func TestRulesReadingMeasuredInputAreStillEvaluatedWithoutTheAssessment(t *testing.T) {
	e := NewPolicyEvaluator()
	policy, _ := e.GetPolicy("cnsa-2.0-2035")

	pr := e.Evaluate(scanWithoutQuantumAssessment(), policy)

	if findViolation(pr, "quantum.requireHybridKeyExchange") == nil {
		t.Error("the hybrid key exchange rule was not evaluated against a classical-only " +
			"key exchange list, which --skip-quantum does not stop the scanner measuring")
	}
	if findViolation(pr, "cipher.requiredKeyExchange") == nil &&
		len(policy.Rules.Cipher.RequiredKeyExchange) > 0 {
		t.Error("the required key exchange rule was not evaluated, though its input is measured")
	}
}
