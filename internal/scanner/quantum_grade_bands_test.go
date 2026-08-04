package scanner

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The --help text states what each Quantum Ready grade requires, and it stated
// something the grader does not do: "Q+ ready: hybrid or full PQC key exchange
// in place". A server with hybrid key exchange deployed reports
// hybridPqcReady=true and grades Q, because the grade comes from the quantum
// readiness score and hybrid key exchange with a classical certificate scores
// 64. Every hybrid host tested graded Q; Q+ was never observed.
//
// These tests pin the numbers the help text now quotes. If the weighting or the
// bands change, the help text has to change with them, and this is what says so.

// TestHybridKeyExchangeWithAClassicalCertificateScores64 pins the number the
// help text quotes for the common real-world case.
func TestHybridKeyExchangeWithAClassicalCertificateScores64(t *testing.T) {
	s := &Scanner{config: &Config{CheckQuantum: true}}
	result := &types.ScanResult{
		Host: "example.com",
		Port: 443,
		KeyExchanges: []types.KeyExchange{
			{Name: "X25519MLKEM768", Type: "hybrid", PQCAlgorithm: "ML-KEM-768",
				HybridClassical: "X25519", Negotiated: true},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			SignatureAlgorithm: "ECDSA-SHA384",
			QuantumSafe:        false,
		},
	}

	assessment := s.assessQuantumRisk(result)
	if assessment.Score != 64 {
		t.Errorf("hybrid key exchange with a classical certificate scored %d, but --help "+
			"tells the user it scores 64. One of the two is now wrong.", assessment.Score)
	}
	if got := quantumScoreToLetter(assessment.Score); got != "Q" {
		t.Errorf("that score graded %q, but --help tells the user it grades Q", got)
	}
	if !assessment.HybridPQCReady {
		t.Fatal("the fixture did not register as hybrid, so this test is not measuring " +
			"what it says")
	}
}

// TestTheQuantumGradeBandsAreWhatHelpSays pins the boundaries themselves, from
// both sides, so a band cannot move without this failing.
func TestTheQuantumGradeBandsAreWhatHelpSays(t *testing.T) {
	for _, tc := range []struct {
		score int
		want  string
	}{
		{100, "Q+"}, {80, "Q+"}, {79, "Q"},
		{50, "Q"}, {49, "Q-"},
		{20, "Q-"}, {19, "QV"},
		{0, "QV"},
	} {
		if got := quantumScoreToLetter(tc.score); got != tc.want {
			t.Errorf("score %d graded %q, but --help documents the bands as "+
				"Q+ 80-100, Q 50-79, Q- 20-49, QV below 20, which makes it %q",
				tc.score, got, tc.want)
		}
	}
}

// TestQPlusIsReachableWithoutAPostQuantumCertificate is the assertion that
// caught a false correction. The help text first said Q+ additionally requires a
// post-quantum certificate. It does not: the key exchange carries 80 of the
// score, so a full PQC key exchange reaches exactly 80 with a classical
// certificate. Replacing one false claim in the help with another is the defect
// this release keeps finding, so the corrected claim is pinned too.
func TestQPlusIsReachableWithoutAPostQuantumCertificate(t *testing.T) {
	s := &Scanner{config: &Config{CheckQuantum: true}}
	result := &types.ScanResult{
		Host: "example.com",
		Port: 443,
		KeyExchanges: []types.KeyExchange{
			{Name: "ML-KEM-1024", Type: "pqc", PQCAlgorithm: "ML-KEM-1024", Negotiated: true},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			SignatureAlgorithm: "ECDSA-SHA384",
			QuantumSafe:        false,
		},
	}

	assessment := s.assessQuantumRisk(result)
	if got := quantumScoreToLetter(assessment.Score); got != "Q+" {
		t.Errorf("a full post-quantum key exchange with a classical certificate scored %d "+
			"and graded %q, but --help tells the user this reaches Q+",
			assessment.Score, got)
	}
}
