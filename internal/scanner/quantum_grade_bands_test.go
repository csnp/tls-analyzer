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
// These tests pin the numbers the help text quotes. What they do NOT do, and
// what their failure messages imply they do, is read the help text: every
// assertion here calls the grader and compares against a number typed into this
// file. So they guard the grader, which never changed, and not the help, which
// is what went wrong. They pass unchanged against the tree before the fix.
//
// That direction is covered in 0.4.1 by
// cmd/tlsanalyzer/help_matches_the_grader_test.go, which parses the rendered
// help and walks both sides of every boundary it prints, and by the help being
// rendered from scanner.QuantumGradeBands rather than restated beside it.
//
// These are kept because they are still the cheaper guard on the scoring model
// itself: moving a band fails here first, and with a message that names the
// score. Their failure messages now say what they actually measured.

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
		t.Errorf("hybrid key exchange with a classical certificate scored %d, want 64. "+
			"--help renders this number from QuantumScoreFor, so moving it moves the "+
			"documentation too, and the point of pinning it here is that it should not "+
			"move silently.", assessment.Score)
	}
	if got := quantumScoreToLetter(assessment.Score); got != "Q" {
		t.Errorf("that score graded %q, want Q", got)
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
			t.Errorf("score %d graded %q, want %q. The help text renders these bands, so "+
				"this is the scoring model changing, not the documentation.",
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
			"and graded %q, want Q+", assessment.Score, got)
	}
}
