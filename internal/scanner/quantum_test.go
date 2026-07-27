package scanner

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func TestQuantumVulnerableAlgorithms(t *testing.T) {
	// Ensure all expected vulnerable algorithms are present
	expected := []string{"RSA", "ECDSA", "ECDH", "DSA", "DH"}
	for _, algo := range expected {
		if _, ok := QuantumVulnerableAlgorithms[algo]; !ok {
			t.Errorf("expected %s to be in QuantumVulnerableAlgorithms", algo)
		}
	}
}

func TestQuantumSafeAlgorithms(t *testing.T) {
	// Ensure PQC algorithms are present
	expected := []string{"ML-KEM", "ML-DSA", "SLH-DSA", "AES-256", "ChaCha20"}
	for _, algo := range expected {
		if _, ok := QuantumSafeAlgorithms[algo]; !ok {
			t.Errorf("expected %s to be in QuantumSafeAlgorithms", algo)
		}
	}
}

func TestHybridKeyExchanges(t *testing.T) {
	tests := []struct {
		name      string
		classical string
		pqc       string
	}{
		{"X25519MLKEM768", "X25519", "ML-KEM-768"},
		{"SecP256r1MLKEM768", "P-256", "ML-KEM-768"},
		{"SecP384r1MLKEM1024", "P-384", "ML-KEM-1024"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ke, ok := HybridKeyExchanges[tt.name]
			if !ok {
				t.Fatalf("expected %s to be in HybridKeyExchanges", tt.name)
			}
			if ke.Classical != tt.classical {
				t.Errorf("expected classical %s, got %s", tt.classical, ke.Classical)
			}
			if ke.PQC != tt.pqc {
				t.Errorf("expected PQC %s, got %s", tt.pqc, ke.PQC)
			}
		})
	}
}

func TestAssessQuantumRisk(t *testing.T) {
	s := New(nil)

	tests := []struct {
		name        string
		result      *types.ScanResult
		wantLevel   types.RiskLevel
		wantHybrid  bool
		wantFullPQC bool
	}{
		{
			name: "classical only - critical risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{Name: "X25519", Type: "classical"},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			wantLevel:   types.RiskCritical,
			wantHybrid:  false,
			wantFullPQC: false,
		},
		{
			name: "hybrid key exchange with classical certificate - medium risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{
						Name:            "X25519MLKEM768",
						Type:            "hybrid",
						HybridClassical: "X25519",
						PQCAlgorithm:    "ML-KEM-768",
					},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			// Hybrid ML-KEM key exchange removes the harvest-now-decrypt-later
			// exposure, which is the only retroactive quantum risk. The
			// certificate is still classical, but no publicly trusted CA issues
			// ML-DSA certificates yet, so this is the strongest posture a real
			// deployment can hold today and must not grade as HIGH or CRITICAL.
			wantLevel:   types.RiskMedium,
			wantHybrid:  true,
			wantFullPQC: false,
		},
		{
			name: "full PQC key exchange with classical certificate - low risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{
						Name:         "ML-KEM-768",
						Type:         "pqc",
						PQCAlgorithm: "ML-KEM-768",
					},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			// Full post-quantum key exchange leaves no retroactive exposure.
			// The remaining risk is signature forgery by a future quantum
			// computer, which is not retroactive and cannot be remediated until
			// CAs issue post-quantum certificates. FullPQCReady stays the signal
			// that distinguishes this from a fully post-quantum deployment.
			wantLevel:   types.RiskLow,
			wantHybrid:  false,
			wantFullPQC: true,
		},
		{
			name: "full PQC everything - very low risk",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{
					{
						Name:         "ML-KEM-768",
						Type:         "pqc",
						PQCAlgorithm: "ML-KEM-768",
					},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "ML-DSA",
				},
			},
			wantLevel:   types.RiskLow,
			wantHybrid:  false,
			wantFullPQC: true,
		},
		{
			name: "no key exchanges - infer from ciphers",
			result: &types.ScanResult{
				KeyExchanges: []types.KeyExchange{},
				CipherSuites: []types.CipherSuite{
					{KeyExchange: "ECDHE"},
				},
				Certificate: &types.Certificate{
					PublicKeyAlgorithm: "RSA",
				},
			},
			wantLevel:   types.RiskCritical,
			wantHybrid:  false,
			wantFullPQC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := s.assessQuantumRisk(tt.result)

			if assessment.Level != tt.wantLevel {
				t.Errorf("expected level %s, got %s", tt.wantLevel, assessment.Level)
			}
			if assessment.HybridPQCReady != tt.wantHybrid {
				t.Errorf("expected HybridPQCReady %v, got %v", tt.wantHybrid, assessment.HybridPQCReady)
			}
			if assessment.FullPQCReady != tt.wantFullPQC {
				t.Errorf("expected FullPQCReady %v, got %v", tt.wantFullPQC, assessment.FullPQCReady)
			}
		})
	}
}

func TestDescribeKeyExchangeRisk(t *testing.T) {
	tests := []struct {
		score    int
		contains string
	}{
		{100, "LOW"},
		{80, "LOW"},
		{50, "MEDIUM"},
		{0, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := describeKeyExchangeRisk(tt.score)
			if !containsAny(result, tt.contains) {
				t.Errorf("expected result to contain %s, got %s", tt.contains, result)
			}
		})
	}
}

func TestDescribeCertificateRisk(t *testing.T) {
	tests := []struct {
		score    int
		contains string
	}{
		{100, "LOW"},
		{80, "LOW"},
		{50, "MEDIUM"},
		{0, "HIGH"},
	}

	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := describeCertificateRisk(tt.score)
			if !containsAny(result, tt.contains) {
				t.Errorf("expected result to contain %s, got %s", tt.contains, result)
			}
		})
	}
}

func TestRecommendTimeToAction(t *testing.T) {
	tests := []struct {
		name             string
		keyExchangeScore int
		certScore        int
		contains         string
	}{
		{"full pqc both dimensions", 100, 100, "MONITORING"},
		{"hybrid key exchange deployed", 80, 0, "MONITORING"},
		{"partial key exchange progress", 50, 0, "12-24 MONTHS"},
		{"fully classical", 0, 0, "IMMEDIATE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := recommendTimeToAction(tt.keyExchangeScore, tt.certScore)
			if !containsAny(result, tt.contains) {
				t.Errorf("expected result to contain %s, got %s", tt.contains, result)
			}
		})
	}
}

// TestHybridServerNotToldToDeployHybrid guards the advice regression that
// shipped before: a server already running a hybrid ML-KEM key exchange was
// scored HIGH risk and told to "begin hybrid PQC implementation", work it had
// already completed. No public CA issues ML-DSA certificates yet, so a
// classical certificate must not drag a hybrid deployment into a failing
// verdict or produce advice the operator cannot act on.
func TestHybridServerNotToldToDeployHybrid(t *testing.T) {
	s := New(DefaultConfig())
	result := &types.ScanResult{
		KeyExchanges: []types.KeyExchange{
			{
				Name: "X25519MLKEM768", Type: "hybrid", QuantumSafe: true,
				PQCAlgorithm: "ML-KEM-768", HybridClassical: "X25519", Negotiated: true,
			},
			{Name: "X25519", Type: "classical"},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			SignatureAlgorithm: "ECDSA-SHA256",
		},
		CipherSuites: []types.CipherSuite{{ForwardSecrecy: true}},
	}

	assessment := s.assessQuantumRisk(result)

	if !assessment.HybridPQCReady {
		t.Error("hybrid key exchange present but HybridPQCReady is false")
	}
	if assessment.Level == types.RiskCritical || assessment.Level == types.RiskHigh {
		t.Errorf("server running hybrid PQC graded %s; expected MEDIUM or better",
			assessment.Level)
	}
	if containsAny(assessment.TimeToAction, "Begin hybrid", "begin hybrid") {
		t.Errorf("advice tells a hybrid-enabled server to deploy hybrid: %s",
			assessment.TimeToAction)
	}
	if !containsAny(assessment.HNDLRisk, "LOW") {
		t.Errorf("hybrid key exchange should reduce HNDL risk, got %s", assessment.HNDLRisk)
	}
}

// TestClassicalOnlyStaysCritical is the other half of the guard: relaxing the
// certificate weighting must not soften the verdict for a server that has done
// nothing, since its recorded traffic is already exposed.
func TestClassicalOnlyStaysCritical(t *testing.T) {
	s := New(DefaultConfig())
	result := &types.ScanResult{
		KeyExchanges: []types.KeyExchange{{Name: "X25519", Type: "classical"}},
		Certificate:  &types.Certificate{PublicKeyAlgorithm: "RSA"},
	}

	assessment := s.assessQuantumRisk(result)

	if assessment.Level != types.RiskCritical {
		t.Errorf("classical-only server graded %s; expected CRITICAL", assessment.Level)
	}
	if !containsAny(assessment.TimeToAction, "IMMEDIATE") {
		t.Errorf("classical-only server should require immediate action, got %s",
			assessment.TimeToAction)
	}
}
