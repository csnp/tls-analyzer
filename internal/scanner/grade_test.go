package scanner

import (
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

func TestScoresToLetter(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A+"},
		{95, "A+"},
		{94, "A"},
		{85, "A"},
		{84, "B"},
		{75, "B"},
		{74, "C"},
		{60, "C"},
		{59, "D"},
		{40, "D"},
		{39, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := scoresToLetter(tt.score); got != tt.want {
				t.Errorf("scoresToLetter(%d) = %v, want %v", tt.score, got, tt.want)
			}
		})
	}
}

func TestQuantumScoreToLetter(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "Q+"},
		{80, "Q+"},
		{79, "Q"},
		{50, "Q"},
		{49, "Q-"},
		{20, "Q-"},
		{19, "QV"},
		{0, "QV"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := quantumScoreToLetter(tt.score); got != tt.want {
				t.Errorf("quantumScoreToLetter(%d) = %v, want %v", tt.score, got, tt.want)
			}
		})
	}
}

func TestScoreProtocols(t *testing.T) {
	tests := []struct {
		name      string
		protocols []types.Protocol
		wantScore int
		wantMax   int
	}{
		{
			name:      "no protocols",
			protocols: []types.Protocol{},
			wantScore: 0,
			wantMax:   25,
		},
		{
			// This asserted 15 until 0.4.0, which pinned a scoring inversion
			// rather than a judgement: TLS 1.3-only is the strictest available
			// configuration and the one the `strict` and `cnsa-2.0-2030` policies
			// require, and it was capped at 15 of 25 because the model wanted
			// TLS 1.2 alongside for the remaining ten points. Turning TLS 1.2 off
			// therefore cost ten points of the grade. TLS 1.3 now carries the full
			// dimension on its own; only deprecated versions deduct.
			name: "TLS 1.3 only",
			protocols: []types.Protocol{
				{Version: "TLS 1.3", Supported: true},
			},
			wantScore: 25,
			wantMax:   25,
		},
		{
			name: "TLS 1.3 and 1.2",
			protocols: []types.Protocol{
				{Version: "TLS 1.3", Supported: true},
				{Version: "TLS 1.2", Supported: true},
			},
			wantScore: 25,
			wantMax:   25,
		},
		{
			name: "TLS 1.2 only",
			protocols: []types.Protocol{
				{Version: "TLS 1.2", Supported: true},
			},
			wantScore: 10,
			wantMax:   25,
		},
		{
			name: "with deprecated TLS 1.0",
			protocols: []types.Protocol{
				{Version: "TLS 1.3", Supported: true},
				{Version: "TLS 1.2", Supported: true},
				{Version: "TLS 1.0", Supported: true},
			},
			wantScore: 15, // 25 - 10 penalty
			wantMax:   25,
		},
		{
			name: "with deprecated TLS 1.1",
			protocols: []types.Protocol{
				{Version: "TLS 1.3", Supported: true},
				{Version: "TLS 1.2", Supported: true},
				{Version: "TLS 1.1", Supported: true},
			},
			wantScore: 20, // 25 - 5 penalty
			wantMax:   25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, max := scoreProtocols(tt.protocols)
			if score != tt.wantScore {
				t.Errorf("scoreProtocols() score = %v, want %v", score, tt.wantScore)
			}
			if max != tt.wantMax {
				t.Errorf("scoreProtocols() max = %v, want %v", max, tt.wantMax)
			}
		})
	}
}

func TestScoreCiphers(t *testing.T) {
	tests := []struct {
		name      string
		ciphers   []types.CipherSuite
		wantScore int
		wantMax   int
	}{
		{
			name:      "no ciphers",
			ciphers:   []types.CipherSuite{},
			wantScore: 0,
			wantMax:   25,
		},
		{
			name: "strong cipher with PFS",
			ciphers: []types.CipherSuite{
				{ForwardSecrecy: true, Bits: 256, Encryption: "AES-GCM"},
			},
			wantScore: 25,
			wantMax:   25,
		},
		{
			name: "deprecated cipher",
			ciphers: []types.CipherSuite{
				{ForwardSecrecy: true, Bits: 128, Deprecated: true},
			},
			wantScore: 0, // 10 + 5 - 15 penalty = 0
			wantMax:   25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, max := scoreCiphers(tt.ciphers)
			if score != tt.wantScore {
				t.Errorf("scoreCiphers() score = %v, want %v", score, tt.wantScore)
			}
			if max != tt.wantMax {
				t.Errorf("scoreCiphers() max = %v, want %v", max, tt.wantMax)
			}
		})
	}
}

func TestScoreCertificate(t *testing.T) {
	tests := []struct {
		name      string
		cert      *types.Certificate
		wantScore int
		wantMax   int
	}{
		{
			name:      "nil certificate",
			cert:      nil,
			wantScore: 0,
			wantMax:   25,
		},
		{
			name: "expired certificate",
			cert: &types.Certificate{
				Expired: true,
			},
			wantScore: 0,
			wantMax:   25,
		},
		{
			name: "valid RSA 4096 certificate",
			cert: &types.Certificate{
				PublicKeyAlgorithm: "RSA",
				PublicKeyBits:      4096,
				SignatureAlgorithm: "SHA256WithRSA",
				DaysUntilExpiry:    365,
			},
			wantScore: 25, // 15 + 5 + 5 + 5 = 30, capped at 25
			wantMax:   25,
		},
		{
			name: "ECDSA certificate",
			cert: &types.Certificate{
				PublicKeyAlgorithm: "ECDSA",
				SignatureAlgorithm: "SHA256WithECDSA",
				DaysUntilExpiry:    365,
			},
			wantScore: 25, // 15 + 5 + 5 + 5 = 30, capped at 25
			wantMax:   25,
		},
		{
			name: "weak SHA1 signature",
			cert: &types.Certificate{
				PublicKeyAlgorithm: "RSA",
				PublicKeyBits:      2048,
				SignatureAlgorithm: "SHA1WithRSA",
				DaysUntilExpiry:    365,
			},
			wantScore: 13, // 15 + 5 + 3 - 10 = 13
			wantMax:   25,
		},
		{
			name: "self-signed certificate",
			cert: &types.Certificate{
				PublicKeyAlgorithm: "RSA",
				PublicKeyBits:      2048,
				SignatureAlgorithm: "SHA256WithRSA",
				DaysUntilExpiry:    365,
				IsSelfSigned:       true,
			},
			wantScore: 23, // 15 + 5 + 3 + 5 - 5 = 23
			wantMax:   25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, max := scoreCertificate(tt.cert)
			if score != tt.wantScore {
				t.Errorf("scoreCertificate() score = %v, want %v", score, tt.wantScore)
			}
			if max != tt.wantMax {
				t.Errorf("scoreCertificate() max = %v, want %v", max, tt.wantMax)
			}
		})
	}
}

func TestCalculateGrade(t *testing.T) {
	s := New(nil)

	// Test a good configuration
	result := &types.ScanResult{
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true},
			{Version: "TLS 1.2", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{ForwardSecrecy: true, Bits: 256, Encryption: "AES-GCM"},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			SignatureAlgorithm: "SHA256WithECDSA",
			DaysUntilExpiry:    365,
		},
		QuantumRisk: types.QuantumRiskAssessment{
			Score: 0, // Classical crypto
		},
	}

	grade := s.calculateGrade(result)

	// Should be 75/100 = B (25+25+25+0 for quantum)
	if grade.Score < 70 || grade.Score > 80 {
		t.Errorf("expected score around 75, got %d", grade.Score)
	}

	if grade.Letter != "B" && grade.Letter != "C" {
		t.Errorf("expected grade B or C, got %s", grade.Letter)
	}

	// Quantum grade should be QV (0 score)
	if grade.QuantumGrade != "QV" {
		t.Errorf("expected quantum grade QV, got %s", grade.QuantumGrade)
	}
}

func TestCalculateGradeWithVulnerabilities(t *testing.T) {
	s := New(nil)

	result := &types.ScanResult{
		Protocols: []types.Protocol{
			{Version: "TLS 1.3", Supported: true},
		},
		CipherSuites: []types.CipherSuite{
			{ForwardSecrecy: true, Bits: 256},
		},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA",
			SignatureAlgorithm: "SHA256WithECDSA",
			DaysUntilExpiry:    365,
		},
		Vulnerabilities: []types.Vulnerability{
			{Severity: types.SeverityCritical},
		},
		QuantumRisk: types.QuantumRiskAssessment{
			Score: 0,
		},
	}

	grade := s.calculateGrade(result)

	// Should have -30 penalty from critical vulnerability
	if grade.Score > 50 {
		t.Errorf("expected score < 50 with critical vuln, got %d", grade.Score)
	}
}
