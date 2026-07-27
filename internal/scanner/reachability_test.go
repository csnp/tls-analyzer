package scanner

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// TestUnresolvableHostIsAnError guards the defect where a host that was never
// contacted produced a confident "F (0/100), risk CRITICAL" report and exit 0.
// In a --targets sweep that made every typo'd or decommissioned host
// indistinguishable from one measured to be insecure.
func TestUnresolvableHostIsAnError(t *testing.T) {
	s := New(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := s.Scan(ctx, "this-host-does-not-exist-zzz9.invalid")
	if err == nil {
		t.Fatalf("expected an error for an unresolvable host, got a result: %+v", result)
	}
	if result != nil {
		t.Errorf("expected no result alongside the error, got %+v", result)
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("error should say the name could not be resolved, got %q", err)
	}
}

// TestAnyProtocolSupported covers the helper that decides whether a scan
// measured anything at all.
func TestAnyProtocolSupported(t *testing.T) {
	if anyProtocolSupported(nil) {
		t.Error("no protocols should not count as measured")
	}
	none := []types.Protocol{
		{Version: "TLS 1.3", Supported: false},
		{Version: "TLS 1.2", Supported: false},
	}
	if anyProtocolSupported(none) {
		t.Error("all-unsupported protocols should not count as measured")
	}
	some := []types.Protocol{
		{Version: "TLS 1.3", Supported: false},
		{Version: "TLS 1.2", Supported: true},
	}
	if !anyProtocolSupported(some) {
		t.Error("one supported protocol should count as measured")
	}
}

// TestSkippedQuantumIsExcludedFromGrade guards the defect where --skip-quantum
// left the quantum score at zero but still charged the full 25 points against
// the total, so declining to run an analysis dropped the grade a whole band.
// A check that did not run must contribute neither points nor maximum.
func TestSkippedQuantumIsExcludedFromGrade(t *testing.T) {
	result := &types.ScanResult{
		Protocols:    []types.Protocol{{Version: "TLS 1.3", Supported: true, Preferred: true}},
		CipherSuites: []types.CipherSuite{{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true}},
		Certificate: &types.Certificate{
			PublicKeyAlgorithm: "ECDSA", PublicKeyBits: 256, DaysUntilExpiry: 90,
		},
		QuantumRisk: types.QuantumRiskAssessment{Score: 0},
	}

	cfg := DefaultConfig()
	cfg.CheckQuantum = false
	skipped := New(cfg).calculateGrade(result)

	for _, f := range skipped.Factors {
		if f.Category == "Quantum Readiness" {
			t.Error("quantum readiness appears as a grade factor even though it was skipped")
		}
	}
	if skipped.Score == 0 {
		t.Error("skipping the quantum check zeroed the whole grade")
	}
}

// TestCipherSuiteBitsNeverZeroForKnownSuites guards ChaCha20 suites reporting a
// key size of 0, which made them read as weaker than AES-128 in every report
// and in policy evaluation. ChaCha20 is defined only with a 256-bit key, and
// the suite name carries no key-size token to parse.
func TestCipherSuiteBitsNeverZeroForKnownSuites(t *testing.T) {
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)

	for _, suite := range suites {
		version := uint16(tls.VersionTLS12)
		if isTLS13Suite(suite.ID) {
			version = tls.VersionTLS13
		}

		cs := parseCipherSuite(suite.ID, version)
		if cs.Bits == 0 {
			t.Errorf("%s reports 0 bits", cs.Name)
		}
		if cs.Encryption == "" {
			t.Errorf("%s reports no encryption algorithm", cs.Name)
		}
	}
}

// TestChaCha20SuitesAre256Bit pins the specific value rather than only checking
// it is non-zero.
func TestChaCha20SuitesAre256Bit(t *testing.T) {
	for _, id := range []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	} {
		cs := parseCipherSuite(id, tls.VersionTLS12)
		if isTLS13Suite(id) {
			cs = parseCipherSuite(id, tls.VersionTLS13)
		}
		if cs.Bits != 256 {
			t.Errorf("%s reports %d bits, want 256", cs.Name, cs.Bits)
		}
	}
}

// TestMergeCipherSuitesDeduplicatesAndOrders checks that the negotiated suite
// and the enumerated ones combine without duplicates and in a deterministic,
// strongest-first order.
func TestMergeCipherSuitesDeduplicatesAndOrders(t *testing.T) {
	negotiated := []types.CipherSuite{
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Bits: 128},
	}
	offered := []types.CipherSuite{
		{ID: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Bits: 256},
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Bits: 128},
		{ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Bits: 128},
	}

	first := mergeCipherSuites(negotiated, offered)
	if len(first) != 3 {
		t.Fatalf("expected 3 deduplicated suites, got %d", len(first))
	}
	if first[0].Bits != 256 {
		t.Errorf("strongest suite should sort first, got %s (%d bits)",
			first[0].Name, first[0].Bits)
	}

	for i := 0; i < 10; i++ {
		again := mergeCipherSuites(negotiated, offered)
		for j := range again {
			if again[j].Name != first[j].Name {
				t.Fatalf("ordering varies between runs at %d: %s vs %s",
					j, again[j].Name, first[j].Name)
			}
		}
	}
}

// TestApplyPortOverrideIsInScanner mirrors the CLI helper's contract at the
// level this package can see: a target already carrying a port keeps it.
func TestParseTargetKeepsExplicitPort(t *testing.T) {
	host, port, err := parseTarget("example.com:8443")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	if host != "example.com" || port != 8443 {
		t.Errorf("got %s:%d, want example.com:8443", host, port)
	}

	host, port, err = parseTarget("example.com")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	if host != "example.com" || port != 443 {
		t.Errorf("got %s:%d, want example.com:443", host, port)
	}
}

// TestSkippedQuantumProducesNoQuantumFindings guards the fabrication where a
// suppressed assessment was rendered as a negative result: the report claimed
// "QV" and recommended enabling hybrid post-quantum key exchange for servers
// that demonstrably already negotiate X25519MLKEM768, while the CNSA section of
// the same output listed that group as approved. Not measured is not absent.
func TestSkippedQuantumProducesNoQuantumFindings(t *testing.T) {
	result := &types.ScanResult{
		Protocols:    []types.Protocol{{Version: "TLS 1.3", Supported: true, Preferred: true}},
		CipherSuites: []types.CipherSuite{{Name: "TLS_AES_256_GCM_SHA384", Bits: 256, ForwardSecrecy: true}},
		KeyExchanges: []types.KeyExchange{{
			Name: "X25519MLKEM768", Type: "hybrid", QuantumSafe: true,
			PQCAlgorithm: "ML-KEM-768", Negotiated: true,
		}},
		Certificate: &types.Certificate{PublicKeyAlgorithm: "ECDSA", PublicKeyBits: 256},
	}

	cfg := DefaultConfig()
	cfg.CheckQuantum = false
	s := New(cfg)

	grade := s.calculateGrade(result)
	if grade.QuantumGrade == "QV" {
		t.Error("a skipped quantum assessment was graded quantum vulnerable")
	}
	if grade.QuantumGrade != "not assessed" {
		t.Errorf("quantumGrade = %q, want \"not assessed\"", grade.QuantumGrade)
	}

	for _, rec := range s.generateRecommendations(result) {
		if rec.Category == "quantum" {
			t.Errorf("skipped quantum assessment still produced a quantum recommendation: %q",
				rec.Title)
		}
	}
}
