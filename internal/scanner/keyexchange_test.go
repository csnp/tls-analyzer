package scanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// TestHybridGroupCodePoints pins the locally declared IANA code points against
// the standard library. These are declared locally so the module can keep a Go
// 1.25 floor, since crypto/tls only exports SecP256r1MLKEM768 and
// SecP384r1MLKEM1024 from Go 1.26. If the standard library ever disagrees with
// the registry values used here, this fails rather than silently misreporting
// a group.
func TestHybridGroupCodePoints(t *testing.T) {
	if groupX25519MLKEM768 != tls.X25519MLKEM768 {
		t.Errorf("X25519MLKEM768 code point drift: local %d, stdlib %d",
			groupX25519MLKEM768, tls.X25519MLKEM768)
	}
	// IANA TLS Supported Groups registry values.
	if groupSecP256r1MLKEM768 != 4587 {
		t.Errorf("SecP256r1MLKEM768 must be IANA 4587, got %d", groupSecP256r1MLKEM768)
	}
	if groupSecP384r1MLKEM1024 != 4589 {
		t.Errorf("SecP384r1MLKEM1024 must be IANA 4589, got %d", groupSecP384r1MLKEM1024)
	}
}

// TestKeyExchangeFromGroup is the direct regression guard for issue #1. The
// previous implementation hardcoded X25519/classical/quantumSafe=false for every
// TLS 1.3 connection, so a hybrid ML-KEM handshake was reported as quantum
// vulnerable and the tool could never report a quantum-safe connection at all.
func TestKeyExchangeFromGroup(t *testing.T) {
	tests := []struct {
		name            string
		id              tls.CurveID
		wantName        string
		wantType        string
		wantQuantumSafe bool
		wantPQC         string
	}{
		{"hybrid x25519 mlkem768", groupX25519MLKEM768, "X25519MLKEM768", "hybrid", true, "ML-KEM-768"},
		{"hybrid p256 mlkem768", groupSecP256r1MLKEM768, "SecP256r1MLKEM768", "hybrid", true, "ML-KEM-768"},
		{"hybrid p384 mlkem1024", groupSecP384r1MLKEM1024, "SecP384r1MLKEM1024", "hybrid", true, "ML-KEM-1024"},
		{"classical x25519", tls.X25519, "X25519", "classical", false, ""},
		{"classical p256", tls.CurveP256, "secp256r1", "classical", false, ""},
		{"classical p384", tls.CurveP384, "secp384r1", "classical", false, ""},
		{"classical p521", tls.CurveP521, "secp521r1", "classical", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ke := keyExchangeFromGroup(tt.id)
			if ke.Name != tt.wantName {
				t.Errorf("name = %q, want %q", ke.Name, tt.wantName)
			}
			if ke.Type != tt.wantType {
				t.Errorf("type = %q, want %q", ke.Type, tt.wantType)
			}
			if ke.QuantumSafe != tt.wantQuantumSafe {
				t.Errorf("quantumSafe = %v, want %v", ke.QuantumSafe, tt.wantQuantumSafe)
			}
			if ke.PQCAlgorithm != tt.wantPQC {
				t.Errorf("pqcAlgorithm = %q, want %q", ke.PQCAlgorithm, tt.wantPQC)
			}
		})
	}
}

// TestKeyExchangeUnknownGroupIsNotQuantumSafe checks the fail-safe direction:
// an unrecognized group must never be reported as quantum-safe.
func TestKeyExchangeUnknownGroupIsNotQuantumSafe(t *testing.T) {
	ke := keyExchangeFromGroup(tls.CurveID(0xFEFE))
	if ke.QuantumSafe {
		t.Error("unknown group reported as quantum-safe")
	}
	if ke.Type != "unknown" {
		t.Errorf("type = %q, want %q", ke.Type, "unknown")
	}
}

// TestParseKeyExchangeNoKeyAgreement covers a connection state with no key
// agreement, which must yield no key exchange rather than a fabricated X25519.
func TestParseKeyExchangeNoKeyAgreement(t *testing.T) {
	if ke := parseKeyExchange(tls.ConnectionState{Version: tls.VersionTLS12}); ke != nil {
		t.Errorf("expected nil for absent key agreement, got %+v", ke)
	}
}

// TestParseKeyExchangeReportsNegotiatedGroup verifies the scanner reports the
// group actually recorded in the connection state.
func TestParseKeyExchangeReportsNegotiatedGroup(t *testing.T) {
	state := tls.ConnectionState{Version: tls.VersionTLS13, CurveID: groupX25519MLKEM768}
	ke := parseKeyExchange(state)
	if ke == nil {
		t.Fatal("expected a key exchange for a TLS 1.3 state with a negotiated group")
	}
	if ke.Name != "X25519MLKEM768" || !ke.QuantumSafe {
		t.Errorf("got %s quantumSafe=%v, want X25519MLKEM768 quantumSafe=true",
			ke.Name, ke.QuantumSafe)
	}
}

// TestCipherSuiteBits guards the substring bug that reported
// TLS_AES_128_GCM_SHA256 as a 256-bit cipher, because Contains(name, "256")
// matched the SHA256 suffix before the AES key size was considered.
func TestCipherSuiteBits(t *testing.T) {
	tests := []struct {
		name       string
		id         uint16
		wantBits   int
		wantQSafe  bool
		wantCipher string
	}{
		{"TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256, 128, false, "AES-GCM"},
		{"TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384, 256, true, "AES-GCM"},
		{"TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256, 256, true, "ChaCha20-Poly1305"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := parseCipherSuite(tt.id, tls.VersionTLS13)
			if cs.Bits != tt.wantBits {
				t.Errorf("bits = %d, want %d", cs.Bits, tt.wantBits)
			}
			if cs.Encryption != tt.wantCipher {
				t.Errorf("encryption = %q, want %q", cs.Encryption, tt.wantCipher)
			}
			if cs.QuantumSafe != tt.wantQSafe {
				t.Errorf("quantumSafe = %v, want %v", cs.QuantumSafe, tt.wantQSafe)
			}
		})
	}
}

// TestTLS12CipherSuiteNeverQuantumSafe checks that a strong bulk cipher does not
// mark a pre-1.3 suite quantum-safe, since those suites carry a classical key
// exchange that Shor's algorithm breaks.
func TestTLS12CipherSuiteNeverQuantumSafe(t *testing.T) {
	cs := parseCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS12)
	if cs.QuantumSafe {
		t.Error("TLS 1.2 suite with a classical key exchange reported quantum-safe")
	}
	if cs.Bits != 256 {
		t.Errorf("bits = %d, want 256", cs.Bits)
	}
}

// TestMergeKeyExchangesOrderingIsDeterministic guards against the probe-timing
// dependence that made scan output vary between identical runs.
func TestMergeKeyExchangesOrderingIsDeterministic(t *testing.T) {
	negotiated := []types.KeyExchange{
		{Name: "X25519", Type: "classical", Bits: 256},
	}
	offered := []types.KeyExchange{
		{Name: "secp256r1", Type: "classical", Bits: 256},
		{Name: "X25519MLKEM768", Type: "hybrid", Bits: 256, QuantumSafe: true},
		{Name: "secp384r1", Type: "classical", Bits: 384},
		{Name: "X25519", Type: "classical", Bits: 256},
	}

	first := mergeKeyExchanges(negotiated, offered)
	for i := 0; i < 20; i++ {
		got := mergeKeyExchanges(negotiated, offered)
		if len(got) != len(first) {
			t.Fatalf("length varies between runs: %d vs %d", len(got), len(first))
		}
		for j := range got {
			if got[j].Name != first[j].Name {
				t.Fatalf("order varies between runs at %d: %s vs %s",
					j, got[j].Name, first[j].Name)
			}
		}
	}

	// Post-quantum groups must sort ahead of classical ones.
	if first[0].Name != "X25519MLKEM768" {
		t.Errorf("hybrid group should sort first, got %s", first[0].Name)
	}
	// The negotiated group must be deduplicated and retain its marker.
	var seen int
	for _, ke := range first {
		if ke.Name != "X25519" {
			continue
		}
		seen++
		if !ke.Negotiated {
			t.Error("negotiated marker lost during merge")
		}
	}
	if seen != 1 {
		t.Errorf("X25519 appears %d times, want 1", seen)
	}
}

// TestPublicKeyBits guards the type switch that returned 0 for every elliptic
// curve and Ed25519 certificate, because those key types do not implement the
// Size() method the previous implementation matched on.
func TestPublicKeyBits(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa p384 keygen: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}

	tests := []struct {
		name string
		key  any
		want int
	}{
		{"rsa 2048", &rsaKey.PublicKey, 2048},
		{"ecdsa p256", &ecKey.PublicKey, 256},
		{"ecdsa p384", &ecKey384.PublicKey, 384},
		{"ed25519", edPub, 256},
		{"unrecognized", struct{}{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publicKeyBits(tt.key); got != tt.want {
				t.Errorf("publicKeyBits = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestFingerprintsAreRealHashes guards the most serious integrity defect found:
// the previous implementation returned hex.EncodeToString(der[:20])+"..." for
// SHA-256 and hex.EncodeToString(der[:10])+"..." for SHA-1. Those are prefixes
// of the certificate itself, not digests, so both "fingerprints" began with the
// same DER header bytes and matched no real certificate fingerprint anywhere.
func TestFingerprintsAreRealHashes(t *testing.T) {
	der := buildTestCertificateDER(t)

	got := sha256Fingerprint(der)
	want := sha256.Sum256(der)
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("sha256Fingerprint = %q, want %q", got, hex.EncodeToString(want[:]))
	}
	if len(got) != 64 {
		t.Errorf("sha256 fingerprint length = %d, want 64 hex chars", len(got))
	}
	if len(sha1Fingerprint(der)) != 40 {
		t.Errorf("sha1 fingerprint length = %d, want 40 hex chars", len(sha1Fingerprint(der)))
	}
	// A digest must not be a prefix of its input, which is what the previous
	// implementation returned.
	if len(der) >= 20 && got == hex.EncodeToString(der[:20])+"..." {
		t.Error("sha256Fingerprint returned a certificate prefix instead of a digest")
	}
	if sha256Fingerprint(der) == sha1Fingerprint(der) {
		t.Error("sha256 and sha1 fingerprints are identical")
	}
}

// TestCertificateQuantumSafetyIsNeverAssumed checks that no certificate Go can
// parse is reported quantum-safe, and that an unrecognized algorithm defaults to
// unsafe rather than safe.
func TestCertificateQuantumSafetyIsNeverAssumed(t *testing.T) {
	for _, algo := range []x509.PublicKeyAlgorithm{
		x509.RSA, x509.ECDSA, x509.Ed25519, x509.DSA, x509.UnknownPublicKeyAlgorithm,
	} {
		cert := &x509.Certificate{PublicKeyAlgorithm: algo}
		if isQuantumSafeCertificate(cert) {
			t.Errorf("%v certificate reported quantum-safe", algo)
		}
	}
}

// buildTestCertificateDER produces a throwaway self-signed certificate so
// fingerprint tests run against real DER without reaching the network.
func buildTestCertificateDER(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}
