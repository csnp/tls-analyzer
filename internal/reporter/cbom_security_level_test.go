package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// algorithmPropertiesByName renders result as a CBOM and returns each
// component's algorithmProperties, keyed by component name, decoded generically
// so a field that is left out can be told apart from one that is present.
func algorithmPropertiesByName(t *testing.T, result *types.ScanResult) map[string]map[string]any {
	t.Helper()

	var buf bytes.Buffer
	if err := (&CBOMReporter{}).Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}

	var doc struct {
		Components []struct {
			Name             string `json:"name"`
			CryptoProperties struct {
				AlgorithmProperties map[string]any `json:"algorithmProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the CBOM is not valid JSON: %v", err)
	}

	props := make(map[string]map[string]any, len(doc.Components))
	for _, c := range doc.Components {
		props[c.Name] = c.CryptoProperties.AlgorithmProperties
	}
	return props
}

// assertLevel checks that field holds want, or is left out when want is 0.
func assertLevel(t *testing.T, props map[string]any, field string, want int) {
	t.Helper()

	got, present := props[field]
	if want == 0 {
		if present {
			t.Errorf("%s is %v, want it left out", field, got)
		}
		return
	}
	if !present {
		t.Errorf("%s is left out, want %d", field, want)
		return
	}
	if n, ok := got.(float64); !ok || int(n) != want {
		t.Errorf("%s is %v, want %d", field, got, want)
	}
}

// TestCBOMCertificateClassicalSecurityLevelIsSecurityStrength pins the
// certificate component's classicalSecurityLevel to the security strength of
// its key, which CycloneDX 1.6 defines it as. It held the key size before, so
// an RSA-2048 certificate claimed 2048 bits of security instead of 112.
func TestCBOMCertificateClassicalSecurityLevelIsSecurityStrength(t *testing.T) {
	cases := []struct {
		name      string
		algorithm string
		bits      int
		want      int // 0 means the field is left out
	}{
		{"ECDSA P-224", "ECDSA", 224, 112},
		{"ECDSA P-256", "ECDSA", 256, 128},
		{"ECDSA P-384", "ECDSA", 384, 192},
		{"ECDSA P-521", "ECDSA", 521, 256},
		{"RSA-1024", "RSA", 1024, 80},
		{"RSA-2048", "RSA", 2048, 112},
		{"RSA-3072", "RSA", 3072, 128},
		{"RSA-4096 takes the lower row", "RSA", 4096, 128},
		{"RSA-7680", "RSA", 7680, 192},
		{"RSA-15360", "RSA", 15360, 256},
		{"Ed25519", "Ed25519", 256, 128},
		// Below the lowest row of the table there is no published strength,
		// and the key size is never a substitute for one.
		{"RSA-512 is below every row", "RSA", 512, 0},
		{"an unrecognised key type", "0", 4096, 0},
		{"an ML-DSA key is not in the classical table", "ML-DSA-65", 15616, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := sampleResultForCBOM()
			result.Certificate.PublicKeyAlgorithm = tc.algorithm
			result.Certificate.PublicKeyBits = tc.bits

			props := algorithmPropertiesByName(t, result)[result.Certificate.Subject]
			if props == nil {
				t.Fatal("the certificate component has no algorithmProperties")
			}
			assertLevel(t, props, "classicalSecurityLevel", tc.want)
		})
	}
}

// TestCBOMCipherClassicalSecurityLevelIsSecurityStrength pins each cipher suite
// component's classicalSecurityLevel. 3DES carries a 168-bit key and 112 bits
// of strength; RC4 has no published strength, so the field is left out rather
// than filled with its key size.
func TestCBOMCipherClassicalSecurityLevelIsSecurityStrength(t *testing.T) {
	cases := []struct {
		suite types.CipherSuite
		want  int // 0 means the field is left out
	}{
		{types.CipherSuite{ID: 0x000A, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Encryption: "3DES", Bits: 168, MAC: "SHA1"}, 112},
		{types.CipherSuite{ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", Encryption: "RC4", Bits: 128, MAC: "SHA1"}, 0},
		{types.CipherSuite{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Encryption: "AES-GCM", Bits: 128}, 128},
		{types.CipherSuite{ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", Encryption: "AES-GCM", Bits: 256}, 256},
		{types.CipherSuite{ID: 0xC013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Encryption: "AES", Bits: 128, MAC: "SHA1"}, 128},
		{types.CipherSuite{ID: 0xC028, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", Encryption: "AES", Bits: 256, MAC: "SHA384"}, 256},
		{types.CipherSuite{ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", Encryption: "ChaCha20-Poly1305", Bits: 256}, 256},
		{types.CipherSuite{ID: 0xFFFF, Name: "TLS_SOMETHING_UNRECOGNISED", Encryption: "Camellia", Bits: 128, MAC: "SHA256"}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.suite.Name, func(t *testing.T) {
			result := sampleResultForCBOM()
			result.CipherSuites = []types.CipherSuite{tc.suite}

			props := algorithmPropertiesByName(t, result)[tc.suite.Name]
			if props == nil {
				t.Fatal("the cipher suite component has no algorithmProperties")
			}
			assertLevel(t, props, "classicalSecurityLevel", tc.want)
		})
	}
}

// TestCBOMKeyExchangeQuantumLevelComesFromTheParameterSet pins
// nistQuantumSecurityLevel to the ML-KEM parameter set. It was 3 for every
// post-quantum or hybrid group, so SecP384r1MLKEM1024, whose ML-KEM part is in
// category 5, was reported as category 3.
func TestCBOMKeyExchangeQuantumLevelComesFromTheParameterSet(t *testing.T) {
	cases := []struct {
		ke   types.KeyExchange
		want int // 0 means the field is left out
	}{
		{types.KeyExchange{Name: "X25519MLKEM768", Type: "hybrid", Curve: "X25519", Bits: 256,
			QuantumSafe: true, PQCAlgorithm: "ML-KEM-768", HybridClassical: "X25519"}, 3},
		{types.KeyExchange{Name: "SecP256r1MLKEM768", Type: "hybrid", Curve: "P-256", Bits: 256,
			QuantumSafe: true, PQCAlgorithm: "ML-KEM-768", HybridClassical: "P-256"}, 3},
		{types.KeyExchange{Name: "SecP384r1MLKEM1024", Type: "hybrid", Curve: "P-384", Bits: 384,
			QuantumSafe: true, PQCAlgorithm: "ML-KEM-1024", HybridClassical: "P-384"}, 5},
		{types.KeyExchange{Name: "MLKEM512", Type: "pqc", QuantumSafe: true, PQCAlgorithm: "ML-KEM-512"}, 1},
		{types.KeyExchange{Name: "MLKEM1024", Type: "pqc", QuantumSafe: true, PQCAlgorithm: "ML-KEM-1024"}, 5},
		// A post-quantum group whose parameter set is not known gets no level,
		// rather than an assumed one.
		{types.KeyExchange{Name: "a hybrid group with no parameter set", Type: "hybrid", QuantumSafe: true}, 0},
		{types.KeyExchange{Name: "a hybrid group with an unknown parameter set", Type: "hybrid",
			QuantumSafe: true, PQCAlgorithm: "Kyber-Unknown"}, 0},
		{types.KeyExchange{Name: "secp256r1", Type: "classical", Curve: "P-256", Bits: 256}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.ke.Name, func(t *testing.T) {
			result := sampleResultForCBOM()
			result.KeyExchanges = []types.KeyExchange{tc.ke}

			props := algorithmPropertiesByName(t, result)[tc.ke.Name]
			if props == nil {
				t.Fatal("the key exchange component has no algorithmProperties")
			}
			assertLevel(t, props, "nistQuantumSecurityLevel", tc.want)
		})
	}
}

// TestCBOMCertificateQuantumLevelComesFromTheParameterSet pins the certificate
// component's nistQuantumSecurityLevel to the ML-DSA parameter set of its key.
// It was 2 for every quantum-safe certificate, under a comment assuming
// ML-DSA-65, which is in category 3.
func TestCBOMCertificateQuantumLevelComesFromTheParameterSet(t *testing.T) {
	cases := []struct {
		name        string
		algorithm   string
		quantumSafe bool
		want        int // 0 means the field is left out
	}{
		{"ML-DSA-44", "ML-DSA-44", true, 2},
		{"ML-DSA-65", "ML-DSA-65", true, 3},
		{"ML-DSA-87", "ML-DSA-87", true, 5},
		// A certificate judged quantum-safe whose parameter set is not known
		// gets no level, rather than an assumed one.
		{"an unknown parameter set", "0", true, 0},
		{"a classical key", "ECDSA", false, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := sampleResultForCBOM()
			result.Certificate.PublicKeyAlgorithm = tc.algorithm
			result.Certificate.SignatureAlgorithm = tc.algorithm
			result.Certificate.QuantumSafe = tc.quantumSafe

			props := algorithmPropertiesByName(t, result)[result.Certificate.Subject]
			if props == nil {
				t.Fatal("the certificate component has no algorithmProperties")
			}
			assertLevel(t, props, "nistQuantumSecurityLevel", tc.want)
		})
	}
}
