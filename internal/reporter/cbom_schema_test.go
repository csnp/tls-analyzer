package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// closedEnums holds the CycloneDX 1.6 enums this reporter can emit a non-member
// value into, read from a copy of the published schema in testdata rather than
// retyped here.
//
// The previous version of this file hand-wrote the same lists. That is a test
// asserting the author's belief about the spec instead of the spec, and it is
// half of why an invalid document shipped: the lists happened to be right, but
// nothing tied them to the schema, so a wrong entry would have been invisible.
// The other half was the input space, covered by
// TestCBOMPrimitivesAreInEnumForEveryCipherSuiteShape below.
type closedEnums struct {
	Primitive                 []string `json:"primitive"`
	Mode                      []string `json:"mode"`
	AssetType                 []string `json:"assetType"`
	RelatedCryptoMaterialType []string `json:"relatedCryptoMaterialType"`
}

func loadClosedEnums(t *testing.T) closedEnums {
	t.Helper()

	body, err := os.ReadFile(filepath.Join("testdata", "cyclonedx", "closed-enums.json"))
	if err != nil {
		t.Fatalf("reading the vendored CycloneDX enums failed: %v", err)
	}

	var enums closedEnums
	if err := json.Unmarshal(body, &enums); err != nil {
		t.Fatalf("parsing the vendored CycloneDX enums failed: %v", err)
	}

	// A mis-extracted or truncated file would silently accept everything, which
	// is the failure mode a hand-written list has.
	if len(enums.Primitive) == 0 || len(enums.Mode) == 0 || len(enums.AssetType) == 0 {
		t.Fatal("the vendored CycloneDX enums are empty, so membership checks would pass vacuously")
	}
	for _, member := range []string{"block-cipher", "stream-cipher", "ae"} {
		if !slices.Contains(enums.Primitive, member) {
			t.Fatalf("the vendored primitive enum is missing %q, so it is not the published enum", member)
		}
	}
	if slices.Contains(enums.Primitive, "cipher") {
		t.Fatal(`the vendored primitive enum contains "cipher", which the published schema does not`)
	}

	return enums
}

func memberSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

var serialNumberPattern = regexp.MustCompile(
	`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestCBOMConformsToCycloneDX checks the CBOM output against the parts of the
// CycloneDX 1.6 schema this reporter can violate. It is deliberately offline so
// CI does not depend on fetching the schema, and it covers the exact defects
// found in 0.3.0: a primitive outside the enum, empty bom-ref strings, and a
// serial number that is not a UUID.
func TestCBOMConformsToCycloneDX(t *testing.T) {
	enums := loadClosedEnums(t)
	cycloneDXPrimitives := memberSet(enums.Primitive)
	cycloneDXAssetTypes := memberSet(enums.AssetType)

	result := sampleResultForCBOM()

	var buf bytes.Buffer
	if err := (&CBOMReporter{}).Report(&buf, result); err != nil {
		t.Fatalf("report: %v", err)
	}

	var doc struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Components   []struct {
			Name             string `json:"name"`
			BOMRef           string `json:"bom-ref"`
			CryptoProperties struct {
				AssetType           string `json:"assetType"`
				AlgorithmProperties *struct {
					Primitive string `json:"primitive"`
				} `json:"algorithmProperties"`
				CertificateProperties *struct {
					SignatureAlgorithmRef string `json:"signatureAlgorithmRef"`
					SubjectPublicKeyRef   string `json:"subjectPublicKeyRef"`
				} `json:"certificateProperties"`
				RelatedCryptoMaterialProperties *struct {
					Type string `json:"type"`
				} `json:"relatedCryptoMaterialProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if !serialNumberPattern.MatchString(doc.SerialNumber) {
		t.Errorf("serialNumber %q does not match the CycloneDX urn:uuid pattern",
			doc.SerialNumber)
	}
	if len(doc.Components) == 0 {
		t.Fatal("CBOM contains no components")
	}

	for _, c := range doc.Components {
		cp := c.CryptoProperties
		if !cycloneDXAssetTypes[cp.AssetType] {
			t.Errorf("component %q: assetType %q is not a CycloneDX asset type",
				c.Name, cp.AssetType)
		}
		if cp.AlgorithmProperties != nil && !cycloneDXPrimitives[cp.AlgorithmProperties.Primitive] {
			t.Errorf("component %q: primitive %q is not in the CycloneDX enum",
				c.Name, cp.AlgorithmProperties.Primitive)
		}
		// bom-ref values must be non-empty when present, so an absent reference
		// has to be omitted rather than serialized as "".
		if cert := cp.CertificateProperties; cert != nil {
			if cert.SignatureAlgorithmRef == "" && bytes.Contains(buf.Bytes(), []byte(`"signatureAlgorithmRef":""`)) {
				t.Errorf("component %q: empty signatureAlgorithmRef was emitted", c.Name)
			}
			if cert.SubjectPublicKeyRef == "" && bytes.Contains(buf.Bytes(), []byte(`"subjectPublicKeyRef":""`)) {
				t.Errorf("component %q: empty subjectPublicKeyRef was emitted", c.Name)
			}
		}
		if rcm := cp.RelatedCryptoMaterialProperties; rcm != nil && rcm.Type == "" {
			t.Errorf("component %q: related crypto material has no type", c.Name)
		}
	}
}

// TestCBOMCertificateReferencesRealKeyMaterial checks that the certificate's
// subjectPublicKeyRef resolves to a component that actually exists, rather than
// pointing at nothing.
func TestCBOMCertificateReferencesRealKeyMaterial(t *testing.T) {
	var buf bytes.Buffer
	if err := (&CBOMReporter{}).Report(&buf, sampleResultForCBOM()); err != nil {
		t.Fatalf("report: %v", err)
	}

	var doc struct {
		Components []struct {
			BOMRef           string `json:"bom-ref"`
			CryptoProperties struct {
				AssetType             string `json:"assetType"`
				CertificateProperties *struct {
					SubjectPublicKeyRef string `json:"subjectPublicKeyRef"`
				} `json:"certificateProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	refs := make(map[string]bool)
	for _, c := range doc.Components {
		refs[c.BOMRef] = true
	}

	var checked bool
	for _, c := range doc.Components {
		cert := c.CryptoProperties.CertificateProperties
		if cert == nil || cert.SubjectPublicKeyRef == "" {
			continue
		}
		checked = true
		if !refs[cert.SubjectPublicKeyRef] {
			t.Errorf("subjectPublicKeyRef %q does not resolve to any component",
				cert.SubjectPublicKeyRef)
		}
	}
	if !checked {
		t.Error("no certificate component carried a subjectPublicKeyRef")
	}
}

func sampleResultForCBOM() *types.ScanResult {
	return &types.ScanResult{
		Target:         "example.com",
		Host:           "example.com",
		Port:           443,
		Timestamp:      time.Now(),
		ScannerVersion: "0.3.0",
		Protocols:      []types.Protocol{{Version: "TLS 1.3", Supported: true, Preferred: true}},
		CipherSuites: []types.CipherSuite{{
			ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Protocol: "TLS 1.3",
			Encryption: "AES-GCM", Bits: 128, ForwardSecrecy: true,
		}},
		KeyExchanges: []types.KeyExchange{
			{
				Name: "X25519MLKEM768", Type: "hybrid", Curve: "X25519", Bits: 256,
				QuantumSafe: true, PQCAlgorithm: "ML-KEM-768", HybridClassical: "X25519",
				Negotiated: true,
			},
			{Name: "X25519", Type: "classical", Curve: "X25519", Bits: 256},
		},
		Certificate: &types.Certificate{
			Subject:            "CN=example.com",
			Issuer:             "CN=Test CA",
			SignatureAlgorithm: "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
			PublicKeyBits:      256,
			NotBefore:          time.Now().Add(-24 * time.Hour),
			NotAfter:           time.Now().Add(24 * time.Hour),
		},
	}
}

// TestCBOMPrimitivesAreInEnumForEveryCipherSuiteShape is the test that would
// have caught the invalid document.
//
// TestCBOMConformsToCycloneDX already checked enum membership, and passed, because
// its fixture holds one AEAD suite (`TLS_AES_128_GCM_SHA256`, no separate MAC) and
// that is the one shape whose primitive was legal. A real scan of example.com
// produced 17 components with `primitive: "cipher"` and 2 with `mode: "stream"`,
// neither a member of its enum, so the whole document failed validation.
//
// This drives every encryption value the scanner can assign, crossed with a MAC
// present and absent, and asserts nothing outside the published enums is emitted.
// Checking the enum is not enough on its own: the inputs have to reach it.
func TestCBOMPrimitivesAreInEnumForEveryCipherSuiteShape(t *testing.T) {
	enums := loadClosedEnums(t)
	primitives := memberSet(enums.Primitive)
	modes := memberSet(enums.Mode)

	// Every value internal/scanner assigns to CipherSuite.Encryption, with a
	// representative real suite name for each.
	suites := []types.CipherSuite{
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", Encryption: "AES-GCM", Bits: 128},
		{ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", Encryption: "ChaCha20-Poly1305", Bits: 256},
		{ID: 0xC02F, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Encryption: "AES-GCM", Bits: 128, MAC: "SHA256"},
		{ID: 0xC013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Encryption: "AES", Bits: 128, MAC: "SHA1"},
		{ID: 0xC028, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", Encryption: "AES", Bits: 256, MAC: "SHA384"},
		{ID: 0xCCA8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Encryption: "ChaCha20-Poly1305", Bits: 256, MAC: "SHA256"},
		{ID: 0x000A, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Encryption: "3DES", Bits: 168, MAC: "SHA1"},
		{ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", Encryption: "RC4", Bits: 128, MAC: "SHA1"},
		// An encryption value the scanner does not currently produce must still
		// fall back to a legal value rather than pass itself through.
		{ID: 0xFFFF, Name: "TLS_SOMETHING_UNRECOGNISED", Encryption: "Camellia", Bits: 128, MAC: "SHA256"},
	}

	for _, cs := range suites {
		t.Run(cs.Name, func(t *testing.T) {
			result := sampleResultForCBOM()
			result.CipherSuites = []types.CipherSuite{cs}

			var buf bytes.Buffer
			if err := (&CBOMReporter{}).Report(&buf, result); err != nil {
				t.Fatalf("report: %v", err)
			}

			var doc struct {
				Components []struct {
					Name             string `json:"name"`
					CryptoProperties struct {
						AlgorithmProperties *struct {
							Primitive string `json:"primitive"`
							Mode      string `json:"mode"`
						} `json:"algorithmProperties"`
					} `json:"cryptoProperties"`
				} `json:"components"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("CBOM is not valid JSON: %v", err)
			}

			var checked bool
			for _, c := range doc.Components {
				if c.Name != cs.Name {
					continue
				}
				checked = true
				props := c.CryptoProperties.AlgorithmProperties
				if props == nil {
					t.Fatalf("%s emitted no algorithmProperties", cs.Name)
				}
				if !primitives[props.Primitive] {
					t.Errorf("%s (encryption %q, mac %q) emitted primitive %q, which is not in the CycloneDX enum; one non-member value invalidates the whole document",
						cs.Name, cs.Encryption, cs.MAC, props.Primitive)
				}
				// mode is omitempty, so an absent mode is legal; a present one
				// must be a member.
				if props.Mode != "" && !modes[props.Mode] {
					t.Errorf("%s emitted mode %q, which is not in the CycloneDX enum", cs.Name, props.Mode)
				}
			}
			if !checked {
				t.Fatalf("no component was emitted for %s, so nothing was asserted", cs.Name)
			}
		})
	}
}

// TestCBOMCipherClassification pins the classification itself, not just its
// legality: "other" for everything would satisfy the enum check above while
// telling a consumer nothing.
func TestCBOMCipherClassification(t *testing.T) {
	tests := []struct {
		suite         types.CipherSuite
		wantPrimitive string
		wantMode      string
	}{
		{types.CipherSuite{Name: "TLS_AES_128_GCM_SHA256", Encryption: "AES-GCM"}, "ae", "gcm"},
		{types.CipherSuite{Name: "TLS_CHACHA20_POLY1305_SHA256", Encryption: "ChaCha20-Poly1305"}, "ae", ""},
		{types.CipherSuite{Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Encryption: "AES", MAC: "SHA1"}, "block-cipher", "cbc"},
		{types.CipherSuite{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Encryption: "3DES", MAC: "SHA1"}, "block-cipher", "cbc"},
		{types.CipherSuite{Name: "TLS_RSA_WITH_RC4_128_SHA", Encryption: "RC4", MAC: "SHA1"}, "stream-cipher", ""},
		{types.CipherSuite{Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Encryption: "ChaCha20-Poly1305", MAC: "SHA256"}, "stream-cipher", ""},
		{types.CipherSuite{Name: "TLS_SOMETHING_UNRECOGNISED", Encryption: "Camellia", MAC: "SHA256"}, "other", ""},
	}

	for _, tt := range tests {
		t.Run(tt.suite.Name+"/"+tt.suite.Encryption, func(t *testing.T) {
			if got := cipherPrimitive(tt.suite); got != tt.wantPrimitive {
				t.Errorf("cipherPrimitive = %q, want %q", got, tt.wantPrimitive)
			}
			if got := cipherMode(tt.suite); got != tt.wantMode {
				t.Errorf("cipherMode = %q, want %q", got, tt.wantMode)
			}
		})
	}
}
