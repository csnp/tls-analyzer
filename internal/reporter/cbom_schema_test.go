package reporter

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// cycloneDXPrimitives is the closed enum CycloneDX 1.6 allows for
// cryptoProperties.algorithmProperties.primitive. Emitting anything outside it
// makes the whole document fail schema validation, which is how this tool
// shipped a CBOM containing the non-member value "kex".
var cycloneDXPrimitives = map[string]bool{
	"drbg": true, "mac": true, "block-cipher": true, "stream-cipher": true,
	"signature": true, "hash": true, "pke": true, "xof": true, "kdf": true,
	"key-agree": true, "kem": true, "ae": true, "combiner": true,
	"other": true, "unknown": true,
}

// cycloneDXAssetTypes is the closed enum for cryptoProperties.assetType.
var cycloneDXAssetTypes = map[string]bool{
	"algorithm": true, "certificate": true, "protocol": true,
	"related-crypto-material": true,
}

var serialNumberPattern = regexp.MustCompile(
	`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestCBOMConformsToCycloneDX checks the CBOM output against the parts of the
// CycloneDX 1.6 schema this reporter can violate. It is deliberately offline so
// CI does not depend on fetching the schema, and it covers the exact defects
// found in 0.3.0: a primitive outside the enum, empty bom-ref strings, and a
// serial number that is not a UUID.
func TestCBOMConformsToCycloneDX(t *testing.T) {
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
