package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
	"github.com/google/uuid"
)

// CBOMReporter outputs results in CycloneDX CBOM format.
type CBOMReporter struct{}

// Report writes the scan result as a CycloneDX CBOM.
func (r *CBOMReporter) Report(w io.Writer, result *types.ScanResult) error {
	cbom := r.generateCBOM(result)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cbom)
}

// Format returns the format name.
func (r *CBOMReporter) Format() string {
	return "cbom"
}

func (r *CBOMReporter) generateCBOM(result *types.ScanResult) types.CryptoBOM {
	cbom := types.CryptoBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: types.CBOMMetadata{
			Timestamp: time.Now(),
			Tools: []types.CBOMTool{
				{
					Vendor:  "CSNP",
					Name:    "qramm-tls-analyzer",
					Version: result.ScannerVersion,
				},
			},
			Component: &types.CBOMComponent{
				Type:    "application",
				Name:    result.Target,
				Version: result.Timestamp.Format(time.RFC3339),
			},
		},
		Components:   make([]types.CryptoComponent, 0),
		Dependencies: make([]types.CBOMDependency, 0),
	}

	// Add service
	cbom.Services = []types.CryptoService{
		{
			BOMRef:      "service-" + result.Target,
			Name:        result.Target,
			Endpoints:   []string{fmt.Sprintf("https://%s:%d", result.Host, result.Port)},
			Description: "TLS-enabled service",
		},
	}

	// Add protocols
	for _, p := range result.Protocols {
		if p.Supported {
			cbom.Components = append(cbom.Components, r.protocolComponent(p, result.Target))
		}
	}

	// Add cipher suites
	for _, cs := range result.CipherSuites {
		cbom.Components = append(cbom.Components, r.cipherComponent(cs, result.Target))
	}

	// Add key exchanges
	for _, ke := range result.KeyExchanges {
		cbom.Components = append(cbom.Components, r.keyExchangeComponent(ke, result.Target))
	}

	// Add certificate
	if result.Certificate != nil {
		cbom.Components = append(cbom.Components,
			r.certificateComponent(result.Certificate, result.Target),
			r.publicKeyComponent(result.Certificate, result.Target))
	}

	return cbom
}

func (r *CBOMReporter) protocolComponent(p types.Protocol, target string) types.CryptoComponent {
	ref := fmt.Sprintf("protocol-%s-%s", target, p.Version)

	return types.CryptoComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        p.Version,
		Description: fmt.Sprintf("TLS protocol version %s", p.Version),
		CryptoProperties: types.CryptoProperties{
			AssetType: "protocol",
			ProtocolProperties: &types.ProtocolProps{
				Type:    "tls",
				Version: p.Version,
			},
		},
		Evidence: &types.CryptoEvidence{
			Occurrences: []types.CryptoOccurrence{
				{
					Location:          "TLS handshake",
					AdditionalContext: fmt.Sprintf("Protocol %s supported on %s", p.Version, target),
				},
			},
		},
	}
}

func (r *CBOMReporter) cipherComponent(cs types.CipherSuite, target string) types.CryptoComponent {
	ref := fmt.Sprintf("cipher-%s-%s", target, cs.Name)

	quantumLevel := 0
	if cs.QuantumSafe {
		quantumLevel = 1 // NIST Level 1 minimum for PQC
	}

	return types.CryptoComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        cs.Name,
		Description: fmt.Sprintf("TLS cipher suite with %d-bit encryption", cs.Bits),
		CryptoProperties: types.CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &types.AlgorithmProps{
				Primitive:              cipherPrimitive(cs),
				Mode:                   cipherMode(cs),
				ClassicalSecurityLevel: cs.Bits,
				QuantumSecurityLevel:   quantumLevel,
				CryptoFunctions:        []string{"encrypt", "decrypt"},
			},
		},
		Evidence: &types.CryptoEvidence{
			Occurrences: []types.CryptoOccurrence{
				{
					Location:          "TLS cipher negotiation",
					AdditionalContext: fmt.Sprintf("Cipher ID: 0x%04X", cs.ID),
				},
			},
		},
	}
}

func (r *CBOMReporter) keyExchangeComponent(ke types.KeyExchange, target string) types.CryptoComponent {
	ref := fmt.Sprintf("kex-%s-%s", target, ke.Name)

	// CycloneDX 1.6 constrains primitive to a fixed enum. "kex" is not a member
	// of it, so emitting that value made the whole document fail schema
	// validation. A classical Diffie-Hellman style exchange is "key-agree";
	// ML-KEM is a key encapsulation mechanism, and a hybrid group is a
	// "combiner" of the two.
	primitive := "key-agree"
	switch ke.Type {
	case "pqc":
		primitive = "kem"
	case "hybrid":
		primitive = "combiner"
	}

	quantumLevel := 0
	if ke.QuantumSafe || ke.Type == "pqc" {
		quantumLevel = 3 // ML-KEM-768 is Level 3
	} else if ke.Type == "hybrid" {
		quantumLevel = 3 // Hybrid provides PQC protection
	}

	comp := types.CryptoComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        ke.Name,
		Description: r.keyExchangeDescription(ke),
		CryptoProperties: types.CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &types.AlgorithmProps{
				Primitive:            primitive,
				QuantumSecurityLevel: quantumLevel,
				CryptoFunctions:      []string{"keygen", "encapsulate", "decapsulate"},
			},
		},
		Evidence: &types.CryptoEvidence{
			Occurrences: []types.CryptoOccurrence{
				{
					Location:          "TLS key exchange",
					AdditionalContext: fmt.Sprintf("Key exchange type: %s", ke.Type),
				},
			},
		},
	}

	if ke.PQCAlgorithm != "" {
		comp.CryptoProperties.AlgorithmProperties.ParameterSetID = ke.PQCAlgorithm
	}

	return comp
}

// publicKeyComponent emits the certificate's public key as its own
// related-crypto-material asset, so the certificate component can reference
// real key material instead of carrying a dangling reference.
func (r *CBOMReporter) publicKeyComponent(cert *types.Certificate, target string) types.CryptoComponent {
	return types.CryptoComponent{
		Type:        "cryptographic-asset",
		BOMRef:      publicKeyRef(target),
		Name:        fmt.Sprintf("%s public key", cert.PublicKeyAlgorithm),
		Description: fmt.Sprintf("Subject public key of the certificate presented by %s", target),
		CryptoProperties: types.CryptoProperties{
			AssetType: "related-crypto-material",
			RelatedCryptoMaterialProperties: &types.RelatedCryptoMaterialProps{
				Type: "public-key",
				Size: cert.PublicKeyBits,
			},
		},
	}
}

func publicKeyRef(target string) string { return fmt.Sprintf("cert-key-%s", target) }

func (r *CBOMReporter) certificateComponent(cert *types.Certificate, target string) types.CryptoComponent {
	ref := fmt.Sprintf("cert-%s", target)

	quantumLevel := 0
	if cert.QuantumSafe {
		quantumLevel = 2 // Assuming ML-DSA-65
	}

	return types.CryptoComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        cert.Subject,
		Description: fmt.Sprintf("X.509 certificate with %s signature", cert.SignatureAlgorithm),
		CryptoProperties: types.CryptoProperties{
			AssetType: "certificate",
			CertificateProperties: &types.CertificateProps{
				SubjectName:         cert.Subject,
				IssuerName:          cert.Issuer,
				NotValidBefore:      cert.NotBefore,
				NotValidAfter:       cert.NotAfter,
				CertificateFormat:   "X.509",
				SubjectPublicKeyRef: publicKeyRef(target),
			},
			AlgorithmProperties: &types.AlgorithmProps{
				Primitive:              "signature",
				ClassicalSecurityLevel: cert.PublicKeyBits,
				QuantumSecurityLevel:   quantumLevel,
				CryptoFunctions:        []string{"sign", "verify"},
			},
		},
		Evidence: &types.CryptoEvidence{
			Occurrences: []types.CryptoOccurrence{
				{
					Location:          "TLS certificate",
					AdditionalContext: certificateValidityContext(cert),
				},
			},
		},
	}
}

// cipherPrimitive classifies a cipher suite for CycloneDX.
//
// `primitive` is a closed enum and "cipher" is not a member of it, so every
// document containing a suite with a separate MAC failed schema validation
// outright. That is the same defect 0.3.0 fixed for key exchange, where "kex"
// was emitted, and left in place here.
//
// A suite with no separate MAC is an AEAD construction. A suite that carries one
// is a cipher composed with a MAC, and is classified by the cipher.
func cipherPrimitive(cs types.CipherSuite) string {
	if cs.MAC == "" {
		return "ae"
	}

	switch {
	case strings.Contains(cs.Encryption, "ChaCha20"), strings.Contains(cs.Encryption, "RC4"):
		return "stream-cipher"
	case strings.Contains(cs.Encryption, "AES"), strings.Contains(cs.Encryption, "DES"):
		return "block-cipher"
	default:
		// Better an honest "other" than a value outside the enum, which would
		// invalidate the entire document rather than one field.
		return "other"
	}
}

// cipherMode returns the block cipher mode of operation.
//
// `mode` is a closed enum of block modes, so the previous "stream" for
// ChaCha20-Poly1305 was not a member. A stream cipher has no block mode, and the
// field is omitempty, so it is left out rather than filled with a value outside
// the enum.
//
// The mode is taken from the suite name, which carries it, rather than from the
// Encryption summary. The summary is "AES" for every CBC suite, so reading it
// reported no mode at all for the suites that have the most interesting one.
func cipherMode(cs types.CipherSuite) string {
	name := strings.ToUpper(cs.Name)

	switch {
	case strings.Contains(name, "_GCM"):
		return "gcm"
	case strings.Contains(name, "_CCM"):
		return "ccm"
	case strings.Contains(name, "_CBC"):
		return "cbc"
	case strings.Contains(strings.ToUpper(cs.Encryption), "GCM"):
		return "gcm"
	default:
		return ""
	}
}

func (r *CBOMReporter) keyExchangeDescription(ke types.KeyExchange) string {
	switch ke.Type {
	case "hybrid":
		return fmt.Sprintf("Hybrid key exchange combining %s with %s", ke.HybridClassical, ke.PQCAlgorithm)
	case "pqc":
		return fmt.Sprintf("Post-quantum key encapsulation: %s", ke.PQCAlgorithm)
	default:
		return fmt.Sprintf("Classical key exchange: %s", ke.Name)
	}
}

// certificateValidityContext describes the certificate's validity window for a
// CBOM consumer.
//
// It said "Expires in N days" whatever the window was, so a certificate dated to
// start next year read as a healthy long-lived one: the only human-readable
// string in the component described it by a date it never reaches in a usable
// state. The structured notValidBefore is present either way, but the prose has
// to agree with it.
//
// A certificate can set both flags if its notAfter precedes its notBefore, and
// that window is never open at all, so it is named rather than described by
// whichever branch happens to be tested first. Expiry is tested before the start
// of the window, matching the text report and the grade, so one scan cannot
// describe one certificate two ways.
func certificateValidityContext(cert *types.Certificate) string {
	switch {
	case cert.Expired && cert.NotYetValid:
		return fmt.Sprintf("Never valid; the validity period ends %s, before it starts %s",
			cert.NotAfter.Format("2006-01-02"), cert.NotBefore.Format("2006-01-02"))
	case cert.Expired:
		return fmt.Sprintf("Expired on %s", cert.NotAfter.Format("2006-01-02"))
	case cert.NotYetValid:
		return fmt.Sprintf("Not yet valid; validity period starts %s",
			cert.NotBefore.Format("2006-01-02"))
	default:
		return fmt.Sprintf("Expires in %d days", cert.DaysUntilExpiry)
	}
}
