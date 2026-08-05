package types

import "time"

// CryptoBOM represents a Cryptographic Bill of Materials in CycloneDX format.
// Based on CycloneDX 1.6 CBOM specification.
type CryptoBOM struct {
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber"`
	Version      int               `json:"version"`
	Metadata     CBOMMetadata      `json:"metadata"`
	Components   []CryptoComponent `json:"components"`
	Services     []CryptoService   `json:"services,omitempty"`
	Dependencies []CBOMDependency  `json:"dependencies,omitempty"`
}

// CBOMMetadata contains metadata about the CBOM.
type CBOMMetadata struct {
	Timestamp   time.Time      `json:"timestamp"`
	Tools       []CBOMTool     `json:"tools"`
	Component   *CBOMComponent `json:"component,omitempty"`
	Manufacture *CBOMOrg       `json:"manufacture,omitempty"`
	Supplier    *CBOMOrg       `json:"supplier,omitempty"`
	Properties  []CBOMProperty `json:"properties,omitempty"`
}

// CBOMProperty is a CycloneDX name/value pair.
//
// It carries the facts CycloneDX has no dedicated field for. The one this was
// added for is whether the target was reached at all: an empty component list is
// otherwise indistinguishable from a host that uses no cryptography, and a CBOM
// is read as an inventory rather than as a scan report.
type CBOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CBOMTool represents the tool that generated the CBOM.
type CBOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CBOMComponent represents a component in metadata.
type CBOMComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// CBOMOrg represents an organization.
type CBOMOrg struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CryptoComponent represents a cryptographic component (algorithm, protocol, etc.).
type CryptoComponent struct {
	Type             string           `json:"type"` // cryptographic-asset
	BOMRef           string           `json:"bom-ref"`
	Name             string           `json:"name"`
	Version          string           `json:"version,omitempty"`
	Description      string           `json:"description,omitempty"`
	CryptoProperties CryptoProperties `json:"cryptoProperties"`
	Evidence         *CryptoEvidence  `json:"evidence,omitempty"`
}

// CryptoProperties contains cryptographic-specific properties.
type CryptoProperties struct {
	AssetType                       string                      `json:"assetType"` // algorithm, protocol, certificate, related-crypto-material
	AlgorithmProperties             *AlgorithmProps             `json:"algorithmProperties,omitempty"`
	ProtocolProperties              *ProtocolProps              `json:"protocolProperties,omitempty"`
	CertificateProperties           *CertificateProps           `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedCryptoMaterialProps `json:"relatedCryptoMaterialProperties,omitempty"`
	OID                             string                      `json:"oid,omitempty"`
}

// RelatedCryptoMaterialProps describes key material rather than an algorithm.
// CycloneDX 1.6 models keys, certificates signing requests, secrets and tokens
// this way; representing them as algorithm assets loses the material's type and
// size.
type RelatedCryptoMaterialProps struct {
	// Type is a CycloneDX relatedCryptoMaterialType, for example private-key,
	// public-key, secret-key, key, ciphertext, signature, or password.
	Type string `json:"type"`
	// Size is the key size in bits, omitted when not known.
	Size int `json:"size,omitempty"`
	// State is the key lifecycle state, for example active or deactivated.
	State string `json:"state,omitempty"`
}

// AlgorithmProps describes a cryptographic algorithm.
type AlgorithmProps struct {
	Primitive              string   `json:"primitive"` // ae, mac, signature, hash, kdf, kex, kem, pke, etc.
	ParameterSetID         string   `json:"parameterSetIdentifier,omitempty"`
	Mode                   string   `json:"mode,omitempty"` // gcm, ccm, cbc, etc.
	Padding                string   `json:"padding,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"` // generate, keygen, encrypt, decrypt, sign, verify
	ClassicalSecurityLevel int      `json:"classicalSecurityLevel,omitempty"`
	QuantumSecurityLevel   int      `json:"nistQuantumSecurityLevel,omitempty"` // 1-5
}

// ProtocolProps describes a cryptographic protocol.
type ProtocolProps struct {
	Type         string           `json:"type"` // tls, ssh, ipsec, etc.
	Version      string           `json:"version"`
	CipherSuites []CipherSuiteRef `json:"cipherSuites,omitempty"`
}

// CipherSuiteRef references a cipher suite.
type CipherSuiteRef struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms"`            // bom-refs to algorithm components
	Identifiers []string `json:"identifiers,omitempty"` // IANA identifiers
}

// CertificateProps describes a certificate.
type CertificateProps struct {
	SubjectName    string    `json:"subjectName"`
	IssuerName     string    `json:"issuerName"`
	NotValidBefore time.Time `json:"notValidBefore"`
	NotValidAfter  time.Time `json:"notValidAfter"`
	// bom-ref values. CycloneDX 1.6 requires a non-empty string when present,
	// so these are omitted rather than emitted empty.
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat"`              // X.509
	CertificateExtension  string `json:"certificateExtension,omitempty"` // pem, der
}

// CryptoEvidence provides evidence of where crypto was found.
type CryptoEvidence struct {
	Occurrences []CryptoOccurrence `json:"occurrences,omitempty"`
}

// CryptoOccurrence shows where crypto was detected.
type CryptoOccurrence struct {
	Location          string `json:"location"` // e.g., "TLS handshake", "certificate"
	Line              int    `json:"line,omitempty"`
	Offset            int    `json:"offset,omitempty"`
	Symbol            string `json:"symbol,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// CryptoService represents a service using cryptography.
type CryptoService struct {
	BOMRef      string   `json:"bom-ref"`
	Name        string   `json:"name"`
	Endpoints   []string `json:"endpoints,omitempty"`
	Description string   `json:"description,omitempty"`
}

// CBOMDependency represents dependencies between components.
type CBOMDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// QuantumSafetyLevel indicates quantum resistance.
type QuantumSafetyLevel string

const (
	QuantumSafe       QuantumSafetyLevel = "quantum-safe"
	QuantumResistant  QuantumSafetyLevel = "quantum-resistant"
	QuantumVulnerable QuantumSafetyLevel = "quantum-vulnerable"
	QuantumUnknown    QuantumSafetyLevel = "unknown"
)
