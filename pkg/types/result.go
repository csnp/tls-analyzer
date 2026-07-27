// Package types defines the public types for the TLS analyzer.
package types

import (
	"time"
)

// ScanResult represents the complete result of a TLS scan.
type ScanResult struct {
	// Target information
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	IP        string    `json:"ip,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Duration  Duration  `json:"duration"`

	// TLS Configuration
	Protocols    []Protocol    `json:"protocols"`
	CipherSuites []CipherSuite `json:"cipherSuites"`
	KeyExchanges []KeyExchange `json:"keyExchanges"`
	Certificate  *Certificate  `json:"certificate,omitempty"`
	CertChain    []Certificate `json:"certificateChain,omitempty"`

	// Analysis
	Vulnerabilities []Vulnerability       `json:"vulnerabilities,omitempty"`
	QuantumRisk     QuantumRiskAssessment `json:"quantumRisk"`
	Grade           Grade                 `json:"grade"`
	Recommendations []Recommendation      `json:"recommendations,omitempty"`

	// Compliance (populated when compliance checks are enabled)
	CNSA2Timeline *CNSA2Timeline     `json:"cnsa2Timeline,omitempty"`
	Compliance    []ComplianceResult `json:"compliance,omitempty"`
	PolicyResult  *PolicyResult      `json:"policyResult,omitempty"`

	// ScanWarnings records limits on this scan's coverage, such as key exchange
	// groups the running build could not offer. Present so that an absent
	// result is never mistaken for a negative one.
	ScanWarnings []string `json:"scanWarnings,omitempty"`

	// Metadata
	ScannerVersion string `json:"scannerVersion"`
	ScanProfile    string `json:"scanProfile,omitempty"` // e.g., "default", "quantum-ready", "compliance"
	Error          string `json:"error,omitempty"`
}

// Duration wraps time.Duration for JSON marshaling.
type Duration struct {
	time.Duration
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

// Protocol represents a TLS protocol version.
type Protocol struct {
	Version   string `json:"version"` // e.g., "TLS 1.3", "TLS 1.2"
	Supported bool   `json:"supported"`
	Preferred bool   `json:"preferred,omitempty"`
}

// CipherSuite represents a TLS cipher suite.
type CipherSuite struct {
	ID               uint16 `json:"id"`
	Name             string `json:"name"`
	Protocol         string `json:"protocol"` // TLS version this was negotiated with
	KeyExchange      string `json:"keyExchange"`
	Authentication   string `json:"authentication"`
	Encryption       string `json:"encryption"`
	MAC              string `json:"mac,omitempty"`
	Bits             int    `json:"bits"`
	QuantumSafe      bool   `json:"quantumSafe"`
	ForwardSecrecy   bool   `json:"forwardSecrecy"`
	Deprecated       bool   `json:"deprecated"`
	DeprecatedReason string `json:"deprecatedReason,omitempty"`
}

// KeyExchange represents a key exchange mechanism.
type KeyExchange struct {
	Name            string `json:"name"`
	Type            string `json:"type"` // "classical", "hybrid", "pqc", "unknown"
	Curve           string `json:"curve,omitempty"`
	Bits            int    `json:"bits,omitempty"`
	QuantumSafe     bool   `json:"quantumSafe"`
	PQCAlgorithm    string `json:"pqcAlgorithm,omitempty"`    // e.g., "ML-KEM-768"
	HybridClassical string `json:"hybridClassical,omitempty"` // e.g., "X25519"
	// Negotiated marks the group this scan's own connection actually used, as
	// opposed to groups the server was separately found to support.
	Negotiated bool `json:"negotiated,omitempty"`
}

// Certificate represents an X.509 certificate.
type Certificate struct {
	Subject            string       `json:"subject"`
	Issuer             string       `json:"issuer"`
	SerialNumber       string       `json:"serialNumber"`
	NotBefore          time.Time    `json:"notBefore"`
	NotAfter           time.Time    `json:"notAfter"`
	SignatureAlgorithm string       `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string       `json:"publicKeyAlgorithm"`
	PublicKeyBits      int          `json:"publicKeyBits"`
	KeyUsage           []string     `json:"keyUsage,omitempty"`
	ExtKeyUsage        []string     `json:"extKeyUsage,omitempty"`
	SANs               []string     `json:"subjectAltNames,omitempty"`
	IsCA               bool         `json:"isCA"`
	IsSelfSigned       bool         `json:"isSelfSigned"`
	QuantumSafe        bool         `json:"quantumSafe"`
	DaysUntilExpiry    int          `json:"daysUntilExpiry"`
	Expired            bool         `json:"expired"`
	Fingerprints       Fingerprints `json:"fingerprints"`
}

// Fingerprints contains certificate fingerprints.
type Fingerprints struct {
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
}

// Vulnerability represents a detected security vulnerability.
type Vulnerability struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	CVE         string   `json:"cve,omitempty"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation"`
}

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// QuantumRiskAssessment provides quantum-specific risk analysis.
type QuantumRiskAssessment struct {
	Score           int       `json:"score"`           // 0-100, higher = more quantum-ready
	Level           RiskLevel `json:"level"`           // CRITICAL, HIGH, MEDIUM, LOW
	KeyExchangeRisk string    `json:"keyExchangeRisk"` // Risk from key exchange
	CertificateRisk string    `json:"certificateRisk"` // Risk from certificate
	HybridPQCReady  bool      `json:"hybridPqcReady"`  // Supports hybrid PQC
	FullPQCReady    bool      `json:"fullPqcReady"`    // Supports full PQC
	HNDLRisk        string    `json:"hndlRisk"`        // Harvest Now, Decrypt Later risk
	TimeToAction    string    `json:"timeToAction"`    // Recommended action timeline
	Details         []string  `json:"details"`
}

// RiskLevel represents quantum risk severity.
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

// Grade represents the overall TLS configuration grade.
type Grade struct {
	Letter       string        `json:"letter"`       // A+, A, B, C, D, F
	Score        int           `json:"score"`        // 0-100
	QuantumGrade string        `json:"quantumGrade"` // Separate quantum readiness grade
	Factors      []GradeFactor `json:"factors"`
}

// GradeFactor explains a component of the grade.
type GradeFactor struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	MaxScore int    `json:"maxScore"`
	Details  string `json:"details"`
}

// Recommendation provides actionable guidance.
type Recommendation struct {
	Priority    int      `json:"priority"` // 1 = highest
	Category    string   `json:"category"` // "quantum", "protocol", "cipher", "certificate"
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Impact      string   `json:"impact"`
	Effort      string   `json:"effort"` // "low", "medium", "high"
	References  []string `json:"references,omitempty"`
}
