// Package types defines the public types for the TLS analyzer.
package types

import (
	"encoding/json"
	"fmt"
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

// UnmarshalJSON implements json.Unmarshaler.
//
// Without it this type marshalled but could not be read back, so a consumer
// importing this package could not decode the tool's own JSON output into the
// tool's own public types: json.Unmarshal failed with "cannot unmarshal string
// into Go struct field ScanResult.duration of type types.Duration".
func (d *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		// Accept a plain nanosecond count as well, which is what a consumer
		// re-encoding the value with the standard time.Duration marshaller emits.
		var nanoseconds int64
		if numErr := json.Unmarshal(data, &nanoseconds); numErr != nil {
			return err
		}
		d.Duration = time.Duration(nanoseconds)
		return nil
	}

	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	d.Duration = parsed

	return nil
}

// Protocol represents a TLS protocol version.
type Protocol struct {
	Version   string `json:"version"` // e.g., "TLS 1.3", "TLS 1.2"
	Supported bool   `json:"supported"`
	Preferred bool   `json:"preferred,omitempty"`
}

// IsDeprecatedProtocol reports whether a protocol version is deprecated for
// use. It lives here so that the text report, the HTML report and the
// vulnerability checks answer the question from one place and cannot disagree
// about the same row: the HTML report painted TLS 1.0 and TLS 1.1 with the same
// green check as TLS 1.3, while the text report marked them "Supported
// (Deprecated)" and the vulnerability list flagged TLS 1.0 as HIGH.
func IsDeprecatedProtocol(version string) bool {
	switch version {
	case "SSL 3.0", "TLS 1.0", "TLS 1.1":
		return true
	}
	return false
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

	// Negotiated marks the suite this scan's own connection actually used, as
	// opposed to suites the server was separately found to accept.
	//
	// It matters most for TLS 1.3, where Go offers all three suites and ignores
	// per-suite configuration, so the one reported is chosen by this scanner's
	// client preference rather than the server's. Measured against openssl 3.6.1
	// on 2026-07-30: example.com, cloudflare.com and google.com all negotiate
	// TLS_AES_256_GCM_SHA384 when the client offers AES-256 first, while this
	// scanner reports TLS_AES_128_GCM_SHA256 for all three. Without this marker
	// the cipher list reads as the server's preference.
	Negotiated bool `json:"negotiated,omitempty"`
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
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	PublicKeyBits      int       `json:"publicKeyBits"`
	KeyUsage           []string  `json:"keyUsage,omitempty"`
	ExtKeyUsage        []string  `json:"extKeyUsage,omitempty"`
	SANs               []string  `json:"subjectAltNames,omitempty"`
	IsCA               bool      `json:"isCA"`
	IsSelfSigned       bool      `json:"isSelfSigned"`
	QuantumSafe        bool      `json:"quantumSafe"`
	DaysUntilExpiry    int       `json:"daysUntilExpiry"`
	Expired            bool      `json:"expired"`

	// NotYetValid reports that the certificate's validity period has not started.
	//
	// It is tracked separately from Expired because Go's x509 verifier returns
	// the same Expired reason for both ends of the window, and the chain check
	// steps aside for that reason on the grounds that "expiry is reported on its
	// own". Nothing reported this end of it, so a certificate dated to start next
	// year scored the certificate dimension 25 of 25 and graded A+ 100/100, while
	// every client would refuse it exactly as it refuses an expired one.
	NotYetValid bool `json:"notYetValid,omitempty"`

	Fingerprints Fingerprints `json:"fingerprints"`

	// RequestedName is the name that was asked of the server, which is the
	// --sni value when one was given and the target host otherwise. It is the
	// name NameMatch is a verdict about.
	RequestedName string `json:"requestedName,omitempty"`

	// NameMatch reports whether this certificate is valid for RequestedName.
	// Only the leaf is checked against a name; every certificate in the
	// presented chain carries CheckNotPerformed.
	NameMatch CheckResult `json:"nameMatch,omitempty"`

	// NameMismatchReason states why the certificate is not valid for
	// RequestedName, so the report can explain the verdict rather than assert it.
	NameMismatchReason string `json:"nameMismatchReason,omitempty"`

	// ChainTrust reports whether the presented chain builds to a root the
	// scanning host trusts, for server authentication. It is an independent
	// question from NameMatch, and the report must not answer one by the other.
	ChainTrust CheckResult `json:"chainTrust,omitempty"`

	// ChainTrustReason states why the chain was not trusted, or why the check
	// was not performed.
	ChainTrustReason string `json:"chainTrustReason,omitempty"`
}

// CheckResult is the outcome of a certificate check that has three states, so
// that "not checked" can never be read as "passed".
//
// The scanner handshakes with verification disabled on purpose: it has to be
// able to connect to and describe an expired, self-signed or untrusted
// certificate, which a verifying client would refuse outright. Disabling
// verification also silently disabled the name and trust checks, so a
// certificate issued for a different host, and a certificate from a root
// nothing trusts, were both reported as valid and awarded the full certificate
// score. These fields carry each check's own answer instead.
type CheckResult string

const (
	// CheckPassed means the check ran and the certificate satisfied it.
	CheckPassed CheckResult = "passed"
	// CheckFailed means the check ran and the certificate did not satisfy it.
	CheckFailed CheckResult = "failed"
	// CheckNotPerformed means the check did not run, so its result is unknown
	// rather than favourable.
	CheckNotPerformed CheckResult = "notPerformed"
)

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
	// Assessed is false when the assessment did not run, which makes every
	// other field in this struct unmeasured rather than zero.
	//
	// Nothing recorded that distinction before, so a zero-valued assessment
	// looked exactly like a measured score of 0 and reached four consumers as
	// one: the policy evaluator raised a HIGH violation reading "Actual: 0" in
	// the same report that said "Quantum Ready: not assessed"; the SARIF
	// reporter emitted a QUANTUM_VULNERABLE finding with an empty message into
	// a format CI systems act on; and the HTML report drew a Quantum Risk
	// Assessment section with an empty risk level styled as low risk. A
	// consumer that reads Score without reading this is reading a sentinel.
	Assessed bool `json:"assessed"`

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

	// DimensionScore is the score across the dimensions in Factors, normalized
	// to 0-100, before any vulnerability penalty. Score cannot be reconciled
	// from Factors alone: a skipped dimension changes the denominator, and the
	// penalty is applied after normalization.
	DimensionScore int `json:"dimensionScore"`

	// DimensionPoints and DimensionMaxPoints are the raw point total and
	// available points behind DimensionScore, so a reader can see why four
	// dimensions worth 25 each do not always total 100.
	DimensionPoints    int `json:"dimensionPoints"`
	DimensionMaxPoints int `json:"dimensionMaxPoints"`

	// SkippedDimensions names the dimensions that did not run, so Score is
	// normalized over a different set from a full scan's and the two are not
	// comparable in either direction. Skipping the quantum assessment removed the
	// dimension most servers score worst on, which RAISED the reported grade:
	// github.com moved from D (40/100) to C (61/100) and a well-configured host
	// reached A+ (100/100) purely by declining to look.
	SkippedDimensions []string `json:"skippedDimensions,omitempty"`

	// VulnerabilityPenalty is the total number of points deducted from
	// DimensionScore for detected vulnerabilities, as a positive number. The
	// penalty was previously applied but never reported, so a breakdown reading
	// 10 + 15 + 25 + 16 = 66 printed under a headline of 21/100 with nothing to
	// account for the difference.
	VulnerabilityPenalty int `json:"vulnerabilityPenalty"`

	// Penalties itemizes VulnerabilityPenalty by severity.
	Penalties []GradePenalty `json:"penalties,omitempty"`

	// PenaltyFloored records that the penalty exceeded DimensionScore and Score
	// was held at zero, so the printed arithmetic would not otherwise close.
	PenaltyFloored bool `json:"penaltyFloored,omitempty"`

	// VulnerabilitiesAssessed is false when the vulnerability checks did not
	// run, which makes the penalty unmeasured rather than zero. Score is then an
	// upper bound on what a full scan would report and is not comparable with
	// one. Declining a check must not read as an improvement.
	VulnerabilitiesAssessed bool `json:"vulnerabilitiesAssessed"`
}

// QuantumGradeNotAssessed is the QuantumGrade value used when the quantum risk
// assessment did not run. The reporters branch on it to omit a section rather
// than render a zero-valued assessment, so it is defined once here instead of
// repeated as a literal in each package that compares it.
const QuantumGradeNotAssessed = "not assessed"

// GradeFactor explains a component of the grade.
type GradeFactor struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	MaxScore int    `json:"maxScore"`
	Details  string `json:"details"`
}

// GradePenalty itemizes one severity's contribution to the vulnerability
// penalty, so the deduction can be traced to the findings that caused it.
type GradePenalty struct {
	Severity    Severity `json:"severity"`
	Count       int      `json:"count"`
	PointsEach  int      `json:"pointsEach"`
	PointsTotal int      `json:"pointsTotal"`
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
