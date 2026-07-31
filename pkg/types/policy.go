package types

import "reflect"

// Policy defines organizational TLS security requirements.
type Policy struct {
	// Metadata
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Extends another policy
	Extends string `json:"extends,omitempty" yaml:"extends,omitempty"`

	// Rules
	Rules PolicyRules `json:"rules" yaml:"rules"`

	// Scoring weights (optional overrides)
	Weights *ScoringWeights `json:"weights,omitempty" yaml:"weights,omitempty"`
}

// PolicyRules contains all policy rules.
type PolicyRules struct {
	// Protocol requirements
	Protocol ProtocolRules `json:"protocol" yaml:"protocol"`

	// Cipher requirements
	Cipher CipherRules `json:"cipher" yaml:"cipher"`

	// Certificate requirements
	Certificate CertificateRules `json:"certificate" yaml:"certificate"`

	// Quantum/PQC requirements
	Quantum QuantumRules `json:"quantum" yaml:"quantum"`
}

// IsEmpty reports whether no rule at all is set, which makes the policy one
// that nothing can fail. A compliant verdict from such a policy carries no
// information, so a policy file that produces one is refused at load.
//
// The comparison is against the zero value rather than a list of fields, so a
// rule field added later is covered without anyone remembering to come back
// here. Hand-maintained field lists are what let the extends merge silently
// drop most of a policy file.
func (r PolicyRules) IsEmpty() bool {
	return reflect.DeepEqual(r, PolicyRules{})
}

// ProtocolRules defines TLS protocol requirements.
type ProtocolRules struct {
	MinVersion       string   `json:"minVersion" yaml:"minVersion"`
	MaxVersion       string   `json:"maxVersion,omitempty" yaml:"maxVersion,omitempty"`
	RequiredVersions []string `json:"requiredVersions,omitempty" yaml:"requiredVersions,omitempty"`
	BannedVersions   []string `json:"bannedVersions,omitempty" yaml:"bannedVersions,omitempty"`
}

// CipherRules defines cipher suite requirements.
type CipherRules struct {
	// Minimum key size in bits
	MinKeySize int `json:"minKeySize" yaml:"minKeySize"`

	// Require forward secrecy
	RequireForwardSecrecy bool `json:"requireForwardSecrecy" yaml:"requireForwardSecrecy"`

	// Required key exchange algorithms
	RequiredKeyExchange []string `json:"requiredKeyExchange,omitempty" yaml:"requiredKeyExchange,omitempty"`

	// Banned algorithms
	BannedAlgorithms []string `json:"bannedAlgorithms,omitempty" yaml:"bannedAlgorithms,omitempty"`

	// Allowed cipher suites (whitelist)
	AllowedCipherSuites []string `json:"allowedCipherSuites,omitempty" yaml:"allowedCipherSuites,omitempty"`

	// Banned cipher suites (blacklist)
	BannedCipherSuites []string `json:"bannedCipherSuites,omitempty" yaml:"bannedCipherSuites,omitempty"`
}

// CertificateRules defines certificate requirements.
type CertificateRules struct {
	// Minimum days until expiry (warning threshold)
	MinValidityDays int `json:"minValidityDays" yaml:"minValidityDays"`

	// Maximum validity period (e.g., 398 days for public certs)
	MaxValidityDays int `json:"maxValidityDays,omitempty" yaml:"maxValidityDays,omitempty"`

	// Minimum RSA key size
	MinRSAKeySize int `json:"minRsaKeySize" yaml:"minRsaKeySize"`

	// Minimum ECC key size
	MinECCKeySize int `json:"minEccKeySize" yaml:"minEccKeySize"`

	// Required signature algorithms
	RequiredSignatureAlgorithms []string `json:"requiredSignatureAlgorithms,omitempty" yaml:"requiredSignatureAlgorithms,omitempty"`

	// Banned signature algorithms
	BannedSignatureAlgorithms []string `json:"bannedSignatureAlgorithms,omitempty" yaml:"bannedSignatureAlgorithms,omitempty"`

	// Require Certificate Transparency
	RequireCT bool `json:"requireCt,omitempty" yaml:"requireCt,omitempty"`

	// Allow self-signed
	AllowSelfSigned bool `json:"allowSelfSigned" yaml:"allowSelfSigned"`
}

// QuantumRules defines post-quantum cryptography requirements.
type QuantumRules struct {
	// Require hybrid PQC key exchange
	RequireHybridKeyExchange bool `json:"requireHybridKeyExchange" yaml:"requireHybridKeyExchange"`

	// Require PQC certificates (future)
	RequirePQCCertificates bool `json:"requirePqcCertificates" yaml:"requirePqcCertificates"`

	// Minimum quantum readiness score
	MinQuantumScore int `json:"minQuantumScore" yaml:"minQuantumScore"`

	// Required key exchange algorithms
	RequiredKeyExchangeAlgorithms []string `json:"requiredKeyExchangeAlgorithms,omitempty" yaml:"requiredKeyExchangeAlgorithms,omitempty"`

	// CNSA 2.0 compliance target year (2027, 2030, 2033, 2035)
	CNSA2TargetYear int `json:"cnsa2TargetYear,omitempty" yaml:"cnsa2TargetYear,omitempty"`
}

// ScoringWeights customizes the grading weights.
type ScoringWeights struct {
	Protocol    int `json:"protocol" yaml:"protocol"`
	Cipher      int `json:"cipher" yaml:"cipher"`
	Certificate int `json:"certificate" yaml:"certificate"`
	Quantum     int `json:"quantum" yaml:"quantum"`
}

// PolicyViolation represents a policy rule violation.
type PolicyViolation struct {
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Expected    string   `json:"expected"`
	Actual      string   `json:"actual"`
	Remediation string   `json:"remediation"`
}

// SkippedPolicyRule records a rule that was not evaluated because the input it
// reads was not measured in this scan.
//
// A rule whose input was not measured is neither passed nor failed, and it must
// not be treated as either. Reading an unmeasured quantum score as the number 0
// produced "[HIGH] Quantum readiness score below minimum, Expected: >= 90 |
// Actual: 0" in the same report that said "Quantum Ready: not assessed".
type SkippedPolicyRule struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// PolicyResult contains the results of policy evaluation.
type PolicyResult struct {
	PolicyName string `json:"policyName"`
	Compliant  bool   `json:"compliant"`
	Score      int    `json:"score"`

	// Complete is false when at least one rule was skipped, which makes both
	// Compliant and Score answers about a smaller set of rules than the policy
	// defines. Score is computed by deducting from 100, so a skipped rule can
	// only raise it, and declining a check must never read as an improvement.
	//
	// The zero value is the cautious one: a PolicyResult that nothing filled in
	// does not claim to be a complete evaluation.
	Complete bool `json:"complete"`

	// SkippedRules names what was not evaluated and why.
	SkippedRules []SkippedPolicyRule `json:"skippedRules,omitempty"`

	// Scope states what this verdict covers. A policy evaluation of a CNSA 2.0
	// target year and the CNSA 2.0 timeline section can disagree about the same
	// deadline because they ask different questions, and neither said so.
	Scope string `json:"scope"`

	Violations []PolicyViolation `json:"violations"`
	Warnings   []PolicyViolation `json:"warnings"`
}

// DefaultPolicies contains built-in policies.
var DefaultPolicies = map[string]Policy{
	"modern": {
		Name:        "modern",
		Version:     "1.0",
		Description: "Modern TLS configuration for 2024+",
		Rules: PolicyRules{
			Protocol: ProtocolRules{
				MinVersion:     "TLS 1.2",
				BannedVersions: []string{"TLS 1.0", "TLS 1.1"},
			},
			Cipher: CipherRules{
				MinKeySize:            128,
				RequireForwardSecrecy: true,
				BannedAlgorithms:      []string{"3DES", "RC4", "MD5", "SHA1"},
			},
			Certificate: CertificateRules{
				MinValidityDays:           30,
				MinRSAKeySize:             2048,
				MinECCKeySize:             256,
				BannedSignatureAlgorithms: []string{"SHA1", "MD5"},
				AllowSelfSigned:           false,
			},
			Quantum: QuantumRules{
				RequireHybridKeyExchange: false,
				MinQuantumScore:          0,
			},
		},
	},
	"strict": {
		Name:        "strict",
		Version:     "1.0",
		Description: "Strict TLS configuration with TLS 1.3 required",
		Rules: PolicyRules{
			Protocol: ProtocolRules{
				MinVersion:       "TLS 1.3",
				RequiredVersions: []string{"TLS 1.3"},
				BannedVersions:   []string{"TLS 1.0", "TLS 1.1", "TLS 1.2"},
			},
			Cipher: CipherRules{
				MinKeySize:            256,
				RequireForwardSecrecy: true,
				BannedAlgorithms:      []string{"3DES", "RC4", "MD5", "SHA1", "CBC"},
			},
			Certificate: CertificateRules{
				MinValidityDays:           30,
				MinRSAKeySize:             4096,
				MinECCKeySize:             384,
				BannedSignatureAlgorithms: []string{"SHA1", "MD5", "SHA256"},
				AllowSelfSigned:           false,
			},
			Quantum: QuantumRules{
				RequireHybridKeyExchange: false,
				MinQuantumScore:          0,
			},
		},
	},
	"cnsa-2.0-2027": {
		Name:        "cnsa-2.0-2027",
		Version:     "1.0",
		Description: "CNSA 2.0 compliance target for 2027 - new NSS systems",
		Rules: PolicyRules{
			Protocol: ProtocolRules{
				MinVersion:       "TLS 1.2",
				RequiredVersions: []string{"TLS 1.3"},
			},
			Cipher: CipherRules{
				MinKeySize:            256,
				RequireForwardSecrecy: true,
				RequiredKeyExchange:   []string{"X25519MLKEM768", "SecP384r1MLKEM1024"},
			},
			Certificate: CertificateRules{
				MinValidityDays: 30,
				MinRSAKeySize:   3072,
				MinECCKeySize:   384,
			},
			Quantum: QuantumRules{
				RequireHybridKeyExchange:      true,
				MinQuantumScore:               50,
				CNSA2TargetYear:               2027,
				RequiredKeyExchangeAlgorithms: []string{"ML-KEM-768", "ML-KEM-1024"},
			},
		},
	},
	"cnsa-2.0-2030": {
		Name:        "cnsa-2.0-2030",
		Version:     "1.0",
		Description: "CNSA 2.0 compliance target for 2030 - TLS 1.3 required",
		Rules: PolicyRules{
			Protocol: ProtocolRules{
				MinVersion:       "TLS 1.3",
				RequiredVersions: []string{"TLS 1.3"},
				BannedVersions:   []string{"TLS 1.0", "TLS 1.1", "TLS 1.2"},
			},
			Cipher: CipherRules{
				MinKeySize:            256,
				RequireForwardSecrecy: true,
				RequiredKeyExchange:   []string{"X25519MLKEM768", "SecP384r1MLKEM1024"},
			},
			Certificate: CertificateRules{
				MinValidityDays: 30,
				MinRSAKeySize:   3072,
				MinECCKeySize:   384,
			},
			Quantum: QuantumRules{
				RequireHybridKeyExchange:      true,
				MinQuantumScore:               70,
				CNSA2TargetYear:               2030,
				RequiredKeyExchangeAlgorithms: []string{"ML-KEM-768", "ML-KEM-1024"},
			},
		},
	},
	"cnsa-2.0-2035": {
		Name:        "cnsa-2.0-2035",
		Version:     "1.0",
		Description: "CNSA 2.0 compliance target for 2035 - full PQC",
		Rules: PolicyRules{
			Protocol: ProtocolRules{
				MinVersion:       "TLS 1.3",
				RequiredVersions: []string{"TLS 1.3"},
			},
			Cipher: CipherRules{
				MinKeySize:            256,
				RequireForwardSecrecy: true,
			},
			Certificate: CertificateRules{
				MinValidityDays:             30,
				MinRSAKeySize:               4096,
				MinECCKeySize:               384,
				RequiredSignatureAlgorithms: []string{"ML-DSA-65", "ML-DSA-87", "SLH-DSA"},
			},
			Quantum: QuantumRules{
				RequireHybridKeyExchange:      true,
				RequirePQCCertificates:        true,
				MinQuantumScore:               90,
				CNSA2TargetYear:               2035,
				RequiredKeyExchangeAlgorithms: []string{"ML-KEM-768", "ML-KEM-1024"},
			},
		},
	},
}
