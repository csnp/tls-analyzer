package types

import "time"

// ComplianceFramework represents a security compliance standard.
type ComplianceFramework string

const (
	FrameworkCNSA2   ComplianceFramework = "CNSA 2.0"
	FrameworkNIST    ComplianceFramework = "NIST 800-53"
	FrameworkCMMC    ComplianceFramework = "CMMC"
	FrameworkPCIDSS  ComplianceFramework = "PCI-DSS"
	FrameworkFedRAMP ComplianceFramework = "FedRAMP"
	FrameworkHIPAA   ComplianceFramework = "HIPAA"
	FrameworkSOC2    ComplianceFramework = "SOC 2"
)

// CNSA2Timeline represents NSA's Commercial National Security Algorithm Suite 2.0 milestones.
type CNSA2Timeline struct {
	// Current assessment date
	AssessmentDate time.Time `json:"assessmentDate"`

	// Scope states what question the milestone statuses answer. Without it, this
	// section and a policy evaluation of the same standard can print opposite
	// verdicts for the same deadline with nothing to tell a reader that they
	// measure different things.
	Scope string `json:"scope"`

	// Milestone compliance status
	Milestones []CNSA2Milestone `json:"milestones"`

	// Overall timeline score (0-100)
	TimelineScore int `json:"timelineScore"`

	// Current phase
	CurrentPhase string `json:"currentPhase"`

	// Days until next deadline
	DaysToNextDeadline int `json:"daysToNextDeadline"`

	// Next required action
	NextAction string `json:"nextAction"`

	// Detailed findings
	Findings []CNSA2Finding `json:"findings"`
}

// CNSA2Milestone represents a specific CNSA 2.0 deadline.
type CNSA2Milestone struct {
	Name        string    `json:"name"`
	Deadline    time.Time `json:"deadline"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // compliant, non-compliant, partial, not-applicable
	Required    []string  `json:"required"`
	Current     []string  `json:"current"`
	Gap         []string  `json:"gap,omitempty"`
}

// CNSA2Finding represents a specific CNSA 2.0 compliance finding.
type CNSA2Finding struct {
	Category    string   `json:"category"` // key-exchange, signature, symmetric, hash
	Algorithm   string   `json:"algorithm"`
	Status      string   `json:"status"` // approved, transitional, deprecated, prohibited
	Replacement string   `json:"replacement,omitempty"`
	Deadline    string   `json:"deadline,omitempty"`
	References  []string `json:"references,omitempty"`
}

// ComplianceResult represents compliance against a specific framework.
type ComplianceResult struct {
	Framework    ComplianceFramework `json:"framework"`
	Version      string              `json:"version"`
	AssessedAt   time.Time           `json:"assessedAt"`
	OverallScore int                 `json:"overallScore"`
	Status       string              `json:"status"` // compliant, non-compliant, partial
	Controls     []ControlMapping    `json:"controls"`
	Findings     []ComplianceFinding `json:"findings"`
}

// ControlMapping maps a finding to specific compliance controls.
type ControlMapping struct {
	ControlID   string `json:"controlId"`
	ControlName string `json:"controlName"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
}

// ComplianceFinding represents a specific compliance issue.
type ComplianceFinding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Controls    []string `json:"controls"` // Affected control IDs
	References  []string `json:"references,omitempty"`
}

// NIST80053Controls maps common TLS issues to NIST 800-53 controls.
var NIST80053Controls = map[string]ControlMapping{
	"TLS_VERSION": {
		ControlID:   "SC-8",
		ControlName: "Transmission Confidentiality and Integrity",
	},
	"CIPHER_STRENGTH": {
		ControlID:   "SC-13",
		ControlName: "Cryptographic Protection",
	},
	"CERTIFICATE": {
		ControlID:   "IA-5",
		ControlName: "Authenticator Management",
	},
	"KEY_MANAGEMENT": {
		ControlID:   "SC-12",
		ControlName: "Cryptographic Key Establishment and Management",
	},
	"PQC_READINESS": {
		ControlID:   "SC-13(4)",
		ControlName: "Cryptographic Protection | Quantum Resistance",
	},
}

// CMMCControls maps TLS issues to CMMC controls.
var CMMCControls = map[string]ControlMapping{
	"TLS_VERSION": {
		ControlID:   "SC.L2-3.13.8",
		ControlName: "Cryptographic Protection",
	},
	"CIPHER_STRENGTH": {
		ControlID:   "SC.L2-3.13.11",
		ControlName: "FIPS Validated Cryptography",
	},
}

// PCIDSSControls maps TLS issues to PCI-DSS requirements.
var PCIDSSControls = map[string]ControlMapping{
	"TLS_VERSION": {
		ControlID:   "4.1",
		ControlName: "Strong Cryptography for Transmission",
	},
	"WEAK_CIPHER": {
		ControlID:   "2.2.5",
		ControlName: "Remove Insecure Services and Protocols",
	},
}
