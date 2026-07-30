// Package analyzer provides advanced analysis capabilities.
package analyzer

import (
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// CNSA2Analyzer performs CNSA 2.0 compliance analysis.
type CNSA2Analyzer struct{}

// NewCNSA2Analyzer creates a new CNSA 2.0 analyzer.
func NewCNSA2Analyzer() *CNSA2Analyzer {
	return &CNSA2Analyzer{}
}

// CNSA 2.0 algorithm classifications.
var (
	// Approved algorithms for CNSA 2.0
	CNSA2ApprovedKeyExchange = map[string]bool{
		"ML-KEM-768":         true,
		"ML-KEM-1024":        true,
		"X25519MLKEM768":     true,
		"SecP256r1MLKEM768":  true,
		"SecP384r1MLKEM1024": true,
	}

	CNSA2ApprovedSignatures = map[string]bool{
		"ML-DSA-65":          true,
		"ML-DSA-87":          true,
		"SLH-DSA-SHA2-128s":  true,
		"SLH-DSA-SHA2-128f":  true,
		"SLH-DSA-SHA2-192s":  true,
		"SLH-DSA-SHA2-192f":  true,
		"SLH-DSA-SHA2-256s":  true,
		"SLH-DSA-SHA2-256f":  true,
		"SLH-DSA-SHAKE-128s": true,
		"SLH-DSA-SHAKE-128f": true,
		"SLH-DSA-SHAKE-192s": true,
		"SLH-DSA-SHAKE-192f": true,
		"SLH-DSA-SHAKE-256s": true,
		"SLH-DSA-SHAKE-256f": true,
	}

	CNSA2ApprovedSymmetric = map[string]bool{
		"AES-256":     true,
		"AES-256-GCM": true,
	}

	CNSA2ApprovedHash = map[string]bool{
		"SHA-384":  true,
		"SHA-512":  true,
		"SHA3-384": true,
		"SHA3-512": true,
	}

	// Transitional algorithms (allowed until deadline)
	CNSA2Transitional = map[string]string{
		"RSA-3072":   "2030",
		"RSA-4096":   "2030",
		"ECDSA-P384": "2030",
		"ECDH-P384":  "2030",
		"X25519":     "2030", // Only in hybrid mode
		"SHA-256":    "2030",
	}

	// Deprecated algorithms (should be phased out)
	CNSA2Deprecated = map[string]string{
		"RSA-2048":   "Immediately",
		"ECDSA-P256": "2027",
		"ECDH-P256":  "2027",
		"SHA-1":      "Immediately",
		"3DES":       "Immediately",
		"RC4":        "Immediately",
	}
)

// Milestones defines CNSA 2.0 timeline.
var CNSA2Milestones = []struct {
	Name         string
	Deadline     time.Time
	Description  string
	Requirements []string
}{
	{
		Name:        "Preparation Phase",
		Deadline:    time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		Description: "Begin PQC integration planning",
		Requirements: []string{
			"Inventory cryptographic assets",
			"Identify quantum-vulnerable systems",
			"Begin testing PQC algorithms",
		},
	},
	{
		Name:        "New NSS Systems",
		Deadline:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Description: "New National Security Systems must use CNSA 2.0 algorithms",
		Requirements: []string{
			"ML-KEM for key establishment",
			"ML-DSA or SLH-DSA for signatures",
			"AES-256 for symmetric encryption",
			"SHA-384 or SHA-512 for hashing",
		},
	},
	{
		Name:        "TLS 1.3 Required",
		Deadline:    time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC),
		Description: "TLS 1.3 with PQC required for all systems",
		Requirements: []string{
			"TLS 1.3 mandatory",
			"Hybrid PQC key exchange required",
			"RSA/ECDH no longer acceptable",
		},
	},
	{
		Name:        "Legacy System Update",
		Deadline:    time.Date(2033, 1, 1, 0, 0, 0, 0, time.UTC),
		Description: "All legacy systems updated to CNSA 2.0",
		Requirements: []string{
			"Complete migration of existing systems",
			"PQC certificates widely deployed",
		},
	},
	{
		Name:        "Full PQC Transition",
		Deadline:    time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		Description: "Transition to pure PQC complete",
		Requirements: []string{
			"Pure PQC (no hybrid required)",
			"Classical algorithms fully retired",
		},
	},
}

// CNSA2TimelineScope states what a milestone status answers for.
//
// This section and a policy evaluation of the same CNSA 2.0 target year
// previously printed opposite verdicts for the same deadline, with nothing to
// tell a reader they were answering different questions: "cnsa-2.0-2027:
// NON-COMPLIANT, 0/100, 16 violations" beside "New NSS Systems (2027-01-01):
// compliant". Both are defensible, because a milestone asks whether the required
// algorithms are available at all while a policy asks whether everything the
// server still accepts qualifies. Each verdict now states its own scope and
// names the other.
const CNSA2TimelineScope = "milestone status reports whether this server can " +
	"negotiate the algorithms a milestone requires. A milestone can be met while " +
	"the server also still accepts weaker options, so a policy evaluation of the " +
	"same target year, which requires every accepted protocol and cipher suite to " +
	"qualify, can report non-compliant against the same deadline. Read the " +
	"milestones for adoption and the policy evaluation for exclusivity."

// Analyze performs CNSA 2.0 compliance analysis.
func (a *CNSA2Analyzer) Analyze(result *types.ScanResult) *types.CNSA2Timeline {
	now := time.Now()

	timeline := &types.CNSA2Timeline{
		AssessmentDate: now,
		Scope:          CNSA2TimelineScope,
		Milestones:     make([]types.CNSA2Milestone, 0),
		Findings:       make([]types.CNSA2Finding, 0),
	}

	// Analyze each milestone
	for _, m := range CNSA2Milestones {
		milestone := a.analyzeMilestone(result, m, now)
		timeline.Milestones = append(timeline.Milestones, milestone)
	}

	// Analyze algorithms
	timeline.Findings = append(timeline.Findings, a.analyzeKeyExchange(result)...)
	timeline.Findings = append(timeline.Findings, a.analyzeSignatures(result)...)
	timeline.Findings = append(timeline.Findings, a.analyzeSymmetric(result)...)

	// Calculate overall score and phase
	timeline.TimelineScore = a.calculateTimelineScore(timeline)
	timeline.CurrentPhase = a.determineCurrentPhase(timeline, now)
	timeline.DaysToNextDeadline = a.daysToNextDeadline(now)
	timeline.NextAction = a.determineNextAction(timeline)

	return timeline
}

func (a *CNSA2Analyzer) analyzeMilestone(result *types.ScanResult, m struct {
	Name         string
	Deadline     time.Time
	Description  string
	Requirements []string
}, now time.Time) types.CNSA2Milestone {

	milestone := types.CNSA2Milestone{
		Name:        m.Name,
		Deadline:    m.Deadline,
		Description: m.Description,
		Required:    m.Requirements,
		Current:     make([]string, 0),
		Gap:         make([]string, 0),
	}

	// Check compliance based on milestone
	switch m.Name {
	case "Preparation Phase":
		milestone.Status = "in-progress" // Assumed if scanning
		milestone.Current = append(milestone.Current, "Cryptographic scanning initiated")

	case "New NSS Systems":
		hasHybridPQC := false
		for _, ke := range result.KeyExchanges {
			if ke.Type == "hybrid" || ke.Type == "pqc" {
				hasHybridPQC = true
				milestone.Current = append(milestone.Current, "PQC key exchange: "+ke.Name)
			}
		}
		if !hasHybridPQC {
			milestone.Gap = append(milestone.Gap, "ML-KEM key exchange not detected")
		}

		// Check symmetric strength. An absent 256-bit suite previously recorded
		// no gap at all, so a server offering only 128-bit suites was reported
		// compliant against a milestone whose own requirement list names AES-256.
		// The gap is only recorded when suites were actually observed: an
		// unobserved cipher list is not a measured absence.
		hasAES256 := false
		for _, cs := range result.CipherSuites {
			if cs.Bits >= 256 {
				hasAES256 = true
				milestone.Current = append(milestone.Current, "AES-256 encryption detected")
				break
			}
		}
		if !hasAES256 && len(result.CipherSuites) > 0 {
			milestone.Gap = append(milestone.Gap,
				"no 256-bit symmetric cipher suite detected (CNSA 2.0 requires AES-256)")
		}

		if len(milestone.Gap) == 0 && hasHybridPQC {
			milestone.Status = "compliant"
		} else if hasHybridPQC {
			milestone.Status = "partial"
		} else {
			milestone.Status = "non-compliant"
		}

	case "TLS 1.3 Required":
		hasTLS13 := false
		for _, p := range result.Protocols {
			if p.Version == "TLS 1.3" && p.Supported {
				hasTLS13 = true
				milestone.Current = append(milestone.Current, "TLS 1.3 supported")
				break
			}
		}
		if !hasTLS13 {
			milestone.Gap = append(milestone.Gap, "TLS 1.3 not supported")
		}

		hasLegacy := false
		for _, p := range result.Protocols {
			if p.Supported && (p.Version == "TLS 1.0" || p.Version == "TLS 1.1" || p.Version == "TLS 1.2") {
				hasLegacy = true
				milestone.Gap = append(milestone.Gap, "Legacy protocol still enabled: "+p.Version)
			}
		}

		if hasTLS13 && !hasLegacy {
			milestone.Status = "compliant"
		} else if hasTLS13 {
			milestone.Status = "partial"
		} else {
			milestone.Status = "non-compliant"
		}

	case "Legacy System Update", "Full PQC Transition":
		// Future milestones - check PQC certificate support
		if result.Certificate != nil && result.Certificate.QuantumSafe {
			milestone.Current = append(milestone.Current, "PQC certificate detected")
			milestone.Status = "compliant"
		} else {
			milestone.Gap = append(milestone.Gap, "PQC certificates not yet available")
			milestone.Status = "not-applicable" // Not yet required
		}
	}

	return milestone
}

func (a *CNSA2Analyzer) analyzeKeyExchange(result *types.ScanResult) []types.CNSA2Finding {
	var findings []types.CNSA2Finding

	for _, ke := range result.KeyExchanges {
		finding := types.CNSA2Finding{
			Category:  "key-exchange",
			Algorithm: ke.Name,
		}

		if CNSA2ApprovedKeyExchange[ke.Name] || CNSA2ApprovedKeyExchange[ke.PQCAlgorithm] {
			finding.Status = "approved"
		} else if deadline, ok := CNSA2Transitional[ke.Name]; ok {
			finding.Status = "transitional"
			finding.Deadline = deadline
			finding.Replacement = "X25519MLKEM768 or SecP384r1MLKEM1024"
		} else if deadline, ok := CNSA2Deprecated[ke.Name]; ok {
			finding.Status = "deprecated"
			finding.Deadline = deadline
			finding.Replacement = "ML-KEM-768 or ML-KEM-1024"
		} else {
			// Classical algorithm
			finding.Status = "deprecated"
			finding.Deadline = "2030"
			finding.Replacement = "Hybrid PQC (X25519MLKEM768)"
		}

		findings = append(findings, finding)
	}

	// If no PQC key exchange detected
	if len(result.KeyExchanges) > 0 {
		hasPQC := false
		for _, ke := range result.KeyExchanges {
			if ke.Type == "hybrid" || ke.Type == "pqc" {
				hasPQC = true
				break
			}
		}
		if !hasPQC {
			findings = append(findings, types.CNSA2Finding{
				Category:    "key-exchange",
				Algorithm:   "classical-only",
				Status:      "prohibited",
				Replacement: "Enable hybrid PQC key exchange",
				Deadline:    "2027 (new systems) / 2030 (all systems)",
				References:  []string{"https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"},
			})
		}
	}

	return findings
}

func (a *CNSA2Analyzer) analyzeSignatures(result *types.ScanResult) []types.CNSA2Finding {
	var findings []types.CNSA2Finding

	if result.Certificate == nil {
		return findings
	}

	finding := types.CNSA2Finding{
		Category:  "signature",
		Algorithm: result.Certificate.SignatureAlgorithm,
	}

	sigAlgo := result.Certificate.SignatureAlgorithm

	if CNSA2ApprovedSignatures[sigAlgo] {
		finding.Status = "approved"
	} else if containsSubstring(sigAlgo, "SHA384", "SHA512") {
		finding.Status = "transitional"
		finding.Deadline = "2033"
		finding.Replacement = "ML-DSA-65 or ML-DSA-87"
	} else if containsSubstring(sigAlgo, "SHA256") {
		finding.Status = "transitional"
		finding.Deadline = "2030"
		finding.Replacement = "ML-DSA-65 or ML-DSA-87"
	} else {
		finding.Status = "deprecated"
		finding.Deadline = "Immediately"
		finding.Replacement = "Reissue with SHA-384+ (transitional) or ML-DSA (target)"
	}

	findings = append(findings, finding)

	// Check key algorithm
	keyFinding := types.CNSA2Finding{
		Category:  "signature-key",
		Algorithm: result.Certificate.PublicKeyAlgorithm,
	}

	switch result.Certificate.PublicKeyAlgorithm {
	case "RSA":
		if result.Certificate.PublicKeyBits >= 3072 {
			keyFinding.Status = "transitional"
			keyFinding.Deadline = "2030"
		} else {
			keyFinding.Status = "deprecated"
			keyFinding.Deadline = "Immediately"
		}
		keyFinding.Replacement = "ML-DSA certificates (when available)"
	case "ECDSA":
		if result.Certificate.PublicKeyBits >= 384 {
			keyFinding.Status = "transitional"
			keyFinding.Deadline = "2030"
		} else {
			keyFinding.Status = "deprecated"
			keyFinding.Deadline = "2027"
		}
		keyFinding.Replacement = "ML-DSA certificates (when available)"
	case "ML-DSA", "CRYSTALS-Dilithium":
		keyFinding.Status = "approved"
	case "SLH-DSA", "SPHINCS+":
		keyFinding.Status = "approved"
	default:
		keyFinding.Status = "unknown"
	}

	findings = append(findings, keyFinding)

	return findings
}

func (a *CNSA2Analyzer) analyzeSymmetric(result *types.ScanResult) []types.CNSA2Finding {
	var findings []types.CNSA2Finding

	for _, cs := range result.CipherSuites {
		finding := types.CNSA2Finding{
			Category:  "symmetric",
			Algorithm: cs.Encryption,
		}

		if cs.Bits >= 256 {
			finding.Status = "approved"
		} else if cs.Bits >= 128 {
			finding.Status = "transitional"
			finding.Deadline = "2030"
			finding.Replacement = "AES-256"
		} else {
			finding.Status = "deprecated"
			finding.Deadline = "Immediately"
			finding.Replacement = "AES-256-GCM"
		}

		findings = append(findings, finding)
	}

	return findings
}

func (a *CNSA2Analyzer) calculateTimelineScore(timeline *types.CNSA2Timeline) int {
	if len(timeline.Milestones) == 0 {
		return 0
	}

	totalWeight := 0
	score := 0

	weights := map[string]int{
		"Preparation Phase":    10,
		"New NSS Systems":      30,
		"TLS 1.3 Required":     25,
		"Legacy System Update": 20,
		"Full PQC Transition":  15,
	}

	statusScores := map[string]int{
		"compliant":      100,
		"partial":        60,
		"in-progress":    40,
		"non-compliant":  0,
		"not-applicable": 100, // Future requirements don't penalize
	}

	for _, m := range timeline.Milestones {
		weight := weights[m.Name]
		totalWeight += weight
		score += weight * statusScores[m.Status] / 100
	}

	if totalWeight == 0 {
		return 0
	}

	return (score * 100) / totalWeight
}

func (a *CNSA2Analyzer) determineCurrentPhase(timeline *types.CNSA2Timeline, now time.Time) string {
	for _, m := range CNSA2Milestones {
		if now.Before(m.Deadline) {
			return m.Name
		}
	}
	return "Full PQC Transition"
}

func (a *CNSA2Analyzer) daysToNextDeadline(now time.Time) int {
	for _, m := range CNSA2Milestones {
		if now.Before(m.Deadline) {
			return int(m.Deadline.Sub(now).Hours() / 24)
		}
	}
	return 0
}

func (a *CNSA2Analyzer) determineNextAction(timeline *types.CNSA2Timeline) string {
	for _, m := range timeline.Milestones {
		if m.Status == "non-compliant" || m.Status == "partial" {
			if len(m.Gap) > 0 {
				return m.Gap[0]
			}
		}
	}

	// Find deprecated algorithms
	for _, f := range timeline.Findings {
		if f.Status == "deprecated" || f.Status == "prohibited" {
			return "Replace " + f.Algorithm + " with " + f.Replacement
		}
	}

	return "Continue monitoring PQC developments"
}

func containsSubstring(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
