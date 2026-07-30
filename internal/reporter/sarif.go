package reporter

import (
	"encoding/json"
	"io"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// SARIFReporter outputs results in SARIF format for security tool integration.
type SARIFReporter struct{}

// SARIF schema structures
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
	SemanticVersion string      `json:"semanticVersion"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription,omitempty"`
	Help             sarifMessage    `json:"help,omitempty"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
	Properties       sarifProperties `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Security struct {
		Severity string `json:"severity,omitempty"`
	} `json:"security,omitempty"`
}

// Report writes the scan result in SARIF format.
func (r *SARIFReporter) Report(w io.Writer, result *types.ScanResult) error {
	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "qramm-tls-analyzer",
						Version:         result.ScannerVersion,
						SemanticVersion: result.ScannerVersion,
						InformationURI:  "https://github.com/csnp/qramm-tls-analyzer",
						Rules:           r.buildRules(result),
					},
				},
				Results: r.buildResults(result),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// Format returns the format name.
func (r *SARIFReporter) Format() string {
	return string(FormatSARIF)
}

func (r *SARIFReporter) buildRules(result *types.ScanResult) []sarifRule {
	var rules []sarifRule
	ruleMap := make(map[string]bool)

	// Add vulnerability rules
	for _, v := range result.Vulnerabilities {
		if ruleMap[v.ID] {
			continue
		}
		ruleMap[v.ID] = true

		rules = append(rules, sarifRule{
			ID:               v.ID,
			Name:             v.Name,
			ShortDescription: sarifMessage{Text: v.Name},
			FullDescription:  sarifMessage{Text: v.Description},
			Help:             sarifMessage{Text: v.Remediation},
			DefaultConfig: sarifRuleConfig{
				Level: severityToSARIF(v.Severity),
			},
			Properties: sarifProperties{
				Tags: []string{"security", "tls", categoryFromID(v.ID)},
			},
		})
	}

	// Add quantum risk rule if applicable.
	//
	// Assessed is checked first because an assessment that did not run leaves a
	// zero-valued struct, and 0 < 50. SARIF is the format a CI system acts on,
	// so --skip-quantum used to publish a QUANTUM_VULNERABLE finding, with an
	// empty message body, about a measurement that never happened.
	if result.QuantumRisk.Assessed && result.QuantumRisk.Score < 50 {
		rules = append(rules, sarifRule{
			ID:               "QUANTUM_VULNERABLE",
			Name:             "Quantum Vulnerability",
			ShortDescription: sarifMessage{Text: "Configuration vulnerable to quantum attacks"},
			FullDescription:  sarifMessage{Text: "The TLS configuration uses cryptographic algorithms that will be broken by quantum computers."},
			Help:             sarifMessage{Text: "Enable hybrid post-quantum key exchange (X25519MLKEM768) and plan migration to PQC certificates."},
			DefaultConfig: sarifRuleConfig{
				Level: "warning",
			},
			Properties: sarifProperties{
				Tags: []string{"security", "quantum", "pqc"},
			},
		})
	}

	return rules
}

func (r *SARIFReporter) buildResults(result *types.ScanResult) []sarifResult {
	var results []sarifResult

	// Add vulnerability results
	for _, v := range result.Vulnerabilities {
		results = append(results, sarifResult{
			RuleID:  v.ID,
			Level:   severityToSARIF(v.Severity),
			Message: sarifMessage{Text: v.Description},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: result.Target,
						},
					},
				},
			},
		})
	}

	// Add quantum risk result. Guarded for the same reason as the rule above:
	// a rule with no result and a result with no rule are both invalid SARIF.
	if result.QuantumRisk.Assessed && result.QuantumRisk.Score < 50 {
		details := "Quantum Risk Assessment:\n"
		for _, d := range result.QuantumRisk.Details {
			details += "- " + d + "\n"
		}
		details += "\nRecommended action: " + result.QuantumRisk.TimeToAction

		results = append(results, sarifResult{
			RuleID:  "QUANTUM_VULNERABLE",
			Level:   "warning",
			Message: sarifMessage{Text: details},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: result.Target,
						},
					},
				},
			},
		})
	}

	return results
}

func severityToSARIF(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

func categoryFromID(id string) string {
	switch {
	case len(id) >= 3 && id[:3] == "TLS":
		return "protocol"
	case len(id) >= 4 && id[:4] == "CERT":
		return "certificate"
	case len(id) >= 6 && id[:6] == "CIPHER":
		return "cipher"
	default:
		return "configuration"
	}
}
