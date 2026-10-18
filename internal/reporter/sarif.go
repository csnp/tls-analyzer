package reporter

import (
	"fmt"
	"io"
	"strings"

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
	Tool        sarifTool           `json:"tool"`
	Invocations []sarifInvocation   `json:"invocations,omitempty"`
	Results     []sarifResult       `json:"results"`
	Properties  *sarifRunProperties `json:"properties,omitempty"`
}

// sarifRunProperties is the run's property bag. It carries the policy verdict,
// which is a statement about the whole run rather than about one result: a
// policy whose only rule was skipped has no result to attach it to, and was
// indistinguishable from a pass.
type sarifRunProperties struct {
	Policy *sarifPolicyVerdict `json:"policy,omitempty"`
}

type sarifPolicyVerdict struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Compliant bool   `json:"compliant"`
	Complete  bool   `json:"complete"`
	Score     int    `json:"score"`
	// Always a list, so a consumer reading it never meets null.
	SkippedRules []string `json:"skippedRules"`
	Scope        string   `json:"scope,omitempty"`
}

// sarifInvocation carries whether the scan actually ran.
//
// SARIF has one field for this and it was never emitted, so a target that was
// never reached produced a valid run with no results, which is the same document
// a clean host produces. A CI system reading SARIF cannot tell "nothing is
// wrong" from "nothing was measured" without it, and this tool's own batch mode
// is what generates those results for a whole file of hosts.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
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
	// A target that produced no measurements produces no rules and no results,
	// and says so in the one field SARIF has for it. Without this the document is
	// byte-for-byte the shape a clean host produces, so a gate reading SARIF
	// passed a host it never connected to.
	unreached := targetWasNeverReached(result)

	// Both always arrays, never null. `"results": null` and `"rules": null` are
	// not empty lists, they are the absence of a list, and the SARIF 2.1.0 schema
	// rejects both: validated against the published schema, an unreached host
	// produced `None is not of type 'array'` at runs[0].tool.driver.rules. The
	// results half was already emitted as null before this release whenever a
	// host had no findings at all.
	rules := []sarifRule{}
	results := []sarifResult{}
	invocation := sarifInvocation{ExecutionSuccessful: true}
	var properties *sarifRunProperties

	if unreached {
		invocation = sarifInvocation{
			ExecutionSuccessful: false,
			ToolExecutionNotifications: []sarifNotification{{
				Level: "error",
				Message: sarifMessage{Text: "The target was not scanned, so nothing was " +
					"measured and no finding here describes it: " + result.Error},
			}},
		}
	} else {
		rules = append(rules, r.buildRules(result)...)
		results = append(results, r.buildResults(result)...)

		// The policy verdict. The exit code already carried it, and the
		// document a CI system uploads beside that exit code did not: no result
		// named the violation and nothing named the policy.
		if pr := result.PolicyResult; pr != nil {
			rules = append(rules, policyRules(pr)...)
			results = append(results, policyResults(pr, result.Target)...)
			properties = &sarifRunProperties{Policy: &sarifPolicyVerdict{
				Name:         pr.PolicyName,
				Status:       policyStatusWord(pr),
				Compliant:    pr.Compliant,
				Complete:     pr.Complete,
				Score:        pr.Score,
				SkippedRules: skippedRuleNames(pr),
				Scope:        pr.Scope,
			}}

			// A skipped rule produces no result, so an evaluation whose only
			// rule was skipped would otherwise be the document a pass produces.
			if !pr.Complete {
				invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications,
					sarifNotification{
						Level:   "warning",
						Message: sarifMessage{Text: policyNotEstablishedText(pr)},
					})
			}
		}
	}

	// The raw.githubusercontent.com path of the OASIS repository that this used
	// to name answers 404, so a validator following $schema found nothing.
	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "qramm-tls-analyzer",
						Version:         result.ScannerVersion,
						SemanticVersion: result.ScannerVersion,
						InformationURI:  "https://github.com/csnp/qramm-tls-analyzer",
						Rules:           rules,
					},
				},
				Invocations: []sarifInvocation{invocation},
				Results:     results,
				Properties:  properties,
			},
		},
	}

	return WriteJSON(w, report, "  ")
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

// policyRuleID is the SARIF rule id of a policy rule. The prefix keeps policy
// rules apart from the scanner's own finding ids, so a consumer can select or
// suppress them as a group.
func policyRuleID(rule string) string {
	return "POLICY." + rule
}

// policyFinding is one policy finding as SARIF reports it.
type policyFinding struct {
	violation types.PolicyViolation
	level     string
	kind      string
}

// policyFindings lists every policy finding with the level it is reported at.
//
// A violation is reported at its own severity. A warning is reported as a note
// whatever its severity: the analyzer makes a rule a warning precisely so that
// it cannot fail anything, such as a PQC certificate no public CA issues yet,
// and an error level would let a code-scanning gate fail on it anyway.
func policyFindings(pr *types.PolicyResult) []policyFinding {
	findings := make([]policyFinding, 0, len(pr.Violations)+len(pr.Warnings))
	for _, v := range pr.Violations {
		findings = append(findings, policyFinding{v, severityToSARIF(v.Severity), "violation"})
	}
	for _, v := range pr.Warnings {
		findings = append(findings, policyFinding{v, "note", "warning"})
	}
	return findings
}

// policyRules declares one rule per policy rule that produced a finding, with
// the finding's fix as the rule's help.
func policyRules(pr *types.PolicyResult) []sarifRule {
	var rules []sarifRule
	seen := make(map[string]bool)
	for _, f := range policyFindings(pr) {
		id := policyRuleID(f.violation.Rule)
		if seen[id] {
			continue
		}
		seen[id] = true

		rules = append(rules, sarifRule{
			ID:               id,
			Name:             f.violation.Rule,
			ShortDescription: sarifMessage{Text: f.violation.Description},
			FullDescription: sarifMessage{Text: "Policy rule " + f.violation.Rule +
				", from the policy applied to this scan."},
			Help: sarifMessage{Text: f.violation.Remediation},
			DefaultConfig: sarifRuleConfig{
				Level: f.level,
			},
			Properties: sarifProperties{
				Tags: []string{"security", "tls", "policy"},
			},
		})
	}
	return rules
}

// policyResults reports each policy finding as a result.
func policyResults(pr *types.PolicyResult, target string) []sarifResult {
	var results []sarifResult
	for _, f := range policyFindings(pr) {
		results = append(results, sarifResult{
			RuleID:  policyRuleID(f.violation.Rule),
			Level:   f.level,
			Message: sarifMessage{Text: policyFindingText(pr, f)},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: target,
						},
					},
				},
			},
		})
	}
	return results
}

// policyFindingText is the result message: what was found, what the policy
// asked for, what the scan saw, and the fix, as the text report prints them.
func policyFindingText(pr *types.PolicyResult, f policyFinding) string {
	v := f.violation
	var b strings.Builder
	b.WriteString(v.Description)
	fmt.Fprintf(&b, "\nPolicy: %s (rule %s, %s %s)", pr.PolicyName, v.Rule, v.Severity, f.kind)
	if v.Expected != "" {
		b.WriteString("\nExpected: " + v.Expected)
	}
	if v.Actual != "" {
		b.WriteString("\nActual: " + v.Actual)
	}
	if v.Remediation != "" {
		b.WriteString("\nFix: " + v.Remediation)
	}
	return b.String()
}

// policyNotEstablishedText is the notification an incomplete evaluation adds
// to the invocation, naming each rule that was not evaluated and why.
func policyNotEstablishedText(pr *types.PolicyResult) string {
	text := "The policy " + pr.PolicyName + " was not fully evaluated against this " +
		"target, so compliance with it is not established."
	if skipped := describeSkippedRules(pr); skipped != "" {
		return text + " Rules not evaluated: " + skipped
	}
	return text + " The evaluation is not marked complete."
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
