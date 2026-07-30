package analyzer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
	"gopkg.in/yaml.v3"
)

// PolicyEvaluator evaluates scan results against policies.
type PolicyEvaluator struct {
	policies map[string]types.Policy
}

// NewPolicyEvaluator creates a new policy evaluator with built-in policies.
func NewPolicyEvaluator() *PolicyEvaluator {
	return &PolicyEvaluator{
		policies: types.DefaultPolicies,
	}
}

// LoadPolicy loads a policy from a YAML file.
//
// Every failure here is an error rather than a default, because the caller is
// about to render a compliance verdict from whatever this returns. An empty
// file used to produce {"policyName": "", "compliant": true, "score": 100} and
// exit 0 against a host that --policy strict failed with 35 HIGH violations at
// the same moment, and a file whose keys were all misspelled produced the same
// green pass. A gate that passes on an input it did not understand is the worst
// direction available to it.
func (e *PolicyEvaluator) LoadPolicy(path string) (*types.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	policy, err := e.decodePolicy(data, types.Policy{})
	if err != nil {
		return nil, err
	}

	// extends overlays this file onto a built-in policy. The overlay is applied
	// by decoding the same document a second time on top of a copy of the base,
	// so every key the file sets wins and every key it omits is inherited.
	//
	// The previous merge copied a hand-picked eight of the rule fields and
	// silently dropped the rest, so a file extending "modern" to ban AES, raise
	// the minimum RSA key size or forbid a signature algorithm was accepted,
	// reported under its own name, and evaluated against the base policy's
	// looser rules. Decoding onto the base cannot drift as rule fields are
	// added, which is how that gap opened.
	if policy.Extends != "" {
		base, ok := e.policies[policy.Extends]
		if !ok {
			return nil, fmt.Errorf(
				"policy %q extends %q, which is not a built-in policy. Available: %s",
				policy.Name, policy.Extends, strings.Join(e.ListPolicies(), ", "))
		}
		policy, err = e.decodePolicy(data, base)
		if err != nil {
			return nil, err
		}
	}

	if err := validatePolicy(&policy, path); err != nil {
		return nil, err
	}

	return &policy, nil
}

// decodePolicy decodes the document onto the given starting policy, refusing
// any key the schema does not define.
//
// Unknown keys were previously ignored, so three plausible hand-written
// spellings of the same policy (flat camelCase, nested by prefix, flat
// snake_case) each produced a compliant verdict with no rule having been
// applied, and the real schema was only discoverable by forcing type errors
// that leak Go type names.
func (e *PolicyEvaluator) decodePolicy(data []byte, onto types.Policy) (types.Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&onto); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty document decodes without error and leaves the target
			// untouched, which is how an empty file became a passing policy.
			return onto, fmt.Errorf("the policy file contains no YAML document")
		}
		return onto, fmt.Errorf("failed to parse policy YAML: %s\n"+
			"Run 'tlsanalyzer print-policy modern' to see a valid policy to start from",
			schemaPathsInErrors.Replace(err.Error()))
	}

	return onto, nil
}

// schemaPathsInErrors rewrites the Go type names the YAML decoder reports into
// the YAML paths a user actually writes. Which struct a key belongs to is an
// implementation detail, and naming it in an error made the tool's own
// diagnostics the place where the schema leaked: the fresh-user pass on this
// tool found the real shape of a policy only by provoking type errors.
//
// PolicyRules is listed before Policy because a replacer resolves overlapping
// patterns in argument order.
var schemaPathsInErrors = strings.NewReplacer(
	"type types.ProtocolRules", "'rules.protocol'",
	"type types.CipherRules", "'rules.cipher'",
	"type types.CertificateRules", "'rules.certificate'",
	"type types.QuantumRules", "'rules.quantum'",
	"type types.ScoringWeights", "'weights'",
	"type types.PolicyRules", "'rules'",
	"type types.Policy", "the top level of a policy file",
)

// validatePolicy refuses a policy that cannot produce a meaningful verdict.
func validatePolicy(policy *types.Policy, path string) error {
	if strings.TrimSpace(policy.Name) == "" {
		return fmt.Errorf("policy file %s sets no 'name'. A report has to be able to say which "+
			"policy it applied, and an unnamed policy was reported as an empty policy name "+
			"beside a compliant verdict", path)
	}

	if policy.Rules.IsEmpty() {
		return fmt.Errorf("policy %q in %s defines no rules, so nothing can fail it and a "+
			"compliant verdict from it would mean nothing. Add at least one rule, or use "+
			"'extends' to inherit one of the built-in policies", policy.Name, path)
	}

	return nil
}

// GetPolicy returns a built-in policy by name.
func (e *PolicyEvaluator) GetPolicy(name string) (*types.Policy, bool) {
	p, ok := e.policies[name]
	return &p, ok
}

// ListPolicies returns all available policy names.
func (e *PolicyEvaluator) ListPolicies() []string {
	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	return names
}

// PolicyEvaluationScope states what a policy verdict covers.
//
// A policy evaluation of a CNSA 2.0 target year and the CNSA 2.0 timeline
// section previously printed opposite verdicts for the same deadline with
// nothing to distinguish them. This evaluation is the stricter of the two: every
// protocol and cipher suite the server still accepts must satisfy the rules, so
// one weak suite that remains on offer is a violation even when a compliant
// suite is also available and is the one normally negotiated.
const PolicyEvaluationScope = "every protocol and cipher suite this server " +
	"accepts is evaluated, so a weak suite that is still offered is a violation " +
	"even when a compliant suite is available and preferred. The CNSA 2.0 " +
	"timeline section answers the narrower question of whether the required " +
	"algorithms are available at all, so the two can differ on the same deadline."

// Evaluate evaluates a scan result against a policy.
func (e *PolicyEvaluator) Evaluate(result *types.ScanResult, policy *types.Policy) *types.PolicyResult {
	pr := &types.PolicyResult{
		PolicyName: policy.Name,
		Compliant:  true,
		Scope:      PolicyEvaluationScope,
		Violations: make([]types.PolicyViolation, 0),
		Warnings:   make([]types.PolicyViolation, 0),
	}

	// Evaluate protocol rules
	e.evaluateProtocol(result, &policy.Rules.Protocol, pr)

	// Evaluate cipher rules
	e.evaluateCipher(result, &policy.Rules.Cipher, pr)

	// Evaluate certificate rules
	e.evaluateCertificate(result, &policy.Rules.Certificate, pr)

	// Evaluate quantum rules
	e.evaluateQuantum(result, &policy.Rules.Quantum, pr)

	// Set compliant flag
	pr.Compliant = len(pr.Violations) == 0

	// A verdict that skipped rules is about a smaller set than the policy
	// defines, so it is not comparable with a full evaluation in either
	// direction.
	pr.Complete = len(pr.SkippedRules) == 0

	// Calculate score
	pr.Score = e.calculateScore(pr, policy)

	return pr
}

func (e *PolicyEvaluator) evaluateProtocol(result *types.ScanResult, rules *types.ProtocolRules, pr *types.PolicyResult) {
	// Check minimum version
	if rules.MinVersion != "" {
		meetsMin := false
		for _, p := range result.Protocols {
			if p.Supported && e.versionAtLeast(p.Version, rules.MinVersion) {
				meetsMin = true
				break
			}
		}
		if !meetsMin {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "protocol.minVersion",
				Severity:    types.SeverityHigh,
				Description: "Minimum TLS version not met",
				Expected:    rules.MinVersion + " or higher",
				Actual:      e.getHighestProtocol(result.Protocols),
				Remediation: "Enable " + rules.MinVersion,
			})
		}
	}

	// Check banned versions
	for _, banned := range rules.BannedVersions {
		for _, p := range result.Protocols {
			if p.Supported && p.Version == banned {
				pr.Violations = append(pr.Violations, types.PolicyViolation{
					Rule:        "protocol.bannedVersions",
					Severity:    types.SeverityHigh,
					Description: "Banned protocol version enabled",
					Expected:    banned + " disabled",
					Actual:      banned + " enabled",
					Remediation: "Disable " + banned,
				})
			}
		}
	}

	// Check required versions
	for _, required := range rules.RequiredVersions {
		found := false
		for _, p := range result.Protocols {
			if p.Supported && p.Version == required {
				found = true
				break
			}
		}
		if !found {
			pr.Warnings = append(pr.Warnings, types.PolicyViolation{
				Rule:        "protocol.requiredVersions",
				Severity:    types.SeverityMedium,
				Description: "Required protocol version not supported",
				Expected:    required + " enabled",
				Actual:      required + " not detected",
				Remediation: "Enable " + required,
			})
		}
	}
}

func (e *PolicyEvaluator) evaluateCipher(result *types.ScanResult, rules *types.CipherRules, pr *types.PolicyResult) {
	for _, cs := range result.CipherSuites {
		// Check minimum key size
		if rules.MinKeySize > 0 && cs.Bits < rules.MinKeySize {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "cipher.minKeySize",
				Severity:    types.SeverityHigh,
				Description: "Cipher suite key size below minimum",
				Expected:    fmt.Sprintf(">= %d bits", rules.MinKeySize),
				Actual:      fmt.Sprintf("%d bits (%s)", cs.Bits, cs.Name),
				Remediation: fmt.Sprintf("Remove %s, use cipher with >= %d-bit key", cs.Name, rules.MinKeySize),
			})
		}

		// Check forward secrecy
		if rules.RequireForwardSecrecy && !cs.ForwardSecrecy {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "cipher.requireForwardSecrecy",
				Severity:    types.SeverityHigh,
				Description: "Cipher suite lacks forward secrecy",
				Expected:    "ECDHE or DHE key exchange",
				Actual:      cs.KeyExchange + " key exchange",
				Remediation: fmt.Sprintf("Remove %s, use ECDHE-based cipher", cs.Name),
			})
		}

		// Check banned algorithms
		for _, banned := range rules.BannedAlgorithms {
			if strings.Contains(cs.Name, banned) || cs.Encryption == banned || cs.MAC == banned {
				pr.Violations = append(pr.Violations, types.PolicyViolation{
					Rule:        "cipher.bannedAlgorithms",
					Severity:    types.SeverityHigh,
					Description: "Banned algorithm detected in cipher suite",
					Expected:    banned + " not used",
					Actual:      cs.Name + " contains " + banned,
					Remediation: fmt.Sprintf("Remove %s from cipher suite configuration", cs.Name),
				})
			}
		}

		// Check banned cipher suites
		for _, banned := range rules.BannedCipherSuites {
			if cs.Name == banned {
				pr.Violations = append(pr.Violations, types.PolicyViolation{
					Rule:        "cipher.bannedCipherSuites",
					Severity:    types.SeverityHigh,
					Description: "Banned cipher suite enabled",
					Expected:    banned + " disabled",
					Actual:      banned + " enabled",
					Remediation: "Remove " + banned + " from cipher suite list",
				})
			}
		}
	}

	// Check required key exchange (at least one must be present)
	if len(rules.RequiredKeyExchange) > 0 {
		found := false
		for _, ke := range result.KeyExchanges {
			for _, required := range rules.RequiredKeyExchange {
				if ke.Name == required || ke.PQCAlgorithm == required {
					found = true
					break
				}
			}
		}
		if !found {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "cipher.requiredKeyExchange",
				Severity:    types.SeverityCritical,
				Description: "Required key exchange algorithm not found",
				Expected:    strings.Join(rules.RequiredKeyExchange, " or "),
				Actual:      "None of the required algorithms detected",
				Remediation: "Enable hybrid PQC key exchange (e.g., X25519MLKEM768)",
			})
		}
	}
}

func (e *PolicyEvaluator) evaluateCertificate(result *types.ScanResult, rules *types.CertificateRules, pr *types.PolicyResult) {
	if result.Certificate == nil {
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate",
			Severity:    types.SeverityCritical,
			Description: "No certificate found",
			Expected:    "Valid certificate",
			Actual:      "Certificate not detected",
			Remediation: "Install a valid TLS certificate",
		})
		return
	}

	cert := result.Certificate

	// Check validity
	if cert.Expired {
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate.validity",
			Severity:    types.SeverityCritical,
			Description: "Certificate has expired",
			Expected:    "Valid certificate",
			Actual:      "Certificate expired",
			Remediation: "Renew the certificate immediately",
		})
	} else if rules.MinValidityDays > 0 && cert.DaysUntilExpiry < rules.MinValidityDays {
		pr.Warnings = append(pr.Warnings, types.PolicyViolation{
			Rule:        "certificate.minValidityDays",
			Severity:    types.SeverityMedium,
			Description: "Certificate expiring soon",
			Expected:    fmt.Sprintf(">= %d days until expiry", rules.MinValidityDays),
			Actual:      fmt.Sprintf("%d days until expiry", cert.DaysUntilExpiry),
			Remediation: "Plan certificate renewal",
		})
	}

	// Check RSA key size
	if cert.PublicKeyAlgorithm == "RSA" && rules.MinRSAKeySize > 0 {
		if cert.PublicKeyBits < rules.MinRSAKeySize {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "certificate.minRsaKeySize",
				Severity:    types.SeverityHigh,
				Description: "RSA key size below minimum",
				Expected:    fmt.Sprintf(">= %d bits", rules.MinRSAKeySize),
				Actual:      fmt.Sprintf("%d bits", cert.PublicKeyBits),
				Remediation: fmt.Sprintf("Reissue certificate with >= %d-bit RSA key", rules.MinRSAKeySize),
			})
		}
	}

	// Check ECC key size
	if cert.PublicKeyAlgorithm == "ECDSA" && rules.MinECCKeySize > 0 {
		if cert.PublicKeyBits < rules.MinECCKeySize {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "certificate.minEccKeySize",
				Severity:    types.SeverityHigh,
				Description: "ECC key size below minimum",
				Expected:    fmt.Sprintf(">= %d bits", rules.MinECCKeySize),
				Actual:      fmt.Sprintf("%d bits", cert.PublicKeyBits),
				Remediation: fmt.Sprintf("Reissue certificate with >= P-%d curve", rules.MinECCKeySize),
			})
		}
	}

	// Check banned signature algorithms
	for _, banned := range rules.BannedSignatureAlgorithms {
		if strings.Contains(cert.SignatureAlgorithm, banned) {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "certificate.bannedSignatureAlgorithms",
				Severity:    types.SeverityHigh,
				Description: "Banned signature algorithm in certificate",
				Expected:    banned + " not used",
				Actual:      cert.SignatureAlgorithm,
				Remediation: "Reissue certificate with SHA-256 or stronger signature",
			})
		}
	}

	// Check self-signed
	if !rules.AllowSelfSigned && cert.IsSelfSigned && !cert.IsCA {
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate.allowSelfSigned",
			Severity:    types.SeverityMedium,
			Description: "Self-signed certificate not allowed",
			Expected:    "Certificate from trusted CA",
			Actual:      "Self-signed certificate",
			Remediation: "Obtain certificate from a trusted Certificate Authority",
		})
	}
}

func (e *PolicyEvaluator) evaluateQuantum(result *types.ScanResult, rules *types.QuantumRules, pr *types.PolicyResult) {
	// Check hybrid key exchange requirement
	if rules.RequireHybridKeyExchange {
		hasHybridPQC := false
		for _, ke := range result.KeyExchanges {
			if ke.Type == "hybrid" || ke.Type == "pqc" {
				hasHybridPQC = true
				break
			}
		}
		if !hasHybridPQC {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "quantum.requireHybridKeyExchange",
				Severity:    types.SeverityCritical,
				Description: "Hybrid PQC key exchange required but not detected",
				Expected:    "X25519MLKEM768 or similar hybrid",
				Actual:      "Classical key exchange only",
				Remediation: "Enable hybrid post-quantum key exchange on your server",
			})
		}
	}

	// Check minimum quantum score.
	//
	// The score is the one policy input that a scan can decline to measure, and
	// an unmeasured assessment is a zero-valued struct. Reading that zero as a
	// measurement raised "Expected: >= 90 | Actual: 0" against a host whose
	// full scan reports 64, in the same report that said the assessment had not
	// run, while the scan-coverage note claimed the assessment was excluded.
	if rules.MinQuantumScore > 0 {
		switch {
		case !result.QuantumRisk.Assessed:
			pr.SkippedRules = append(pr.SkippedRules, types.SkippedPolicyRule{
				Rule: "quantum.minQuantumScore",
				Reason: fmt.Sprintf(
					"the quantum risk assessment did not run in this scan, so there is no "+
						"score to compare against the minimum of %d. Re-run without "+
						"--skip-quantum to evaluate this rule", rules.MinQuantumScore),
			})
		case result.QuantumRisk.Score < rules.MinQuantumScore:
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "quantum.minQuantumScore",
				Severity:    types.SeverityHigh,
				Description: "Quantum readiness score below minimum",
				Expected:    fmt.Sprintf(">= %d", rules.MinQuantumScore),
				Actual:      fmt.Sprintf("%d", result.QuantumRisk.Score),
				Remediation: "Enable PQC key exchange to improve quantum readiness",
			})
		}
	}

	// Check PQC certificate requirement
	if rules.RequirePQCCertificates {
		if result.Certificate == nil || !result.Certificate.QuantumSafe {
			pr.Warnings = append(pr.Warnings, types.PolicyViolation{
				Rule:        "quantum.requirePqcCertificates",
				Severity:    types.SeverityMedium,
				Description: "PQC certificate required (future requirement)",
				Expected:    "ML-DSA or SLH-DSA certificate",
				Actual:      "Classical certificate",
				Remediation: "Plan migration to PQC certificates when available from CAs",
			})
		}
	}
}

func (e *PolicyEvaluator) calculateScore(pr *types.PolicyResult, policy *types.Policy) int {
	// Start with 100, deduct for violations and warnings
	score := 100

	for _, v := range pr.Violations {
		switch v.Severity {
		case types.SeverityCritical:
			score -= 30
		case types.SeverityHigh:
			score -= 15
		case types.SeverityMedium:
			score -= 5
		}
	}

	for _, w := range pr.Warnings {
		switch w.Severity {
		case types.SeverityHigh:
			score -= 5
		case types.SeverityMedium:
			score -= 2
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (e *PolicyEvaluator) versionAtLeast(version, minVersion string) bool {
	versionOrder := map[string]int{
		"SSL 3.0": 0,
		"TLS 1.0": 1,
		"TLS 1.1": 2,
		"TLS 1.2": 3,
		"TLS 1.3": 4,
	}

	return versionOrder[version] >= versionOrder[minVersion]
}

func (e *PolicyEvaluator) getHighestProtocol(protocols []types.Protocol) string {
	highest := "None"
	highestOrder := -1

	versionOrder := map[string]int{
		"SSL 3.0": 0,
		"TLS 1.0": 1,
		"TLS 1.1": 2,
		"TLS 1.2": 3,
		"TLS 1.3": 4,
	}

	for _, p := range protocols {
		if p.Supported {
			if order, ok := versionOrder[p.Version]; ok && order > highestOrder {
				highestOrder = order
				highest = p.Version
			}
		}
	}

	return highest
}
