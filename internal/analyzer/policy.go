package analyzer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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

	if err := validatePolicy(&policy, path, declaresARule(data) || policy.Extends != ""); err != nil {
		return nil, err
	}

	return &policy, nil
}

// declaresARule reports whether the document actually writes a rule, read from
// the YAML rather than inferred from the decoded struct.
//
// Presence cannot be recovered from the decoded value, because Go cannot tell an
// unset field from one set to its zero value. That inversion refused
// `allowSelfSigned: false`, the restrictive setting every built-in policy uses,
// as "defines no rules", while accepting `allowSelfSigned: true`. It also let
// three things through that mean nothing: a rules block whose only key is
// `cnsa2TargetYear`, which is a label rather than a constraint; an empty list;
// and a list whose only item is blank. Each loaded and reported COMPLIANT
// 100/100 against a host that satisfied nothing.
func declaresARule(data []byte) bool {
	var doc struct {
		Rules map[string]map[string]yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// A document that does not parse is refused elsewhere with a better
		// message; do not let this check turn that into "defines no rules".
		return true
	}

	for _, section := range doc.Rules {
		for key, node := range section {
			// A label enforces nothing on its own, so a policy consisting only of
			// one is as empty as a policy with no rules at all.
			if key == "cnsa2TargetYear" {
				continue
			}
			if node.Kind == yaml.SequenceNode {
				for _, item := range node.Content {
					if item.Kind == yaml.ScalarNode && strings.TrimSpace(item.Value) != "" &&
						item.Tag != "!!null" {
						return true
					}
				}
				continue
			}
			if node.Kind == yaml.ScalarNode && node.Tag != "!!null" {
				return true
			}
		}
	}
	return false
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

// normalizeAlgorithmName reduces an algorithm, cipher suite or signature name to
// its letters and digits, lowercased, so that the separators different sources
// use do not decide whether a rule applies.
//
// The names reach this package from sources that disagree on both case and
// punctuation: the scanner's own tables, the x509 package's signature algorithm
// strings, and a policy file a human typed. "SHA-256" is the spelling NIST uses
// and the spelling this tool's own remediation text teaches ("Reissue
// certificate with SHA-256 or stronger signature"), while the certificate field
// reads "SHA256-RSA". Matching those literally meant the rule silently did
// nothing, so banning SHA-256 reported COMPLIANT against a SHA256-RSA
// certificate. Unlike protocol versions these names are not a closed set, so
// they cannot be refused at load time: banning an algorithm the server does not
// use is a legitimate rule that simply does not fire.
func normalizeAlgorithmName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// containsFold reports whether substr occurs in s once both are normalized.
func containsFold(s, substr string) bool {
	return strings.Contains(normalizeAlgorithmName(s), normalizeAlgorithmName(substr))
}

// equalFoldAlgorithm reports whether two algorithm or suite names are the same
// once both are normalized.
func equalFoldAlgorithm(a, b string) bool {
	return normalizeAlgorithmName(a) == normalizeAlgorithmName(b)
}

// protocolVersionOrder ranks the protocol versions the scanner reports. It is
// the single definition of that closed set: comparison, the "highest supported"
// summary and policy value validation all read it, so a version added here
// cannot be understood by one of them and not the others.
var protocolVersionOrder = map[string]int{
	"SSL 3.0": 0,
	"TLS 1.0": 1,
	"TLS 1.1": 2,
	"TLS 1.2": 3,
	"TLS 1.3": 4,
}

// unprobeableProtocolVersions are version names this tool understands but cannot
// test for. Go's TLS stack will not offer SSL 2.0 or SSL 3.0 at all, so the
// scanner never reports them, and a policy banning one cannot be evaluated: the
// absence of a result is not evidence the server has it disabled. They are
// accepted in a policy file, because banning them is a legitimate thing to
// write, and each use raises a warning saying the rule was not tested.
var unprobeableProtocolVersions = map[string]string{
	"SSL 2.0": "Go's TLS stack cannot offer SSL 2.0, so this scanner cannot tell " +
		"whether the server accepts it",
	"SSL 3.0": "Go's TLS stack cannot offer SSL 3.0, so this scanner cannot tell " +
		"whether the server accepts it",
}

// knownProtocolVersionNames is every version name a policy may use: the ones the
// scanner probes, plus the ones it understands but cannot measure. Validation
// reads this, so a legitimate "ban SSL 2.0" is accepted while "TLSv1.2" is not.
func knownProtocolVersionNames() map[string]bool {
	names := make(map[string]bool, len(protocolVersionOrder)+len(unprobeableProtocolVersions))
	for name := range protocolVersionOrder {
		names[name] = true
	}
	for name := range unprobeableProtocolVersions {
		names[name] = true
	}
	return names
}

// knownProtocolVersions lists the accepted values in rank order, for error
// messages. Built from the same sources so they cannot drift apart.
func knownProtocolVersions() string {
	ordered := make([]string, len(protocolVersionOrder))
	for name, rank := range protocolVersionOrder {
		ordered[rank] = name
	}
	extra := make([]string, 0, len(unprobeableProtocolVersions))
	for name := range unprobeableProtocolVersions {
		if _, ranked := protocolVersionOrder[name]; !ranked {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return strings.Join(append(extra, ordered...), ", ")
}

// closestProtocolVersion picks the accepted spelling nearest to what the user
// wrote, so the error can contrast the two. Comparing the rejected value against
// a hardcoded example produced `"TLSv1.2" and "TLSv1.2" are not the same value`
// for the exact typo this check exists to catch.
func closestProtocolVersion(value string) string {
	normalized := normalizeAlgorithmName(value)
	best, bestScore := "TLS 1.2", -1
	names := make([]string, 0, len(protocolVersionOrder)+len(unprobeableProtocolVersions))
	for name := range knownProtocolVersionNames() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		candidate := normalizeAlgorithmName(name)
		score := 0
		for i := 0; i < len(candidate) && i < len(normalized); i++ {
			if candidate[len(candidate)-1-i] == normalized[len(normalized)-1-i] {
				score++
				continue
			}
			break
		}
		if score > bestScore {
			best, bestScore = name, score
		}
	}
	return best
}

// validateProtocolVersionValues refuses a protocol version this tool does not
// recognise.
//
// Unknown KEYS have been refused since 0.4.0, but unknown VALUES were dropped
// in silence, which is the same fail-open one level down: `bannedVersions:
// ["TLSv1.2"]` matched no scanned protocol, so the rule vanished and the report
// read COMPLIANT 100/100 with exit 0 against a server that does enable TLS 1.2.
// `minVersion` was worse than silent, because an unknown key in a Go map reads
// back as 0, which is the rank of SSL 3.0, so `minVersion: garbage` was
// satisfied by any protocol at all. A one-character difference the user cannot
// see must not decide whether a compliance gate passes.
func validateProtocolVersionValues(rules *types.ProtocolRules) error {
	fields := []struct {
		name   string
		values []string
	}{
		{"minVersion", nil},
		{"maxVersion", nil},
		{"bannedVersions", rules.BannedVersions},
		{"requiredVersions", rules.RequiredVersions},
	}
	if rules.MinVersion != "" {
		fields[0].values = []string{rules.MinVersion}
	}
	if rules.MaxVersion != "" {
		fields[1].values = []string{rules.MaxVersion}
	}

	known := knownProtocolVersionNames()
	for _, field := range fields {
		for _, value := range field.values {
			if !known[value] {
				return fmt.Errorf("rules.protocol.%s has the value %q, which is not a protocol "+
					"version this tool recognises. Accepted values are: %s. Spelling and spacing "+
					"both matter, so %q is not the same value as %q, and an unrecognised one "+
					"would silently match nothing and leave the rule out of the verdict",
					field.name, value, knownProtocolVersions(), value, closestProtocolVersion(value))
			}
		}
	}
	return nil
}

// validatePolicy refuses a policy that cannot produce a meaningful verdict.
func validatePolicy(policy *types.Policy, path string, declaresRule bool) error {
	if strings.TrimSpace(policy.Name) == "" {
		return fmt.Errorf("policy file %s sets no 'name'. A report has to be able to say which "+
			"policy it applied, and an unnamed policy was reported as an empty policy name "+
			"beside a compliant verdict", path)
	}

	if !declaresRule {
		return fmt.Errorf("policy %q in %s defines no rules, so nothing can fail it and a "+
			"compliant verdict from it would mean nothing. Add at least one rule, or use "+
			"'extends' to inherit one of the built-in policies", policy.Name, path)
	}

	if err := validateProtocolVersionValues(&policy.Rules.Protocol); err != nil {
		return fmt.Errorf("policy %q in %s: %w", policy.Name, path, err)
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
	// Check minimum version.
	//
	// This asks two questions, and used to ask only the first: can the server
	// reach the minimum, and does it still accept anything below it. Asking only
	// the first made minVersion a capability check, so `minVersion: TLS 1.3`
	// reported COMPLIANT 100/100 with exit 0 against a server that also accepted
	// TLS 1.0, in the same report that listed TLS 1.0 as supported and raised a
	// HIGH finding for it. Two built-in CNSA 2.0 policies set a minVersion and no
	// bannedVersions, so both gave a clean protocol verdict to a TLS 1.0 server.
	//
	// The floor reading is what the rule's name says, what the Scope paragraph
	// printed beside the verdict promises, and what every server configuration
	// directive of the same name means. It is also the fail-closed direction: a
	// user who meant "the server must be capable of TLS 1.3" gets a violation
	// they can see and remove, while a user who meant "nothing below TLS 1.3"
	// previously got silence.
	if rules.MinVersion != "" {
		minRank, minKnown := protocolVersionOrder[rules.MinVersion]

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

		for _, p := range result.Protocols {
			rank, known := protocolVersionOrder[p.Version]
			if p.Supported && known && minKnown && rank < minRank {
				pr.Violations = append(pr.Violations, types.PolicyViolation{
					Rule:        "protocol.minVersion",
					Severity:    types.SeverityHigh,
					Description: "Protocol version below the minimum is still accepted",
					Expected:    "nothing below " + rules.MinVersion + " accepted",
					Actual:      p.Version + " still enabled",
					Remediation: "Disable " + p.Version,
				})
			}
		}
	}

	// Check banned versions
	for _, banned := range rules.BannedVersions {
		// A version the scanner cannot offer is a question it cannot answer. The
		// built-in "modern" policy bans SSL 3.0, and that ban has never been
		// tested against anything: the probe list is TLS 1.0 to TLS 1.3, so the
		// version simply never appears in a result and the rule passed on every
		// host. Say so rather than counting silence as compliance.
		if reason, cannotProbe := unprobeableProtocolVersions[banned]; cannotProbe {
			pr.SkippedRules = append(pr.SkippedRules, types.SkippedPolicyRule{
				Rule: "protocol.bannedVersions",
				Reason: fmt.Sprintf(
					"%s is banned by this policy, but %s. The rule is not evaluated rather "+
						"than counted as satisfied. Confirm it with a scanner built with "+
						"legacy protocol support, such as nmap's ssl-enum-ciphers script; "+
						"OpenSSL 3.x removed the -ssl2 and -ssl3 client options, so "+
						"s_client cannot answer this either", banned, reason),
			})
			continue
		}
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

	// Check maximum version.
	//
	// Declared and documented since the schema was written, and never read, so a
	// policy capping the protocol version passed unconditionally.
	if rules.MaxVersion != "" {
		maxRank := protocolVersionOrder[rules.MaxVersion]
		for _, p := range result.Protocols {
			if rank, known := protocolVersionOrder[p.Version]; p.Supported && known && rank > maxRank {
				pr.Violations = append(pr.Violations, types.PolicyViolation{
					Rule:        "protocol.maxVersion",
					Severity:    types.SeverityMedium,
					Description: "Protocol version above the permitted maximum",
					Expected:    rules.MaxVersion + " or lower",
					Actual:      p.Version + " enabled",
					Remediation: "Disable " + p.Version,
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
		// A version the policy says MUST be supported, and that the scan shows is
		// not, is a violation. It was a warning, so the verdict read COMPLIANT
		// with exit 0 while the same report printed "TLS 1.3  Not Supported" and
		// "Fix: Enable TLS 1.3". Two built-in CNSA 2.0 policies require TLS 1.3,
		// so a CI gate on either was green whatever the server did.
		if !found {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "protocol.requiredVersions",
				Severity:    types.SeverityHigh,
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

		// Check banned algorithms.
		//
		// Matched case-insensitively: these are free-form algorithm names rather
		// than a closed set, so they cannot be validated at load time the way
		// protocol versions are, and an exact-case match meant "sha1" banned
		// nothing while "SHA1" banned seven suites on the same host.
		for _, banned := range rules.BannedAlgorithms {
			if containsFold(cs.Name, banned) || equalFoldAlgorithm(cs.Encryption, banned) ||
				equalFoldAlgorithm(cs.MAC, banned) {
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
			if equalFoldAlgorithm(cs.Name, banned) {
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

	// Check the allowed cipher suite whitelist.
	//
	// Declared, documented and printed by print-policy, and never read, so a
	// policy that named an explicit allowlist accepted every suite the server
	// offered. A whitelist that permits everything is the most misleading shape
	// this rule could have, because the user wrote down exactly what they wanted.
	if len(rules.AllowedCipherSuites) > 0 {
		for _, cs := range result.CipherSuites {
			allowed := false
			for _, permitted := range rules.AllowedCipherSuites {
				if equalFoldAlgorithm(cs.Name, permitted) {
					allowed = true
					break
				}
			}
			if !allowed {
				pr.Violations = append(pr.Violations, types.PolicyViolation{
					Rule:        "cipher.allowedCipherSuites",
					Severity:    types.SeverityHigh,
					Description: "Cipher suite is not on the allowed list",
					Expected:    "one of: " + strings.Join(rules.AllowedCipherSuites, ", "),
					Actual:      cs.Name + " offered",
					Remediation: "Remove " + cs.Name + " from the cipher suite configuration",
				})
			}
		}
	}

	// Check required key exchange (at least one must be present)
	if len(rules.RequiredKeyExchange) > 0 {
		found := false
		for _, ke := range result.KeyExchanges {
			for _, required := range rules.RequiredKeyExchange {
				if equalFoldAlgorithm(ke.Name, required) || equalFoldAlgorithm(ke.PQCAlgorithm, required) {
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

	// A certificate no client would accept cannot satisfy a certificate policy.
	//
	// The name and chain checks are reported and score the certificate dimension
	// zero, but the policy evaluator did not read either, so a policy asking for
	// key size, lifetime and a trusted CA reported COMPLIANT 100/100 against
	// wrong.host.badssl.com and untrusted-root.badssl.com, in the same report
	// that printed "NOT VALID FOR THIS NAME" and scored Certificate 0/25. The
	// individual rules were each satisfied, which is exactly why this has to be
	// its own check rather than an adjustment to them.
	if cert.NameMatch == types.CheckFailed {
		reason := cert.NameMismatchReason
		if reason == "" {
			reason = "the certificate is not valid for the name it was requested under"
		}
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate.nameMatch",
			Severity:    types.SeverityCritical,
			Description: "Certificate is not valid for the requested name",
			Expected:    "a certificate valid for " + cert.RequestedName,
			Actual:      reason,
			Remediation: "Serve a certificate whose subject alternative names cover " +
				cert.RequestedName,
		})
	}
	if cert.ChainTrust == types.CheckFailed {
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate.chainTrust",
			Severity:    types.SeverityCritical,
			Description: "Certificate chain does not build to a trusted root",
			Expected:    "a chain to a root in the trust store of the host running the scan",
			Actual:      "chain verification failed",
			Remediation: "Serve the full chain, including any intermediate certificates, " +
				"from a publicly trusted CA",
		})
	}

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

	// Check the maximum certificate lifetime.
	//
	// Declared and documented, and never read, so a policy capping certificate
	// lifetime accepted any lifetime at all.
	if rules.MaxValidityDays > 0 && !cert.NotBefore.IsZero() && !cert.NotAfter.IsZero() {
		lifetimeDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
		if lifetimeDays > rules.MaxValidityDays {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "certificate.maxValidityDays",
				Severity:    types.SeverityMedium,
				Description: "Certificate lifetime exceeds the permitted maximum",
				Expected:    fmt.Sprintf("<= %d days total validity", rules.MaxValidityDays),
				Actual:      fmt.Sprintf("%d days total validity", lifetimeDays),
				Remediation: fmt.Sprintf("Reissue the certificate with a lifetime of %d days or less",
					rules.MaxValidityDays),
			})
		}
	}

	// Check required signature algorithms.
	//
	// Declared, documented, printed by print-policy and named by the built-in
	// cnsa-2.0-2035 policy, and never read. Requiring ML-DSA-65 of a SHA256-RSA
	// certificate reported COMPLIANT 100/100 and exit 0, on this tool's flagship
	// post-quantum use case.
	if len(rules.RequiredSignatureAlgorithms) > 0 {
		satisfied := false
		for _, required := range rules.RequiredSignatureAlgorithms {
			if containsFold(cert.SignatureAlgorithm, required) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "certificate.requiredSignatureAlgorithms",
				Severity:    types.SeverityHigh,
				Description: "Certificate signature algorithm is not one of those required",
				Expected:    strings.Join(rules.RequiredSignatureAlgorithms, " or "),
				Actual:      cert.SignatureAlgorithm,
				Remediation: "Reissue the certificate with one of: " +
					strings.Join(rules.RequiredSignatureAlgorithms, ", "),
			})
		}
	}

	// Certificate Transparency.
	//
	// The rule is part of the schema and is documented, but this scanner does not
	// collect SCTs or query CT logs, so there is no input to evaluate it against.
	// Reporting it as satisfied would be the same fail-open as reading an
	// unmeasured quantum score as a zero, so it is recorded as not evaluated and
	// the verdict is marked incomplete.
	if rules.RequireCT {
		pr.SkippedRules = append(pr.SkippedRules, types.SkippedPolicyRule{
			Rule: "certificate.requireCt",
			Reason: "this scanner does not collect signed certificate timestamps or query " +
				"Certificate Transparency logs, so it has no evidence either way. Check the " +
				"certificate at https://crt.sh to evaluate this requirement",
		})
	}

	// Check banned signature algorithms
	for _, banned := range rules.BannedSignatureAlgorithms {
		if containsFold(cert.SignatureAlgorithm, banned) {
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

	// Check required key exchange algorithms.
	//
	// Declared, documented, printed by print-policy and named by all three
	// built-in CNSA 2.0 policies, and never read. Requiring ML-KEM-768 of a host
	// with no post-quantum key exchange at all reported COMPLIANT 100/100 and
	// exit 0. In the built-ins the gap was masked by cipher.requiredKeyExchange,
	// which covers the same ground and does work, so a user who kept only the
	// quantum block of a printed policy got an unconditional pass.
	if len(rules.RequiredKeyExchangeAlgorithms) > 0 {
		found := false
		for _, ke := range result.KeyExchanges {
			for _, required := range rules.RequiredKeyExchangeAlgorithms {
				if equalFoldAlgorithm(ke.Name, required) || equalFoldAlgorithm(ke.PQCAlgorithm, required) {
					found = true
					break
				}
			}
		}
		if !found {
			pr.Violations = append(pr.Violations, types.PolicyViolation{
				Rule:        "quantum.requiredKeyExchangeAlgorithms",
				Severity:    types.SeverityCritical,
				Description: "Required key exchange algorithm not found",
				Expected:    strings.Join(rules.RequiredKeyExchangeAlgorithms, " or "),
				Actual:      "None of the required algorithms detected",
				Remediation: "Enable one of: " + strings.Join(rules.RequiredKeyExchangeAlgorithms, ", "),
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
	return protocolVersionOrder[version] >= protocolVersionOrder[minVersion]
}

func (e *PolicyEvaluator) getHighestProtocol(protocols []types.Protocol) string {
	highest := "None"
	highestOrder := -1

	for _, p := range protocols {
		if p.Supported {
			if order, ok := protocolVersionOrder[p.Version]; ok && order > highestOrder {
				highestOrder = order
				highest = p.Version
			}
		}
	}

	return highest
}
