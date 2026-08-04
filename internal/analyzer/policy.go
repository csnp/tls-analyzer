package analyzer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
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
	// The rules as this document alone decodes them, kept before `extends` merges
	// a base in, so the standalone question is answered from the standalone view.
	//
	// The two views cannot actually disagree today: declaresARule only reads keys
	// the document writes, and the overlay decodes the same document over the
	// base, so the document always wins for exactly those keys. Passing the merged
	// rules here is byte-for-byte equivalent. It is kept separate because the
	// distinction is the one the surrounding code reasons about, not because a
	// test can currently tell them apart.
	standaloneRules := policy.Rules

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

	// Whether the policy constrains anything is decided on the MERGED rules, not
	// on the document alone. Short-circuiting on the presence of `extends` meant
	// the check never ran for an inheriting policy, so the exact shape refused
	// standalone was accepted as an overlay, and an overlay that zeroed every
	// inherited rule loaded under its own name and reported COMPLIANT 100/100
	// with no violations against a server offering TLS 1.0 and a 3DES suite.
	//
	// The merged rules are re-serialised and put through the same reader rather
	// than judged by a second, parallel implementation, so "a value that can
	// constrain" is defined in exactly one place.
	merged, err := yaml.Marshal(struct {
		Rules types.PolicyRules `yaml:"rules"`
	}{policy.Rules})
	if err != nil {
		return nil, fmt.Errorf("failed to re-read policy %q for validation: %w", policy.Name, err)
	}

	// The document is authoritative for a standalone policy, because it is the
	// only place an unset field can be told from one written to its zero value,
	// and `allowSelfSigned: false` is both. The merged view is consulted only for
	// an inheriting policy, where what matters is whether anything survives the
	// overlay: there `allowSelfSigned` reads as unconstraining exactly when the
	// overlay set it to true, which is the disarming case.
	declares := declaresARule(data, standaloneRules) ||
		(policy.Extends != "" && declaresARule(merged, policy.Rules))

	if err := validatePolicy(&policy, path, declares, data); err != nil {
		return nil, err
	}

	// The name and description are rendered into a human-readable verdict, and
	// this file is untrusted input.
	policy.Name = sanitizeForReport(policy.Name, 120)
	policy.Description = sanitizeForReport(policy.Description, 120)

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
// The document supplies PRESENCE (which keys were written) and the decoded rules
// supply the VALUE. Judging the value from anywhere else means two decoders
// deciding what one scalar means, and they do not agree:
//
//   - `requireForwardSecrecy: no` resolves to a !!str when decoded into `any`,
//     but yaml.v3's struct decoder has a YAML 1.1 compatibility path that sets
//     the bool field to false. Read as a string it looks like a constraint; the
//     evaluator sees false and enforces nothing.
//   - `minKeySize: 0.4` is a positive float to `any` and truncates to 0 in the
//     int field. Read as a float it looks like a constraint; the evaluator sees
//     0 and enforces nothing.
//
// Both shapes produced COMPLIANT 100/100 with exit 0 from a policy that
// constrains nothing. Reading the value the evaluator will actually use removes
// the disagreement rather than trying to keep two readers in step.
// warningOnlyRuleKeys names the rules that report into Warnings and can never
// produce a violation, so they can never fail a policy.
//
// Both are deliberate, and docs/policies.md states why for each: a certificate
// inside its renewal window is not misconfigured, and no publicly trusted CA
// issues a post-quantum certificate today. Warning is the right report for both.
// What was wrong was letting either one, alone, make a policy look enforceable.
//
// TestEveryWarningOnlyRuleIsListed keeps this in step with the evaluator by
// walking the evaluator for rules that reach Warnings, so a rule that moves
// between Warnings and Violations cannot leave this list stale.
var warningOnlyRuleKeys = map[string]bool{
	"certificate.minValidityDays":    true,
	"quantum.requirePqcCertificates": true,
}

func declaresARule(data []byte, rules types.PolicyRules) bool {
	var doc struct {
		Rules map[string]map[string]yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// A document that does not parse is refused elsewhere with a better
		// message; do not let this check turn that into "defines no rules".
		return true
	}

	decoded := reflect.ValueOf(rules)

	for sectionKey, section := range doc.Rules {
		for key, node := range section {
			// A label enforces nothing on its own, so a policy consisting only of
			// one is as empty as a policy with no rules at all.
			if key == "cnsa2TargetYear" {
				continue
			}
			// Nor does a rule that can only ever warn. This guard asked whether a
			// VALUE could constrain and never whether the RULE could produce a
			// violation, so `minValidityDays: 3650` alone, and
			// `requirePqcCertificates: true` alone, each loaded and then reported
			// COMPLIANT 98/100 with exit 0 forever, in the same report that
			// measured the requirement as unmet. Neither rule can fail a policy by
			// design, so neither can be the thing that makes one enforceable.
			if warningOnlyRuleKeys[sectionKey+"."+key] {
				continue
			}
			if node.Tag == "!!null" {
				continue
			}

			field, ok := ruleField(decoded, sectionKey, key)
			if !ok {
				// An unmapped key is refused by the schema decoder with a better
				// message; do not turn that into "defines no rules".
				return true
			}
			if fieldConstrains(key, field) {
				return true
			}
		}
	}
	return false
}

// ruleField finds the decoded value behind a written `rules.<section>.<key>`,
// matched on the yaml struct tags so it cannot drift as fields are added.
func ruleField(rules reflect.Value, section, key string) (reflect.Value, bool) {
	sectionValue, ok := fieldByYAMLTag(rules, section)
	if !ok {
		return reflect.Value{}, false
	}
	return fieldByYAMLTag(sectionValue, key)
}

func fieldByYAMLTag(v reflect.Value, name string) (reflect.Value, bool) {
	if v.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("yaml")
		if tag == "" {
			continue
		}
		if before, _, _ := strings.Cut(tag, ","); before == name {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// fieldConstrains reports whether a decoded rule value can actually fail a scan.
//
// Every rule is gated on a positive number, a true boolean or a non-empty list,
// so a zero, a false or an empty list is a no-op by construction.
// `allowSelfSigned` is the one inversion in the schema: there FALSE is the
// restrictive setting, and it is the setting every built-in policy uses.
func fieldConstrains(key string, v reflect.Value) bool {
	if key == "allowSelfSigned" {
		return v.Kind() == reflect.Bool && !v.Bool()
	}

	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() > 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() > 0
	case reflect.Float32, reflect.Float64:
		return v.Float() > 0
	case reflect.String:
		return strings.TrimSpace(v.String()) != ""
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			if item.Kind() == reflect.String {
				if strings.TrimSpace(item.String()) != "" {
					return true
				}
				continue
			}
			return true
		}
		return false
	default:
		// A kind this function does not understand cannot be shown to constrain
		// anything, so it does not count as a declared rule.
		//
		// Both halves of the previous comment here were false. It called this arm
		// unreachable on the strength of a walk test that only checks yaml tags and
		// that each field resolves through ruleField, never its Kind, so a rule
		// field added as a *int or a map[string]string reached this arm with the
		// suite green. And it called returning true the safe direction, which is
		// backwards: declaresARule accepts a policy when any field constrains, so
		// true accepts a policy whose only rule may enforce nothing, which is the
		// fail-open direction and the exact shape of the ruleless policies this
		// guard exists to refuse. False refuses the file instead, which is a
		// message the author can act on.
		//
		// TestEveryRuleFieldResolvesThroughTheReflectionMapping now asserts Kind as
		// well, so a field of an unhandled kind fails the suite when it is added
		// rather than arriving here silently.
		return false
	}
}

// decodePolicy decodes the document onto the given starting policy, refusing
// any key the schema does not define.
//
// Unknown keys were previously ignored, so three plausible hand-written
// spellings of the same policy (flat camelCase, nested by prefix, flat
// snake_case) each produced a compliant verdict with no rule having been
// applied, and the real schema was only discoverable by forcing type errors
// that leak Go type names.
// scrubPath makes a policy file's PATH safe to print.
//
// The refusals this release added interpolate the path with %s, and a path is
// untrusted for the same reason the file's contents are: this package's own
// threat model says a policy file "arrives from a vendor, a repository or a
// colleague", and a repository supplies the file's name exactly as much as its
// contents. Git preserves control bytes in filenames, and iterating a directory
// of policies is an ordinary CI shape.
//
// The sibling sites that interpolate a NAME use %q, which escapes control
// characters and needs no help. These use %s, because a quoted path is harder to
// copy back into a shell.
func scrubPath(path string) string {
	return sanitize.ForReport(path, sanitize.MaxReportDetail)
}

// scrubDecoderMessage neutralises the untrusted text in a YAML decoder error
// while keeping the decoder's own structure.
//
// The distinction the whole fix rests on: untrusted text loses its newlines,
// tool-authored text keeps them. yaml.v3 reports a document's problems as a
// TypeError holding one entry per problem, joined with newlines. Those newlines
// are the DECODER'S, and an author fixing a misspelled key needs them one per
// line with its line number. Scrubbing the joined string collapses them along
// with the attacker's, so a file with eleven misspellings rendered as a single
// wrapped blob with five of the eleven dropped behind the length cap: the fix
// for a forgery would have cost the diagnostic that makes refusing unknown keys
// worth doing.
//
// Scrubbing each entry instead applies the budget per diagnostic, so the list
// survives at full length and every entry is still individually bounded and
// stripped.
func scrubDecoderMessage(err error) string {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		scrubbed := make([]string, 0, len(typeErr.Errors))
		for _, entry := range typeErr.Errors {
			scrubbed = append(scrubbed,
				sanitize.ForReport(schemaPathsInErrors.Replace(entry), sanitize.MaxReportDetail))
		}
		// Rebuilt in the shape yaml.v3's own TypeError.Error() uses, so the
		// message an author reads is unchanged apart from the scrubbing.
		return fmt.Sprintf("yaml: unmarshal errors:\n  %s", strings.Join(scrubbed, "\n  "))
	}
	// A syntax error rather than a type error carries no entry list, so there is
	// no structure to preserve and the whole message is untrusted.
	return sanitize.ForReport(schemaPathsInErrors.Replace(err.Error()), sanitize.MaxReportDetail)
}

func (e *PolicyEvaluator) decodePolicy(data []byte, onto types.Policy) (types.Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&onto); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty document decodes without error and leaves the target
			// untouched, which is how an empty file became a passing policy.
			return onto, fmt.Errorf("the policy file contains no YAML document")
		}
		// KnownFields(true) makes the decoder echo an unrecognised key's NAME
		// back verbatim and untruncated, and a policy file is untrusted text by
		// this package's own rule, so this message is a forgery surface: a key
		// name carrying a cursor-up sequence and newlines printed a fabricated
		// COMPLIANT verdict on the stderr that shares the terminal with the
		// report.
		return onto, fmt.Errorf("failed to parse policy YAML: %s\n"+
			"Run 'tlsanalyzer print-policy modern' to see a valid policy to start from",
			scrubDecoderMessage(err))
	}

	// Everything after the first `---` was read by nobody.
	//
	// A file whose first document was trivially satisfiable and whose second was
	// strict reported the first document's name, COMPLIANT, 100/100 and exit 0,
	// while the second document alone failed the same host with 7 violations and
	// exit 2. The rules the author wrote were discarded in silence, and the
	// verdict named a policy that was only part of the file.
	//
	// Refusing is the only safe direction, per this loader's own rule that a gate
	// passing on an input it did not understand is the worst available to it.
	// Guessing which document was meant, or merging them, would both be a verdict
	// about a policy nobody wrote.
	if extra, complete := countRemainingDocuments(dec); extra > 0 {
		total := fmt.Sprintf("%d", extra+1)
		if !complete {
			total = "at least " + total
		}
		return onto, fmt.Errorf(
			"the policy file contains %s YAML documents separated by '---', and only the "+
				"first would be applied, so the rules in %s would be discarded in silence. "+
				"Put each policy in its own file and apply one with --policy-file",
			total, otherDocuments(extra, complete))
	}

	return onto, nil
}

// countRemainingDocuments counts what is left in the stream after the document
// already decoded.
//
// A document that does not parse still counts: it is a document the author
// wrote, and refusing the file names a real problem either way.
//
// Emptiness is judged on the decoded VALUE, not on the node. A trailing `---`
// with nothing after it still yields a DocumentNode with one child, so
// yaml.Node reports Kind 1 and one content item exactly as a real document
// does, and a check on Kind never fires. Decoding into an interface gives nil
// for a document that carries nothing, which is the question actually being
// asked: did the author write a policy there that is being discarded.
func countRemainingDocuments(dec *yaml.Decoder) (count int, complete bool) {
	for {
		var doc any
		err := dec.Decode(&doc)
		switch {
		case errors.Is(err, io.EOF):
			return count, true

		case err != nil:
			// A document that does not parse still counts, and counting it ENDS
			// the walk.
			//
			// yaml.v3 does not advance past a syntax error: it returns the same
			// non-EOF error on every subsequent Decode, forever. Looping until EOF
			// therefore never terminated, and a policy file whose second document
			// had a syntax error hung the process at 100% CPU before any network
			// work, producing no output at all. In CI that reads as a hung scan
			// rather than a rejected file.
			//
			// One more document is enough to refuse the file, which is the outcome
			// either way, so there is nothing to gain by reading further. The count
			// is a lower bound from here, and the caller says so rather than
			// asserting a total it did not finish counting.
			return count + 1, false

		case doc == nil:
			// A separator with nothing after it declares no rules, so it is not a
			// discarded policy and refusing the file over it would be a false alarm.
			continue

		default:
			count++
		}
	}
}

// otherDocuments names the documents after the first, for the refusal message.
//
// When the walk stopped early on a malformed document the count is a lower
// bound, so the phrasing must not claim a total the file may exceed.
func otherDocuments(n int, complete bool) string {
	if !complete {
		return "the others"
	}
	if n == 1 {
		return "the other one"
	}
	return fmt.Sprintf("the other %d", n)
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
//
// A needle that normalizes to nothing never matches. Without that guard the
// normalization reintroduced the fail-open it was written to close, because
// strings.Contains(s, "") is true: a value with no ASCII alphanumerics, such as
// the fullwidth spelling of "ML-DSA-65" or a lone em dash, matched every input.
// A required-algorithm rule written that way passed unconditionally while
// rendering as though it were strict, and a banned-algorithm rule written that
// way flagged every suite on a safe server.
func containsFold(s, substr string) bool {
	needle := normalizeAlgorithmName(substr)
	if needle == "" {
		return false
	}
	return strings.Contains(normalizeAlgorithmName(s), needle)
}

// signatureUpgradePreference is the order in which a replacement certificate
// signature algorithm is suggested, strongest first.
//
// Every entry is obtainable from a publicly trusted CA today. ML-DSA and SLH-DSA
// are deliberately absent: no public CA issues a post-quantum certificate yet, so
// naming one here would be advice the operator cannot act on, which this tool
// treats as a defect in its own right. A policy that genuinely wants one says so
// in requiredSignatureAlgorithms, and that branch is preferred over this list.
var signatureUpgradePreference = []string{
	"ECDSA-SHA512",
	"ECDSA-SHA384",
	"SHA384-RSA",
	"ECDSA-SHA256",
	"SHA256-RSA",
}

// bannedSignatureRemediation names a next step the SAME policy will accept.
//
// This carried a hardcoded "Reissue certificate with SHA-256 or stronger
// signature" whatever the policy banned. The shipped `strict` policy bans SHA1,
// MD5 and SHA256, because it is aiming at SHA-384 or better, so scanning any
// ECDSA-SHA256 certificate under `strict` printed a fix that reproduces the
// violation it claims to resolve. The remediation is derived from the policy
// now, and only ever names an algorithm that policy does not ban.
func bannedSignatureRemediation(rules *types.CertificateRules) string {
	if rules == nil {
		return "Reissue the certificate with a signature algorithm this policy does not ban"
	}
	if len(rules.RequiredSignatureAlgorithms) > 0 {
		return "Reissue the certificate with a signature algorithm this policy requires: " +
			strings.Join(rules.RequiredSignatureAlgorithms, ", ")
	}

	for _, candidate := range signatureUpgradePreference {
		bannedHere := false
		for _, banned := range rules.BannedSignatureAlgorithms {
			if containsFold(candidate, banned) {
				bannedHere = true
				break
			}
		}
		if !bannedHere {
			return "Reissue the certificate with a signature algorithm this policy allows, " +
				"for example " + candidate
		}
	}

	// Every candidate is banned, so naming one would contradict the violation.
	return "Reissue the certificate with a signature algorithm this policy does not ban"
}

// equalFoldAlgorithm reports whether two algorithm or suite names are the same
// once both are normalized. Two values that both normalize to nothing are not
// equal for this purpose: an empty scanned field must not satisfy a rule.
func equalFoldAlgorithm(a, b string) bool {
	na, nb := normalizeAlgorithmName(a), normalizeAlgorithmName(b)
	if na == "" || nb == "" {
		return false
	}
	return na == nb
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

// sanitizeForReport strips the control characters that let a policy file forge
// the report it appears in.
//
// The name and description are attacker-supplied: a policy file arrives from a
// vendor, a repository or a colleague, and it is rendered into a human-readable
// verdict. A name containing newlines printed its own "Status: COMPLIANT /
// Score: 100/100" block and pushed the real verdict off the screen, and an ANSI
// escape survived --no-color. The exit code and the JSON stayed honest
// throughout, which is exactly why the text report had to be fixed rather than
// relied upon.
func sanitizeForReport(s string, maxLen int) string {
	return sanitize.ForReport(s, maxLen)
}

// sanitizePolicyResult scrubs every string in a verdict that can carry text from
// the policy file.
//
// Sanitising the name and description alone was not enough: a rule VALUE is
// interpolated into Expected, Actual and Remediation, and those are printed by
// the same renderer. An allowed-suite list containing an ANSI cursor-up sequence
// rewrote the line above it, so a NON-COMPLIANT verdict could be overprinted
// with a COMPLIANT one, surviving --no-color. Doing it once here covers every
// consumer rather than every print site.
func sanitizePolicyResult(pr *types.PolicyResult) {
	const maxDetail = sanitize.MaxReportDetail
	scrub := func(vs []types.PolicyViolation) {
		for i := range vs {
			vs[i].Description = sanitizeForReport(vs[i].Description, maxDetail)
			vs[i].Expected = sanitizeForReport(vs[i].Expected, maxDetail)
			vs[i].Actual = sanitizeForReport(vs[i].Actual, maxDetail)
			vs[i].Remediation = sanitizeForReport(vs[i].Remediation, maxDetail)
		}
	}
	scrub(pr.Violations)
	scrub(pr.Warnings)
	for i := range pr.SkippedRules {
		pr.SkippedRules[i].Reason = sanitizeForReport(pr.SkippedRules[i].Reason, maxDetail)
	}
}

// closestProtocolVersion picks the accepted spelling nearest to what the user
// wrote, so the error can contrast the two. Comparing the rejected value against
// a hardcoded example produced `"TLSv1.2" and "TLSv1.2" are not the same value`
// for the exact typo this check exists to catch.
//
// The family letters are weighed before the digits, because a suffix-only
// comparison scored every candidate zero for "TLS 1.4" and fell back to
// whichever name sorted first, suggesting "SSL 2.0" for a TLS typo.
func closestProtocolVersion(value string) string {
	normalized := normalizeAlgorithmName(value)
	names := make([]string, 0, len(protocolVersionOrder)+len(unprobeableProtocolVersions))
	for name := range knownProtocolVersionNames() {
		names = append(names, name)
	}
	sort.Strings(names)

	best, bestScore := "TLS 1.2", -1
	for _, name := range names {
		candidate := normalizeAlgorithmName(name)
		score := 0
		// Shared leading letters: "tls" against "tls", which is what separates a
		// mistyped TLS version from an SSL one.
		for i := 0; i < len(candidate) && i < len(normalized); i++ {
			if candidate[i] != normalized[i] {
				break
			}
			score += 2
		}
		// Shared trailing characters, which separates 1.2 from 1.3.
		for i := 0; i < len(candidate) && i < len(normalized); i++ {
			if candidate[len(candidate)-1-i] != normalized[len(normalized)-1-i] {
				break
			}
			score++
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

// writtenWarningOnlyRules names the warning-only rules the DOCUMENT wrote, so
// the refusal can quote them back to the author.
//
// It reads the document rather than the decoded rules for the same reason
// declaresARule does: the decoded view of an inheriting policy is the MERGED
// view, and every built-in sets minValidityDays. Judging on that named
// certificate.minValidityDays for an overlay that never mentioned it, and then
// advised using 'extends' to a file already using 'extends'. The refusal was
// right and both halves of its diagnosis were wrong.
func writtenWarningOnlyRules(data []byte, rules types.PolicyRules) []string {
	var doc struct {
		Rules map[string]map[string]yaml.Node `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}

	decoded := reflect.ValueOf(rules)

	var written []string
	for sectionKey, section := range doc.Rules {
		for key, node := range section {
			if node.Tag == "!!null" {
				continue
			}
			full := sectionKey + "." + key
			if !warningOnlyRuleKeys[full] {
				continue
			}
			// Presence from the document, VALUE from the decoded rules, the same
			// split declaresARule uses. Naming a rule on presence alone told the
			// author that `minValidityDays: 0` "will stay advisory, reporting a
			// warning", when a zero makes the evaluator emit nothing at all. Those
			// inputs get the plain "defines no rules" message, which is true.
			field, ok := ruleField(decoded, sectionKey, key)
			if !ok || !fieldConstrains(key, field) {
				continue
			}
			written = append(written, full)
		}
	}
	sort.Strings(written)
	return written
}

// validatePolicy refuses a policy that cannot produce a meaningful verdict.
func validatePolicy(policy *types.Policy, path string, declaresRule bool, data []byte) error {
	if strings.TrimSpace(policy.Name) == "" {
		return fmt.Errorf("policy file %s sets no 'name'. A report has to be able to say which "+
			"policy it applied, and an unnamed policy was reported as an empty policy name "+
			"beside a compliant verdict", scrubPath(path))
	}

	if !declaresRule {
		// Say which of the two cases this is. "Defines no rules" is false for a
		// policy that writes rules which happen to be warning-only, and a message
		// that describes the wrong problem sends the author looking in the wrong
		// place.
		if written := writtenWarningOnlyRules(data, policy.Rules); len(written) > 0 {
			// Say that the named rules stay advisory whatever else is added.
			// Without that, the remedy this message offers looks like it makes the
			// whole file enforceable: add one real rule and the file loads, but the
			// rule the author actually cared about still cannot fail, and the
			// verdict is a green exit 0 that means nothing about it. Moving the
			// false assurance is not removing it.
			return fmt.Errorf("policy %q in %s defines only rules that report a warning and "+
				"can never fail a policy (%s), so nothing can fail it and a compliant verdict "+
				"from it would mean nothing. Add at least one rule that can produce a "+
				"violation, or use 'extends' to inherit one of the built-in policies. Note "+
				"that %s will stay advisory even then, reporting a warning and never "+
				"changing the verdict or the exit code; see the 'Rules that only warn' "+
				"section of docs/policies.md for why",
				policy.Name, scrubPath(path), strings.Join(written, ", "), strings.Join(written, " and "))
		}
		return fmt.Errorf("policy %q in %s defines no rules, so nothing can fail it and a "+
			"compliant verdict from it would mean nothing. Add at least one rule, or use "+
			"'extends' to inherit one of the built-in policies", policy.Name, scrubPath(path))
	}

	if err := validateProtocolVersionValues(&policy.Rules.Protocol); err != nil {
		return fmt.Errorf("policy %q in %s: %w", policy.Name, scrubPath(path), err)
	}

	if err := validateAlgorithmValues(&policy.Rules); err != nil {
		return fmt.Errorf("policy %q in %s: %w", policy.Name, scrubPath(path), err)
	}

	return nil
}

// validateAlgorithmValues refuses an algorithm name that carries no letters or
// digits at all.
//
// Names are compared on their letters and digits, so such a value reduces to
// nothing and can never identify an algorithm. Left unchecked it does not merely
// fail to match: an empty needle matches everything, so a required-algorithm
// rule passed unconditionally and a banned-algorithm rule flagged every suite.
// Refusing it at load is the same treatment an unrecognised protocol version
// gets, and for the same reason: the alternative is a rule that renders as
// though it were strict and enforces nothing.
func validateAlgorithmValues(rules *types.PolicyRules) error {
	fields := []struct {
		name   string
		values []string
	}{
		{"cipher.bannedAlgorithms", rules.Cipher.BannedAlgorithms},
		{"cipher.bannedCipherSuites", rules.Cipher.BannedCipherSuites},
		{"cipher.allowedCipherSuites", rules.Cipher.AllowedCipherSuites},
		{"cipher.requiredKeyExchange", rules.Cipher.RequiredKeyExchange},
		{"certificate.bannedSignatureAlgorithms", rules.Certificate.BannedSignatureAlgorithms},
		{"certificate.requiredSignatureAlgorithms", rules.Certificate.RequiredSignatureAlgorithms},
		{"quantum.requiredKeyExchangeAlgorithms", rules.Quantum.RequiredKeyExchangeAlgorithms},
	}

	for _, field := range fields {
		for _, value := range field.values {
			if normalizeAlgorithmName(value) == "" {
				return fmt.Errorf("rules.%s contains the value %q, which has no letters or "+
					"digits. Algorithm names are compared on their letters and digits, so this "+
					"value cannot identify anything: as a requirement it would be satisfied by "+
					"any input, and as a ban it would match every input. Write the name as it "+
					"appears in the report, for example ML-KEM-768 or SHA-256",
					field.name, value)
			}
		}
	}
	return nil
}

// GetPolicy returns a built-in policy by name.
func (e *PolicyEvaluator) GetPolicy(name string) (*types.Policy, bool) {
	p, ok := e.policies[name]
	return &p, ok
}

// ListPolicies returns all available policy names, in a stable order.
//
// Sorted because the names are printed: by the `policies` command, and by the
// refusal that names the built-ins after an unknown `extends`. Ranging the map
// gave a different order on every run, which makes a golden-output test flaky
// and a CI diff noisy for a value that never changed. knownProtocolVersions
// sorts for the same reason.
func (e *PolicyEvaluator) ListPolicies() []string {
	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	sort.Strings(names)
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

	// Rule values from the policy file reach Expected, Actual and Remediation,
	// and those are rendered into the verdict a human reads.
	sanitizePolicyResult(pr)

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

		// A strict reading of the floor also asserts that SSL 2.0 and SSL 3.0 are
		// not accepted, and this scanner cannot see either. It is NOT recorded as
		// a skipped rule, deliberately: every policy sets a minVersion, so doing
		// so would mark every evaluation incomplete forever and make "complete"
		// mean nothing, which costs more honesty than it buys. The difference
		// from bannedVersions is intent. There the user names SSL 3.0 and is
		// specifically asking about it, so being unable to answer is the whole
		// point; here they are describing a TLS floor. The probe range is
		// disclosed in the scan coverage notes instead.
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
		// The mirror of the banned case: claiming a version is missing is as
		// unfounded as claiming it is absent when the scanner cannot offer it.
		if reason, cannotProbe := unprobeableProtocolVersions[required]; cannotProbe {
			pr.SkippedRules = append(pr.SkippedRules, types.SkippedPolicyRule{
				Rule: "protocol.requiredVersions",
				Reason: fmt.Sprintf(
					"%s is required by this policy, but %s. The rule is not evaluated rather "+
						"than reported as unmet", required, reason),
			})
			continue
		}
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

// chainTrustActual states why the chain was not trusted, for the Actual field of
// the violation.
//
// This read "chain verification failed" regardless of cause, which discarded the
// one detail an operator needs to act: which certificate is at fault. An expired
// INTERMEDIATE is not visible in anything else the report prints about the
// certificate, because every other field describes the leaf.
func chainTrustActual(cert *types.Certificate) string {
	if cert.ChainTrustReason == "" {
		return "chain verification failed"
	}
	return cert.ChainTrustReason
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
	//
	// Each check has a third state, and that state was the missing half of the
	// expired-intermediate CRITICAL. CheckNotPerformed was read as neither a
	// violation nor a skip here and in every other consumer, so "the check did
	// not run" was indistinguishable from "the check passed" all the way to the
	// exit code. A check that did not run cannot establish that the certificate
	// policy is satisfied, so it is recorded as a skipped rule and the verdict is
	// marked incomplete, the same fail-closed path certificate.requireCt takes.
	//
	// Only CheckPassed is written as an accepting arm, and every other value
	// skips. That is deliberate and the default arm IS reachable: CheckResult is
	// a string whose zero value is "", not CheckNotPerformed, so a Certificate
	// built by a consumer of pkg/types that never set these fields arrives here
	// with "". Listing CheckNotPerformed instead of defaulting would read that ""
	// as acceptance, which is the same fail-open one level down. Scans made by
	// this scanner always set both fields, so no real scan reaches the arm by
	// that route.
	switch cert.NameMatch {
	case types.CheckFailed:
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
	case types.CheckPassed:
	default:
		reason := cert.NameMismatchReason
		if reason == "" {
			reason = "the name check did not run in this scan"
		}
		pr.SkippedRules = append(pr.SkippedRules, types.SkippedPolicyRule{
			Rule: "certificate.nameMatch",
			Reason: reason + ", so there is no evidence either way that this certificate " +
				"authenticates the name it was requested under",
		})
	}

	switch cert.ChainTrust {
	case types.CheckFailed:
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate.chainTrust",
			Severity:    types.SeverityCritical,
			Description: "Certificate chain does not build to a trusted root",
			Expected:    "a chain to a root in the trust store of the host running the scan",
			Actual:      chainTrustActual(cert),
			Remediation: "Serve the full chain, including any intermediate certificates, " +
				"from a publicly trusted CA",
		})
	case types.CheckPassed:
	default:
		reason := cert.ChainTrustReason
		if reason == "" {
			reason = "the chain check did not run in this scan"
		}
		pr.SkippedRules = append(pr.SkippedRules, types.SkippedPolicyRule{
			Rule: "certificate.chainTrust",
			Reason: reason + ", so there is no evidence either way that this chain builds " +
				"to a trusted root",
		})
	}

	// Check validity. Both ends of the window are a violation: a certificate
	// whose validity has not started is refused by every client exactly as an
	// expired one is. Checking only Expired left the other end silent here, and
	// silent in the worst way, because a not-yet-valid certificate then fell
	// through to the minValidityDays branch where its DaysUntilExpiry is large
	// enough to clear any threshold.
	if cert.Expired || cert.NotYetValid {
		description, actual := "Certificate has expired", "Certificate expired"
		remediation := "Renew the certificate immediately"
		if cert.NotYetValid {
			description = "Certificate is not yet valid"
			actual = "Validity period starts " + cert.NotBefore.Format("2006-01-02")
			remediation = "Check the certificate's notBefore date and the clock on the " +
				"scanning host, then deploy a certificate that is valid now"
		}
		pr.Violations = append(pr.Violations, types.PolicyViolation{
			Rule:        "certificate.validity",
			Severity:    types.SeverityCritical,
			Description: description,
			Expected:    "Valid certificate",
			Actual:      actual,
			Remediation: remediation,
		})
	} else if rules.MinValidityDays > 0 && cert.DaysUntilExpiry < rules.MinValidityDays {
		// Deliberately a warning, not a violation. docs/policies.md states the
		// reason: a certificate inside its renewal window is not misconfigured,
		// and failing a build on it would fail every host running a 90-day
		// certificate for the last month of its life. See warningOnlyRuleKeys,
		// which stops a policy made only of rules like this from loading as
		// though it could gate anything.
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
				Remediation: bannedSignatureRemediation(rules),
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

	// Check PQC certificate requirement.
	//
	// Deliberately a warning, not a violation. docs/policies.md states the
	// reason: no publicly trusted CA issues an ML-DSA or SLH-DSA certificate
	// today, so failing on it would fail every host on the internet for a
	// condition no operator can remedy. See warningOnlyRuleKeys, which stops a
	// policy made only of rules like this from loading as though it could gate
	// anything.
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
