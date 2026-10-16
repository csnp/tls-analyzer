package reporter

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// A policy verdict that only the text report carries is a verdict most readers
// never see.
//
// `--policy-file hyb.yaml --format sarif` exited 2 with "policy not satisfied",
// and the SARIF file it wrote held no result naming the violation, no mention of
// the policy, and an invocation reporting success. HTML and CBOM were the same.
// docs/ci-cd-integration.md uploads that SARIF to code scanning and
// docs/policies.md recommends `--policy strict --format html`, so both documented
// paths delivered the exit code and dropped the reason for it.

// hybridVerdict is the evaluation a policy requiring hybrid key exchange
// produces against a host that offers classical key exchange only. The strings
// are the ones the analyzer writes for quantum.requireHybridKeyExchange.
func hybridVerdict() *types.PolicyResult {
	return &types.PolicyResult{
		PolicyName: "hyb",
		Compliant:  false,
		Complete:   true,
		Score:      70,
		Violations: []types.PolicyViolation{{
			Rule:        "quantum.requireHybridKeyExchange",
			Severity:    types.SeverityCritical,
			Description: "Hybrid PQC key exchange required but not detected",
			Expected:    "X25519MLKEM768 or similar hybrid",
			Actual:      "Classical key exchange only",
			Remediation: "Enable hybrid post-quantum key exchange on your server",
		}},
		Warnings: []types.PolicyViolation{},
	}
}

// incompleteVerdict is a policy whose only rule could not be evaluated, so no
// rule failed and nothing was established either.
func incompleteVerdict() *types.PolicyResult {
	return &types.PolicyResult{
		PolicyName: "q90",
		Compliant:  true,
		Complete:   false,
		Score:      100,
		SkippedRules: []types.SkippedPolicyRule{{
			Rule:   "quantum.minQuantumScore",
			Reason: "the quantum risk assessment did not run in this scan",
		}},
		Violations: []types.PolicyViolation{},
		Warnings:   []types.PolicyViolation{},
	}
}

// compliantVerdict is the acceptance control: a full evaluation with nothing
// wrong. Without it, every "says not established" assertion below would pass
// for a renderer that printed that phrase on every policy.
func compliantVerdict() *types.PolicyResult {
	return &types.PolicyResult{
		PolicyName: "modern",
		Compliant:  true,
		Complete:   true,
		Score:      100,
		Violations: []types.PolicyViolation{},
		Warnings:   []types.PolicyViolation{},
	}
}

func withPolicy(pr *types.PolicyResult) *types.ScanResult {
	result := scannedResult()
	result.PolicyResult = pr
	return result
}

func render(t *testing.T, rep Reporter, result *types.ScanResult) string {
	t.Helper()
	var buf bytes.Buffer
	if err := rep.Report(&buf, result); err != nil {
		t.Fatalf("%s report: %v", rep.Format(), err)
	}
	return buf.String()
}

// htmlSection returns the <section> carrying id, so an assertion about one
// section cannot be satisfied by text elsewhere on the page.
func htmlSection(t *testing.T, page, id string) string {
	t.Helper()
	start := strings.Index(page, `id="`+id+`"`)
	if start < 0 {
		t.Fatalf("the page has no section with id %q", id)
	}
	section := page[start:]
	if end := strings.Index(section, "</section>"); end >= 0 {
		section = section[:end]
	}
	return section
}

func sarifPolicyResults(t *testing.T, run map[string]any) []map[string]any {
	t.Helper()
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("SARIF results is %T, not an array", run["results"])
	}
	var policy []map[string]any
	for _, r := range results {
		res, _ := r.(map[string]any)
		if id, _ := res["ruleId"].(string); strings.HasPrefix(id, "POLICY.") {
			policy = append(policy, res)
		}
	}
	return policy
}

func sarifPolicyProperties(t *testing.T, run map[string]any) map[string]any {
	t.Helper()
	props, _ := run["properties"].(map[string]any)
	policy, _ := props["policy"].(map[string]any)
	if policy == nil {
		t.Fatalf("the SARIF run carries no policy verdict in its property bag: %v", run["properties"])
	}
	return policy
}

func sarifNotificationTexts(t *testing.T, run map[string]any) []string {
	t.Helper()
	invocations, _ := run["invocations"].([]any)
	if len(invocations) != 1 {
		t.Fatalf("SARIF carries %d invocations, want 1", len(invocations))
	}
	inv, _ := invocations[0].(map[string]any)
	notifications, _ := inv["toolExecutionNotifications"].([]any)
	var texts []string
	for _, n := range notifications {
		note, _ := n.(map[string]any)
		msg, _ := note["message"].(map[string]any)
		text, _ := msg["text"].(string)
		texts = append(texts, note["level"].(string)+": "+text)
	}
	return texts
}

// TestSARIFCarriesEachPolicyViolationAsAResult is the CI half of the defect. A gate that
// fails on exit code 2 and uploads this file has to be able to show why.
func TestSARIFCarriesEachPolicyViolationAsAResult(t *testing.T) {
	out := render(t, &SARIFReporter{}, withPolicy(hybridVerdict()))
	run := sarifRunOf(t, out)

	policy := sarifPolicyResults(t, run)
	if len(policy) != 1 {
		t.Fatalf("SARIF carries %d POLICY. results, want 1 for the one violation:\n%s", len(policy), out)
	}
	res := policy[0]
	if res["ruleId"] != "POLICY.quantum.requireHybridKeyExchange" {
		t.Errorf("ruleId = %v, want POLICY.quantum.requireHybridKeyExchange", res["ruleId"])
	}
	if res["level"] != "error" {
		t.Errorf("level = %v, want error for a CRITICAL violation", res["level"])
	}
	msg, _ := res["message"].(map[string]any)
	text, _ := msg["text"].(string)
	for _, want := range []string{
		"Hybrid PQC key exchange required but not detected",
		"X25519MLKEM768 or similar hybrid",
		"Classical key exchange only",
		"Enable hybrid post-quantum key exchange on your server",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the result message does not carry %q:\n%s", want, text)
		}
	}

	// Every result needs its rule, or the document is not valid SARIF.
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules, _ := driver["rules"].([]any)
	var rule map[string]any
	for _, r := range rules {
		candidate, _ := r.(map[string]any)
		if candidate["id"] == "POLICY.quantum.requireHybridKeyExchange" {
			if rule != nil {
				t.Error("the policy rule is declared twice")
			}
			rule = candidate
		}
	}
	if rule == nil {
		t.Fatalf("no rule declares POLICY.quantum.requireHybridKeyExchange: %v", rules)
	}
	help, _ := rule["help"].(map[string]any)
	if help["text"] != "Enable hybrid post-quantum key exchange on your server" {
		t.Errorf("the rule's help is %v, want the violation's fix", help)
	}

	verdict := sarifPolicyProperties(t, run)
	if verdict["name"] != "hyb" {
		t.Errorf("policy name = %v, want hyb", verdict["name"])
	}
	if verdict["compliant"] != false || verdict["complete"] != true {
		t.Errorf("verdict = %v, want compliant false and complete true", verdict)
	}
	if verdict["score"] != float64(70) {
		t.Errorf("policy score = %v, want 70", verdict["score"])
	}
	if skipped, ok := verdict["skippedRules"].([]any); !ok || len(skipped) != 0 {
		t.Errorf("skippedRules = %v, want an empty list", verdict["skippedRules"])
	}

	// The non-compliance does not make the scan a failed execution.
	if !sarifExecutionSuccessful(t, run) {
		t.Error("a scan that ran and found a violation reports a failed execution")
	}
}

// TestSARIFSaysAnIncompleteEvaluationEstablishedNothing covers the verdict
// that has no violation to show. With no result and a successful invocation, a
// policy whose only rule was skipped produced a document identical to a pass.
func TestSARIFSaysAnIncompleteEvaluationEstablishedNothing(t *testing.T) {
	out := render(t, &SARIFReporter{}, withPolicy(incompleteVerdict()))
	run := sarifRunOf(t, out)

	notes := sarifNotificationTexts(t, run)
	var found string
	for _, n := range notes {
		if strings.Contains(n, "not established") {
			found = n
		}
	}
	if found == "" {
		t.Fatalf("no notification says compliance was not established: %v", notes)
	}
	if !strings.HasPrefix(found, "warning: ") {
		t.Errorf("the notification is %q, want level warning", found)
	}
	if !strings.Contains(found, "quantum.minQuantumScore") {
		t.Errorf("the notification does not name the skipped rule: %q", found)
	}

	verdict := sarifPolicyProperties(t, run)
	if verdict["complete"] != false {
		t.Errorf("complete = %v, want false", verdict["complete"])
	}
	if verdict["status"] != "compliance not established" {
		t.Errorf("status = %v, want \"compliance not established\"", verdict["status"])
	}
	skipped, _ := verdict["skippedRules"].([]any)
	if len(skipped) != 1 || skipped[0] != "quantum.minQuantumScore" {
		t.Errorf("skippedRules = %v, want [quantum.minQuantumScore]", verdict["skippedRules"])
	}

	t.Run("control: a complete evaluation carries no such notification", func(t *testing.T) {
		run := sarifRunOf(t, render(t, &SARIFReporter{}, withPolicy(compliantVerdict())))
		for _, n := range sarifNotificationTexts(t, run) {
			if strings.Contains(n, "not established") {
				t.Errorf("a complete evaluation says compliance was not established: %q", n)
			}
		}
		if status := sarifPolicyProperties(t, run)["status"]; status != "compliant" {
			t.Errorf("status = %v, want compliant", status)
		}
	})

	t.Run("control: no policy, no policy verdict", func(t *testing.T) {
		run := sarifRunOf(t, render(t, &SARIFReporter{}, scannedResult()))
		if _, present := run["properties"]; present {
			t.Errorf("a scan without a policy carries a policy verdict: %v", run["properties"])
		}
		if got := sarifPolicyResults(t, run); len(got) != 0 {
			t.Errorf("a scan without a policy carries %d POLICY. results", len(got))
		}
	})
}

func cbomProperties(t *testing.T, out string) map[string]string {
	t.Helper()
	doc := decodeJSON(t, out)
	meta, _ := doc["metadata"].(map[string]any)
	props, _ := meta["properties"].([]any)
	got := make(map[string]string, len(props))
	for _, p := range props {
		kv, _ := p.(map[string]any)
		name, okName := kv["name"].(string)
		value, okValue := kv["value"].(string)
		if !okName || !okValue {
			t.Errorf("CBOM property %v is not a name and value of strings", kv)
			continue
		}
		got[name] = value
	}
	return got
}

// TestCBOMCarriesThePolicyVerdict puts the verdict beside the inventory it was
// reached from, in the metadata properties the unreached branch already uses.
func TestCBOMCarriesThePolicyVerdict(t *testing.T) {
	props := cbomProperties(t, render(t, &CBOMReporter{}, withPolicy(hybridVerdict())))

	want := map[string]string{
		"qramm:policyName":      "hyb",
		"qramm:policyCompliant": "false",
		"qramm:policyComplete":  "true",
		"qramm:policyScore":     "70",
	}
	for name, value := range want {
		if props[name] != value {
			t.Errorf("%s = %q, want %q (properties: %v)", name, props[name], value, props)
		}
	}
	violations := props["qramm:policyViolations"]
	for _, needle := range []string{
		"quantum.requireHybridKeyExchange",
		"Hybrid PQC key exchange required but not detected",
	} {
		if !strings.Contains(violations, needle) {
			t.Errorf("qramm:policyViolations = %q, want it to carry %q", violations, needle)
		}
	}

	t.Run("incomplete", func(t *testing.T) {
		props := cbomProperties(t, render(t, &CBOMReporter{}, withPolicy(incompleteVerdict())))
		if props["qramm:policyComplete"] != "false" {
			t.Errorf("qramm:policyComplete = %q, want false", props["qramm:policyComplete"])
		}
		if !strings.Contains(props["qramm:policyStatus"], "not established") {
			t.Errorf("qramm:policyStatus = %q, want it to say compliance was not established",
				props["qramm:policyStatus"])
		}
	})
}

// TestHTMLCarriesThePolicyVerdict is the page docs/policies.md tells a reader to
// generate with --policy. It had no policy section at all.
func TestHTMLCarriesThePolicyVerdict(t *testing.T) {
	page := render(t, &HTMLReporter{IncludeCSS: true}, withPolicy(hybridVerdict()))
	section := htmlSection(t, page, "policy")

	for _, want := range []string{
		"hyb",
		"NON-COMPLIANT",
		"70/100",
		"quantum.requireHybridKeyExchange",
		"Hybrid PQC key exchange required but not detected",
		"X25519MLKEM768 or similar hybrid",
		"Classical key exchange only",
		"Enable hybrid post-quantum key exchange on your server",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the policy section does not carry %q:\n%s", want, section)
		}
	}
	if strings.Contains(section, "not established") {
		t.Errorf("a complete evaluation is labelled not established:\n%s", section)
	}
}

// standaloneCompliant matches COMPLIANT as a verdict word, not as part of
// NON-COMPLIANT or "compliance".
var standaloneCompliant = regexp.MustCompile(`(?i)(^|[^-a-z])compliant([^a-z]|$)`)

// TestHTMLSaysAnIncompleteEvaluationEstablishedNothing requires an evaluation
// that skipped rules to read as what it is. Nothing failed, so the old verdict
// fields say compliant, and nothing was checked, so that word is unearned.
func TestHTMLSaysAnIncompleteEvaluationEstablishedNothing(t *testing.T) {
	page := render(t, &HTMLReporter{IncludeCSS: true}, withPolicy(incompleteVerdict()))
	section := htmlSection(t, page, "policy")

	if !strings.Contains(section, "not established") {
		t.Errorf("the policy section does not say compliance was not established:\n%s", section)
	}
	if strings.Contains(section, "✓") {
		t.Errorf("an incomplete evaluation carries a pass mark:\n%s", section)
	}
	if m := standaloneCompliant.FindString(section); m != "" {
		t.Errorf("an incomplete evaluation is called compliant (%q):\n%s", m, section)
	}
	for _, want := range []string{"quantum.minQuantumScore", "did not run in this scan"} {
		if !strings.Contains(section, want) {
			t.Errorf("the skipped rule or its reason is missing (%q):\n%s", want, section)
		}
	}

	t.Run("incomplete with a violation", func(t *testing.T) {
		pr := hybridVerdict()
		pr.Complete = false
		pr.SkippedRules = incompleteVerdict().SkippedRules
		section := htmlSection(t, render(t, &HTMLReporter{}, withPolicy(pr)), "policy")
		if !strings.Contains(section, "NON-COMPLIANT") {
			t.Errorf("a violation found before a rule was skipped is still a violation:\n%s", section)
		}
		if !strings.Contains(section, "not established") {
			t.Errorf("the skipped rule is not reflected in the verdict:\n%s", section)
		}
	})

	t.Run("control: a complete compliant evaluation", func(t *testing.T) {
		section := htmlSection(t, render(t, &HTMLReporter{}, withPolicy(compliantVerdict())), "policy")
		if !strings.Contains(section, "COMPLIANT") {
			t.Errorf("a complete compliant evaluation does not say so:\n%s", section)
		}
		if strings.Contains(section, "not established") {
			t.Errorf("a complete evaluation is labelled not established:\n%s", section)
		}
	})
}
