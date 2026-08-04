package analyzer

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// This file names nothing that did not already exist, so it compiles against the
// pre-fix sources and fails there on behaviour.
//
// The defect: LoadPolicy decoded one YAML document and ignored the rest of the
// stream. A file whose first document was trivially satisfiable and whose second
// was strict reported the first document's name, COMPLIANT, 100/100 and exit 0,
// while the second document alone failed the same host with violations and exit
// 2. The rules the author wrote were discarded in silence.

// writePolicyFile lives in policy_rule_values_test.go and writes into the test's
// own t.TempDir, so no test here can observe a file another test wrote.

const trivialDocument = `name: Part One
version: "1.0"
description: trivially satisfiable
rules:
  certificate:
    minEccKeySize: 128
`

const strictDocument = `name: Part Two
version: "1.0"
description: strict, and silently discarded
rules:
  protocol:
    minVersion: TLS 1.3
  certificate:
    minRsaKeySize: 8192
`

// TestAMultiDocumentPolicyFileIsRefused is the reproduction.
func TestAMultiDocumentPolicyFileIsRefused(t *testing.T) {
	path := writePolicyFile(t, trivialDocument+"---\n"+strictDocument)

	e := NewPolicyEvaluator()
	_, err := e.LoadPolicy(path)
	if err == nil {
		t.Fatal("a file holding two policies loaded as one, so the second document's rules " +
			"were discarded and the verdict names a policy that is only part of the file")
	}

	// The message has to name the problem, not merely fail. A user looking at a
	// file they wrote needs to be told which part of it is not being read.
	for _, want := range []string{"---", "first"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not mention %q, so it does not say what is wrong",
				err.Error(), want)
		}
	}
}

// TestTheRefusalCountsEveryDocument keeps the message truthful about the file in
// front of the user rather than reporting a fixed number.
func TestTheRefusalCountsEveryDocument(t *testing.T) {
	third := `name: Part Three
version: "1.0"
rules:
  cipher:
    minKeySize: 256
`
	path := writePolicyFile(t, trivialDocument+"---\n"+strictDocument+"---\n"+third)

	e := NewPolicyEvaluator()
	_, err := e.LoadPolicy(path)
	if err == nil {
		t.Fatal("a file holding three policies loaded as one")
	}
	if !strings.Contains(err.Error(), "3 YAML documents") {
		t.Errorf("the refusal %q does not report the number of documents in the file",
			err.Error())
	}
}

// TestASingleDocumentPolicyStillLoads is the control. Refusing every file would
// satisfy the tests above and break the feature.
func TestASingleDocumentPolicyStillLoads(t *testing.T) {
	path := writePolicyFile(t, strictDocument)

	e := NewPolicyEvaluator()
	policy, err := e.LoadPolicy(path)
	if err != nil {
		t.Fatalf("a single-document policy file was refused: %v", err)
	}
	if policy.Name != "Part Two" {
		t.Errorf("loaded policy is named %q, want %q", policy.Name, "Part Two")
	}
	if policy.Rules.Certificate.MinRSAKeySize != 8192 {
		t.Errorf("the document's rules did not survive the load: minRsaKeySize=%d",
			policy.Rules.Certificate.MinRSAKeySize)
	}
}

// TestSeparatorsAroundASingleDocumentAreNotExtraDocuments is the second control,
// and it is the one that caught a false claim. A leading `---` is ordinary YAML
// and a trailing one carries no rules, so neither is a discarded policy.
//
// Judging this on yaml.Node.Kind does not work: a trailing separator still
// yields a DocumentNode with one child, exactly as a real document does, so a
// Kind check never fires and every such file is refused. The value has to be
// decoded to see that it is empty.
func TestSeparatorsAroundASingleDocumentAreNotExtraDocuments(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"leading", "---\n" + strictDocument},
		{"trailing", strictDocument + "---\n"},
		{"both", "---\n" + strictDocument + "---\n"},
		{"trailing with a comment", strictDocument + "---\n# nothing here\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)

			e := NewPolicyEvaluator()
			policy, err := e.LoadPolicy(path)
			if err != nil {
				t.Fatalf("a single policy with a %s separator was refused: %v", tc.name, err)
			}
			if policy.Rules.Certificate.MinRSAKeySize != 8192 {
				t.Errorf("the document's rules did not survive the load: minRsaKeySize=%d",
					policy.Rules.Certificate.MinRSAKeySize)
			}
		})
	}
}

// TestAWarningOnlyRuleCanFailAPolicy is the reproduction of the second HIGH.
//
// certificate.minValidityDays and quantum.requirePqcCertificates appended to
// Warnings, which neither the compliance verdict nor the exit code reads, so
// either rule on its own reported COMPLIANT 98/100 with exit 0 forever while the
// scan had measured the requirement as unmet.
func TestAWarningOnlyRuleCanFailAPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		rule string
	}{
		{
			name: "minValidityDays",
			rule: "certificate.minValidityDays",
			body: `name: ten year certificates
version: "1.0"
rules:
  certificate:
    minValidityDays: 3650
`,
		},
		{
			name: "requirePqcCertificates",
			rule: "quantum.requirePqcCertificates",
			body: `name: pqc certificates
version: "1.0"
rules:
  quantum:
    requirePqcCertificates: true
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)

			e := NewPolicyEvaluator()
			policy, err := e.LoadPolicy(path)
			if err != nil {
				t.Fatalf("load policy: %v", err)
			}

			// A host that meets nothing the rule asks for: a classical certificate
			// with 63 days left, which is what cloudflare.com measured at.
			result := scanWithChainCheckResult(types.CheckPassed, types.CheckPassed)
			result.Certificate.DaysUntilExpiry = 63
			result.Certificate.QuantumSafe = false

			pr := e.Evaluate(result, policy)

			if findViolation(pr, tc.rule) == nil {
				t.Errorf("%s raised no violation against a scan that measured the requirement "+
					"as unmet; warnings=%v", tc.rule, pr.Warnings)
			}
			if pr.Compliant {
				t.Errorf("a policy whose only rule is %s reported COMPLIANT %d/100 against a "+
					"scan that measured the requirement as unmet, so the rule can never fail",
					tc.rule, pr.Score)
			}
		})
	}
}

// TestAMetRequirementIsStillCompliant is the control for the promotion. Raising
// the violation unconditionally would satisfy the test above and fail every
// host, including those that satisfy the rule.
func TestAMetRequirementIsStillCompliant(t *testing.T) {
	for _, tc := range []struct {
		name        string
		body        string
		rule        string
		days        int
		quantumSafe bool
	}{
		{
			name: "validity above the minimum",
			rule: "certificate.minValidityDays",
			body: `name: thirty day minimum
version: "1.0"
rules:
  certificate:
    minValidityDays: 30
`,
			days:        90,
			quantumSafe: false,
		},
		{
			name: "a post-quantum certificate",
			rule: "quantum.requirePqcCertificates",
			body: `name: pqc certificates
version: "1.0"
rules:
  quantum:
    requirePqcCertificates: true
`,
			days:        90,
			quantumSafe: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)

			e := NewPolicyEvaluator()
			policy, err := e.LoadPolicy(path)
			if err != nil {
				t.Fatalf("load policy: %v", err)
			}

			result := scanWithChainCheckResult(types.CheckPassed, types.CheckPassed)
			result.Certificate.DaysUntilExpiry = tc.days
			result.Certificate.QuantumSafe = tc.quantumSafe

			pr := e.Evaluate(result, policy)

			if v := findViolation(pr, tc.rule); v != nil {
				t.Errorf("%s raised a violation against a scan that satisfies it: "+
					"Expected %q, Actual %q", tc.rule, v.Expected, v.Actual)
			}
			if !pr.Compliant {
				t.Errorf("a host satisfying the only rule in the policy was reported "+
					"non-compliant; violations=%v", pr.Violations)
			}
		})
	}
}
