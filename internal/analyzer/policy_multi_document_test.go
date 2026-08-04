package analyzer

import (
	"strings"
	"testing"
	"time"

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

func findWarning(pr *types.PolicyResult, rule string) *types.PolicyViolation {
	for i := range pr.Warnings {
		if pr.Warnings[i].Rule == rule {
			return &pr.Warnings[i]
		}
	}
	return nil
}

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

// TestAPolicyOfOnlyWarningRulesIsRefused is the reproduction of the second HIGH.
//
// certificate.minValidityDays and quantum.requirePqcCertificates report into
// Warnings, which neither the compliance verdict nor the exit code reads, so
// either rule on its own reported COMPLIANT 98/100 with exit 0 forever while the
// same scan measured the requirement as unmet.
//
// Both rules warn by design and docs/policies.md states why for each: a
// certificate inside its renewal window is not misconfigured, and no publicly
// trusted CA issues a post-quantum certificate today. So the defect is not that
// they warn, it is that the guard refusing unenforceable policies asked whether
// a VALUE could constrain rather than whether the RULE could produce a
// violation, and so let a policy made only of these load as a gate.
func TestAPolicyOfOnlyWarningRulesIsRefused(t *testing.T) {
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
		{
			name: "both together",
			rule: "certificate.minValidityDays",
			body: `name: both warning rules
version: "1.0"
rules:
  certificate:
    minValidityDays: 3650
  quantum:
    requirePqcCertificates: true
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)

			e := NewPolicyEvaluator()
			_, err := e.LoadPolicy(path)
			if err == nil {
				t.Fatalf("a policy whose only rule is %s loaded, and it can never fail, so "+
					"it reports compliant with exit 0 against every host forever", tc.rule)
			}

			// The refusal must describe THIS problem. "Defines no rules" is false
			// here: the policy does define one, it just cannot fail.
			if !strings.Contains(err.Error(), tc.rule) {
				t.Errorf("the refusal %q does not name the rule at fault (%s)",
					err.Error(), tc.rule)
			}
			if strings.Contains(err.Error(), "defines no rules") {
				t.Errorf("the refusal says the policy defines no rules, which is false: it "+
					"defines %s. %q", tc.rule, err.Error())
			}
		})
	}
}

// TestAWarningOnlyRuleStillWarnsAlongsideARealRule is the control that keeps the
// documented behaviour. The rules are supposed to warn; only a policy made
// ENTIRELY of them is refused. Treating them as violations would fail every host
// running a 90-day certificate through the last month of its life, and every
// host on the internet for the PQC rule, which is why they warn.
func TestAWarningOnlyRuleStillWarnsAlongsideARealRule(t *testing.T) {
	path := writePolicyFile(t, `name: mixed
version: "1.0"
rules:
  certificate:
    minEccKeySize: 256
    minValidityDays: 3650
  quantum:
    requirePqcCertificates: true
`)

	e := NewPolicyEvaluator()
	policy, err := e.LoadPolicy(path)
	if err != nil {
		t.Fatalf("a policy with one enforceable rule was refused: %v", err)
	}

	result := scanWithChainCheckResult(types.CheckPassed, types.CheckPassed)
	result.Certificate.DaysUntilExpiry = 63
	result.Certificate.QuantumSafe = false

	pr := e.Evaluate(result, policy)

	for _, rule := range []string{"certificate.minValidityDays", "quantum.requirePqcCertificates"} {
		if findWarning(pr, rule) == nil {
			t.Errorf("%s raised no warning against a scan that measured it as unmet; "+
				"warnings=%v", rule, pr.Warnings)
		}
		if findViolation(pr, rule) != nil {
			t.Errorf("%s was raised as a violation. It warns by design; see docs/policies.md",
				rule)
		}
	}
	if !pr.Compliant {
		t.Errorf("warnings made the verdict non-compliant, which would fail a build on a "+
			"certificate inside its renewal window; violations=%v", pr.Violations)
	}
}

// TestAMalformedLaterDocumentIsRefusedAndTerminates is the reproduction of a
// defect the multi-document refusal itself introduced.
//
// yaml.v3 does not advance past a syntax error: after one, every subsequent
// Decode returns the SAME non-EOF error, forever. The document walk broke only
// on io.EOF, so a policy file whose second document had a syntax error spun at
// 100% CPU and never returned, before any network work and with no output at
// all. In CI that reads as a hung scan rather than a rejected file.
//
// The walk had no case for a malformed later document, which is why this
// shipped. The test is bounded by a channel rather than left to run, so a
// regression fails the suite instead of hanging it.
func TestAMalformedLaterDocumentIsRefusedAndTerminates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second string
	}{
		{"unclosed flow sequence", "foo: [unclosed\n"},
		{"tab indentation", "name: x\n\tbad: 1\n"},
		{"undefined anchor", "foo: *nosuchanchor\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, trivialDocument+"---\n"+tc.second)

			done := make(chan error, 1)
			go func() {
				_, err := NewPolicyEvaluator().LoadPolicy(path)
				done <- err
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a file whose second document does not parse was accepted")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("LoadPolicy did not return: the document walk does not terminate on " +
					"a malformed document, so the CLI hangs before any scan begins")
			}
		})
	}
}

// TestTheDocumentCountDoesNotAssertATotalItDidNotFinishCounting pins the
// message against the walk's own limits.
//
// The walk stops at the first document that does not parse, so anything after
// it is never counted. Asserting a total there understated the file: four
// documents with a malformed second reported "contains 2 YAML documents ... the
// other one would be discarded", when three were being discarded.
func TestTheDocumentCountDoesNotAssertATotalItDidNotFinishCounting(t *testing.T) {
	third := "name: Part Three\nversion: \"1.0\"\nrules:\n  cipher:\n    minKeySize: 256\n"
	fourth := "name: Part Four\nversion: \"1.0\"\nrules:\n  cipher:\n    minKeySize: 128\n"

	t.Run("stopped early on a malformed document", func(t *testing.T) {
		path := writePolicyFile(t,
			trivialDocument+"---\nfoo: [unclosed\n---\n"+third+"---\n"+fourth)

		_, err := NewPolicyEvaluator().LoadPolicy(path)
		if err == nil {
			t.Fatal("the file was accepted")
		}
		if !strings.Contains(err.Error(), "at least") {
			t.Errorf("the refusal asserts a total the walk did not finish counting, so it "+
				"understates how much of the file is being discarded: %q", err.Error())
		}
		if strings.Contains(err.Error(), "the other one") {
			t.Errorf("the refusal claims exactly one other document when it stopped "+
				"counting early: %q", err.Error())
		}
	})

	t.Run("counted the whole file", func(t *testing.T) {
		path := writePolicyFile(t, trivialDocument+"---\n"+strictDocument+"---\n"+third)

		_, err := NewPolicyEvaluator().LoadPolicy(path)
		if err == nil {
			t.Fatal("the file was accepted")
		}
		// Here the count IS exact, so hedging would be its own inaccuracy.
		if strings.Contains(err.Error(), "at least") {
			t.Errorf("the refusal hedges a count it completed: %q", err.Error())
		}
		if !strings.Contains(err.Error(), "3 YAML documents") {
			t.Errorf("the refusal does not report the exact count it reached: %q", err.Error())
		}
	})
}

// TestAnInertWarningOnlyValueIsNotCalledAdvisory keeps the refusal's diagnosis
// honest about values as well as keys.
//
// The evaluator gates minValidityDays on > 0 and requirePqcCertificates on true,
// so a zero or a false makes the rule emit nothing at all. Naming it and saying
// it "will stay advisory, reporting a warning" describes behaviour the author
// will never see. Those files get the plain "defines no rules", which is true.
func TestAnInertWarningOnlyValueIsNotCalledAdvisory(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"minValidityDays zero", "name: z\nversion: \"1.0\"\nrules:\n  certificate:\n    minValidityDays: 0\n"},
		{"minValidityDays negative", "name: n\nversion: \"1.0\"\nrules:\n  certificate:\n    minValidityDays: -5\n"},
		{"requirePqcCertificates false", "name: f\nversion: \"1.0\"\nrules:\n  quantum:\n    requirePqcCertificates: false\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)

			_, err := NewPolicyEvaluator().LoadPolicy(path)
			if err == nil {
				t.Fatal("a policy that constrains nothing was accepted")
			}
			if strings.Contains(err.Error(), "advisory") {
				t.Errorf("the refusal says the rule will report a warning, but this value "+
					"makes the evaluator emit nothing at all: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "defines no rules") {
				t.Errorf("the refusal does not give the accurate diagnosis for a rule set to "+
					"its no-op value: %q", err.Error())
			}
		})
	}
}

// TestAWarningOnlyRuleWithAConstrainingValueIsStillNamed is the control for the
// case above. Gating on the value must not stop the real case being named.
func TestAWarningOnlyRuleWithAConstrainingValueIsStillNamed(t *testing.T) {
	path := writePolicyFile(t,
		"name: real\nversion: \"1.0\"\nrules:\n  certificate:\n    minValidityDays: 3650\n")

	_, err := NewPolicyEvaluator().LoadPolicy(path)
	if err == nil {
		t.Fatal("a policy of only warning rules was accepted")
	}
	if !strings.Contains(err.Error(), "certificate.minValidityDays") {
		t.Errorf("the refusal no longer names a warning-only rule that does constrain: %q",
			err.Error())
	}
	if !strings.Contains(err.Error(), "advisory") {
		t.Errorf("the refusal no longer warns that the rule stays advisory: %q", err.Error())
	}
}
