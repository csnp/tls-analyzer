package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The policy schema is documented in docs/policies.md, and unknown keys are
// refused at load. A documented example that the loader rejects is worse than
// no example: it is a dead end that looks authoritative, and the reader has no
// other description of the schema to fall back on.
//
// This walks every YAML block in that document and puts it through the real
// loader, so the documentation cannot drift from the parser. It is the same
// shape as asserting that every command a help text cites is a registered
// command.

var yamlBlock = regexp.MustCompile("(?s)```yaml\\n(.*?)```")

func policiesDoc(t *testing.T) string {
	t.Helper()

	// The test binary runs in the package directory, so walk up to the module
	// root rather than assuming a working directory.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "docs", "policies.md")
		if _, err := os.Stat(candidate); err == nil {
			body, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatalf("read %s: %v", candidate, err)
			}
			return string(body)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("docs/policies.md not found, so this test would pass without checking anything")
	return ""
}

func TestEveryPolicyExampleInTheDocsLoads(t *testing.T) {
	doc := policiesDoc(t)

	matches := yamlBlock.FindAllStringSubmatch(doc, -1)
	if len(matches) == 0 {
		t.Fatal("no YAML examples found in docs/policies.md, so this test is vacuous")
	}

	e := NewPolicyEvaluator()
	checked := 0

	for i, m := range matches {
		body := m[1]

		// A block that is not a whole policy is a fragment documenting one rule
		// group or the weights block. It is completed into a loadable policy
		// rather than skipped, because a fragment is where a reader copies a key
		// from, and a key that does not exist is refused now that unknown keys
		// are rejected: leaving fragments unchecked is what let four
		// non-existent keys sit in this document.
		complete := strings.Contains(body, "name:")
		if !complete {
			body = "name: docs-fragment\nversion: \"1.0\"\n" + body
			if !strings.Contains(body, "rules:") {
				// The weights block is valid on its own but sets no rule, and a
				// ruleless policy is refused for its own reasons.
				body += "rules:\n  cipher:\n    minKeySize: 128\n"
			}
		}
		checked++

		t.Run(fmt.Sprintf("block%d-%s", i+1, firstLineOf(body)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			policy, err := e.LoadPolicy(path)
			if err != nil {
				t.Fatalf("YAML block %d in docs/policies.md does not load: %v\n\n%s",
					i+1, err, body)
			}
			if policy.Rules.IsEmpty() {
				t.Fatalf("YAML block %d loads but sets no rules, so the example documents "+
					"a policy nothing can fail:\n\n%s", i+1, body)
			}
		})
	}

	if checked == 0 {
		t.Fatal("no complete policy examples were checked, so this test is vacuous")
	}
}

// TestTheDocumentedInheritanceExampleActuallyOverrides is the specific claim
// the old merge broke. docs/policies.md shows extends with certificate
// overrides, and the merge copied a hand-picked set of rule fields that did not
// include any certificate rule, so the documented example was accepted and
// silently evaluated against the base policy's requirements.
func TestTheDocumentedInheritanceExampleActuallyOverrides(t *testing.T) {
	doc := policiesDoc(t)

	section := doc[strings.Index(doc, "## Policy Inheritance"):]
	m := yamlBlock.FindStringSubmatch(section)
	if m == nil {
		t.Fatal("no YAML example under Policy Inheritance, so this test is vacuous")
	}
	body := m[1]
	if !strings.Contains(body, "extends:") {
		t.Fatalf("the inheritance example no longer uses extends:\n%s", body)
	}

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewPolicyEvaluator()
	policy, err := e.LoadPolicy(path)
	if err != nil {
		t.Fatalf("the documented inheritance example does not load: %v\n\n%s", err, body)
	}

	base, ok := e.GetPolicy(policy.Extends)
	if !ok {
		t.Fatalf("the example extends %q, which is not a built-in policy", policy.Extends)
	}

	// The example has to demonstrate both halves of what extends does, whichever
	// keys it happens to pick: something the file set has to differ from the
	// base, and something the file omitted has to be inherited from it. An
	// example whose overrides coincide with the base's own values would look
	// identical to one whose overrides were discarded, which is the failure the
	// old merge produced.
	if reflect.DeepEqual(policy.Rules, base.Rules) {
		t.Fatalf("the loaded rules are byte-identical to base policy %q's, so either the "+
			"overrides were discarded or the example overrides nothing the base does not "+
			"already require and demonstrates neither", base.Name)
	}

	inherited := reflect.DeepEqual(policy.Rules.Protocol, base.Rules.Protocol) ||
		reflect.DeepEqual(policy.Rules.Cipher, base.Rules.Cipher) ||
		reflect.DeepEqual(policy.Rules.Quantum, base.Rules.Quantum)
	if !inherited {
		t.Fatalf("no rule group was inherited unchanged from %q, so the example does not "+
			"demonstrate inheritance", base.Name)
	}
}

func firstLineOf(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		}
	}
	return "example"
}

// TestEverySchemaKeyIsDocumented is the other direction. The loader refuses any
// key the schema does not define, so the documentation is now the only
// description of what a user may write, and a field added later without a line
// in the docs is a field nobody can discover.
//
// The key list is read from the struct tags rather than restated here, because a
// hand-copied list in a test is a second thing to keep in sync and would agree
// with the docs by being equally stale.
func TestEverySchemaKeyIsDocumented(t *testing.T) {
	doc := policiesDoc(t)

	structs := []reflect.Type{
		reflect.TypeOf(types.Policy{}),
		reflect.TypeOf(types.PolicyRules{}),
		reflect.TypeOf(types.ProtocolRules{}),
		reflect.TypeOf(types.CipherRules{}),
		reflect.TypeOf(types.CertificateRules{}),
		reflect.TypeOf(types.QuantumRules{}),
		reflect.TypeOf(types.ScoringWeights{}),
	}

	checked := 0
	for _, st := range structs {
		for i := 0; i < st.NumField(); i++ {
			tag := st.Field(i).Tag.Get("yaml")
			key, _, _ := strings.Cut(tag, ",")
			if key == "" || key == "-" {
				continue
			}
			checked++

			// The key has to appear as a YAML key, not merely as a word
			// somewhere in the prose.
			if !strings.Contains(doc, key+":") {
				t.Errorf("%s.%s is written as %q in a policy file and appears nowhere in "+
					"docs/policies.md. Unknown keys are refused, so an undocumented key "+
					"is one a user cannot discover and cannot guess.",
					st.Name(), st.Field(i).Name, key)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no schema keys were checked, so this test is vacuous")
	}
}
