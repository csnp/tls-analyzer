package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
)

// print-policy is the only surface that shows a user the policy schema, and its
// header made a claim about that schema which was false.
//
// It read "Every key below is part of the schema. Any other key is refused."
// while `extends` is accepted by the loader and is not printed, because a
// built-in policy inherits from nothing. So the one place a user can discover
// the schema told them the key did not exist, and the warning-only refusal
// message tells them to use it.

// TestExtendsIsAcceptedByTheLoader establishes the premise. If extends were not
// accepted, the header would have been true and the test below would be
// asserting the wrong thing.
func TestExtendsIsAcceptedByTheLoader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	body := `name: inherits
version: "1.0"
extends: modern
rules:
  certificate:
    minEccKeySize: 256
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	e := analyzer.NewPolicyEvaluator()
	policy, err := e.LoadPolicy(path)
	if err != nil {
		t.Fatalf("extends was refused, so this test's premise is wrong: %v", err)
	}
	if policy.Extends != "modern" {
		t.Fatalf("extends did not survive the load: %q", policy.Extends)
	}
	// It really inherits, rather than merely parsing.
	if policy.Rules.Protocol.MinVersion == "" {
		t.Error("nothing was inherited from the base policy, so extends is not doing what " +
			"the header would be describing")
	}
}

// TestPrintPolicyHeaderDoesNotDenyExtends is the reproduction. A header that
// tells the reader every other key is refused, while naming none of the keys
// that are not refused, is a false statement about the tool's own schema.
func TestPrintPolicyHeaderDoesNotDenyExtends(t *testing.T) {
	header := printPolicyHeader()

	if !strings.Contains(header, "extends") {
		t.Errorf("the print-policy header does not mention 'extends', which the loader "+
			"accepts and this output never shows, so the schema's only discovery surface "+
			"denies a key the refusal messages tell users to reach for.\nheader: %s", header)
	}
}
