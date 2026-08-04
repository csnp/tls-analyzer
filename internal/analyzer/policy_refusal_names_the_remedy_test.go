package analyzer

import (
	"strings"
	"testing"
)

// A refusal has to leave the reader able to fix their file. These pin the parts
// of the warning-only refusal that a fresh reader found misleading.
//
// The message said "a compliant verdict from it would mean nothing" and then
// offered two remedies. Following either one produces a file that loads and
// reports COMPLIANT with exit 0 while the rule the author wrote still cannot
// fail, so the remedy moved the false assurance rather than removing it.

// TestTheWarningOnlyRefusalSaysTheRuleStaysAdvisory is the reproduction.
func TestTheWarningOnlyRefusalSaysTheRuleStaysAdvisory(t *testing.T) {
	path := writePolicyFile(t, `name: pqc certs
version: "1.0"
rules:
  quantum:
    requirePqcCertificates: true
`)

	e := NewPolicyEvaluator()
	_, err := e.LoadPolicy(path)
	if err == nil {
		t.Fatal("a policy of only warning rules loaded")
	}
	msg := err.Error()

	// It must name the rule, offer a remedy, AND say the rule stays advisory
	// after the remedy. The first two without the third is the misleading shape.
	for _, want := range []string{
		"quantum.requirePqcCertificates",
		"extends",
		"advisory",
		"exit code",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q, so a reader who follows it still gets "+
				"a green exit 0 for a rule they believe they are gating on.\nmessage: %s",
				want, msg)
		}
	}
}

// TestTheWarningOnlyRefusalNamesEveryOffendingRule keeps the message specific
// when a file writes both of them, rather than naming one and leaving the reader
// to discover the second by trial.
func TestTheWarningOnlyRefusalNamesEveryOffendingRule(t *testing.T) {
	path := writePolicyFile(t, `name: both
version: "1.0"
rules:
  certificate:
    minValidityDays: 3650
  quantum:
    requirePqcCertificates: true
`)

	e := NewPolicyEvaluator()
	_, err := e.LoadPolicy(path)
	if err == nil {
		t.Fatal("a policy of only warning rules loaded")
	}
	for _, want := range []string{"certificate.minValidityDays", "quantum.requirePqcCertificates"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s, though the file writes it.\nmessage: %s",
				want, err.Error())
		}
	}
}
