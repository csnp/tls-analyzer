package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestAScrubbedErrorStillUnwraps
//
// stderr shares the terminal with the report, and the error text carries the
// target back, which may have come from a --targets file somebody else wrote.
// Scrubbing it by rebuilding the message with %s would have been simpler and
// would have broken the exit code: main uses errors.As to tell a policy-gate
// failure (exit 2) from a scan failure (exit 1), and this tool's own CI guidance
// documents that difference. So the wrapper has to do both, and both halves are
// asserted here rather than one.
func TestAScrubbedErrorStillUnwraps(t *testing.T) {
	gate := &policyGateError{message: "policy not satisfied by example.com"}
	wrapped := fmt.Errorf("scan failed: %w", scrubbedError{gate})

	var found *policyGateError
	if !errors.As(wrapped, &found) {
		t.Fatal("errors.As no longer finds the policy gate error through the scrubber, " +
			"so a policy failure would exit 1 instead of 2")
	}
	if found.message != gate.message {
		t.Errorf("unwrapping produced a different error: %q", found.message)
	}
}

// TestAScrubbedErrorCollapsesControlCharacters is the other half.
//
// A test asserting only the unwrapping would pass against a wrapper that does
// no scrubbing at all, which is the whole point of the type.
func TestAScrubbedErrorCollapsesControlCharacters(t *testing.T) {
	hostile := errors.New("invalid target: address \x1b[2K\x1b[1AFORGED TLS Security: A+ (100/100).invalid:443")
	got := scrubbedError{hostile}.Error()

	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("a raw escape byte reached stderr: %q", got)
	}
	if !strings.Contains(got, "invalid target") {
		t.Errorf("scrubbing lost the tool's own words: %q", got)
	}
}

// TestTheScrubbedErrorIsActuallyUsed guards against the wrapper existing and not
// being applied, which is the shape of a fix that ships inert.
func TestTheScrubbedErrorIsActuallyUsed(t *testing.T) {
	hostile := errors.New("cannot resolve \x1b[1Aforged")
	// The composition scanSingleTarget performs.
	wrapped := fmt.Errorf("scan failed: %w", scrubbedError{hostile})

	if strings.ContainsRune(wrapped.Error(), 0x1b) {
		t.Errorf("the composed error still carries a raw escape byte: %q", wrapped.Error())
	}
	if !errors.Is(wrapped, hostile) {
		t.Error("the original error is no longer reachable through the chain")
	}
}
