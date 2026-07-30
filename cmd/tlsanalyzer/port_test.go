package main

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
)

// TestRuntimeErrorsDoNotPrintTheUsageBlock guards the defect where every error,
// including an unreachable host, printed the one-line message and then the whole
// ~30 line usage block after it, so the line that mattered scrolled away.
func TestRuntimeErrorsDoNotPrintTheUsageBlock(t *testing.T) {
	if !rootCmd.SilenceUsage {
		t.Error("usage is still printed after a runtime error, which buries the error message")
	}
}

// TestFlagErrorsPointAtHelp keeps suppressing usage from creating a dead end: a
// mistyped flag no longer lists the valid ones, so it has to say where to look.
func TestFlagErrorsPointAtHelp(t *testing.T) {
	err := rootCmd.FlagErrorFunc()(rootCmd, errTestFlag{})
	if err == nil {
		t.Fatal("no flag error function is set")
	}
	if !strings.Contains(err.Error(), "--help") {
		t.Errorf("a flag error gives no next step: %q", err.Error())
	}
}

type errTestFlag struct{}

func (errTestFlag) Error() string { return "unknown flag: --nope" }

// TestHelpExplainsTheQuantumReadyGrades guards the defect where the report
// printed "Quantum Ready: Q" with no key anywhere in the output or in --help, so
// a reader could not tell whether Q was a good result.
func TestHelpExplainsTheQuantumReadyGrades(t *testing.T) {
	for _, grade := range []string{"Q+", "Q-", "QV"} {
		if !strings.Contains(rootCmd.Long, grade) {
			t.Errorf("--help does not explain the %s quantum readiness grade", grade)
		}
	}
}

// TestApplyPortOverride guards the defect where -p/--port was declared and
// documented as "overrides port in target" but never read, so
// "tlsanalyzer host -p 8443" silently scanned port 443 and reported a confident
// grade for a port the user never asked about.
func TestApplyPortOverride(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		port     int
		expected string
	}{
		{"bare host", "example.com", 8443, "example.com:8443"},
		{"host with port is overridden", "example.com:4443", 443, "example.com:443"},
		{"same port is a no-op", "example.com:443", 443, "example.com:443"},
		{"ipv4 literal", "192.0.2.1", 8443, "192.0.2.1:8443"},
		{"ipv4 with port", "192.0.2.1:9000", 8443, "192.0.2.1:8443"},
		{"bracketed ipv6 with port", "[2001:db8::1]:9000", 8443, "[2001:db8::1]:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applyPortOverride(tt.target, tt.port); got != tt.expected {
				t.Errorf("applyPortOverride(%q, %d) = %q, want %q",
					tt.target, tt.port, got, tt.expected)
			}
		})
	}
}

// TestApplyPortOverrideDoesNotManglePlainIPv6 checks that a bare IPv6 literal,
// which contains colons that are not a port separator, is not truncated.
func TestApplyPortOverrideDoesNotManglePlainIPv6(t *testing.T) {
	got := applyPortOverride("[2001:db8::1]", 8443)
	if got != "[2001:db8::1]:8443" {
		t.Errorf("applyPortOverride on a bracketed IPv6 literal = %q, want [2001:db8::1]:8443", got)
	}
}

// TestValidateFormat guards the silent fallback where an unrecognized --format
// produced a text report and exit 0, so a pipeline asking for "--format JSON"
// received text and a success code.
func TestValidateFormat(t *testing.T) {
	for _, format := range supportedFormats {
		if err := validateFormat(format); err != nil {
			t.Errorf("validateFormat(%q) rejected a supported format: %v", format, err)
		}
	}

	for _, format := range []string{"JSON", "Text", "xml", "yaml", "bogus", ""} {
		if err := validateFormat(format); err == nil {
			t.Errorf("validateFormat(%q) accepted an unsupported format", format)
		}
	}
}

// TestVersionLiteralsAgree keeps the two version strings from drifting.
//
// The release workflow injects only main.version with -ldflags, so
// scanner.Version is whatever the source says. main stamps its own value onto
// every report, which is why a stale scanner.Version does not reach CLI output,
// but a consumer importing the library reads it directly and would be told a
// version that was never released.
func TestVersionLiteralsAgree(t *testing.T) {
	if version != scanner.Version {
		t.Errorf("cmd/tlsanalyzer reports version %q while internal/scanner reports %q; "+
			"bump both when releasing", version, scanner.Version)
	}
}
