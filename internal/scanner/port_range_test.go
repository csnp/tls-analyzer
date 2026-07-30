package scanner

import (
	"strings"
	"testing"
)

// TestParseTargetRejectsAPortOutsideTheTCPRange guards the defect where an
// out-of-range port was accepted, reached the dialer, and produced
// "no TLS connection could be established to example.com:-5 (host unreachable,
// port closed, or not speaking TLS)". That message describes the host, so a
// rejected argument read as a finding about the target.
//
// parseTarget is the one place the -p/--port flag and a port written into the
// target both arrive, so validating here covers both routes.
func TestParseTargetRejectsAPortOutsideTheTCPRange(t *testing.T) {
	for _, target := range []string{
		"example.com:0",
		"example.com:-1",
		"example.com:-5",
		"example.com:65536",
		"example.com:70000",
	} {
		if _, port, err := parseTarget(target); err == nil {
			t.Errorf("parseTarget(%q) accepted an out-of-range port and returned %d",
				target, port)
		}
	}
}

// TestParseTargetRejectsANonNumericPort guards the silent fallback: a port that
// was not a number left the parsed value at 443, so the report named the target
// the user typed and scanned a port they never asked for. Same class as the
// --format fallback fixed in 0.3.0.
func TestParseTargetRejectsANonNumericPort(t *testing.T) {
	for _, target := range []string{"example.com:abc", "example.com:https"} {
		_, port, err := parseTarget(target)
		if err == nil {
			t.Errorf("parseTarget(%q) returned port %d with no error, so an unusable "+
				"port was reinterpreted as the default rather than refused", target, port)
			continue
		}

		// The message has to quote what was rejected. Falling through to the
		// range check instead would report "invalid port 0", which names a value
		// the user never typed.
		offending := target[strings.LastIndex(target, ":")+1:]
		if !strings.Contains(err.Error(), offending) {
			t.Errorf("parseTarget(%q) failed with %q, which does not name the rejected port %q",
				target, err, offending)
		}
	}

	if _, port, err := parseTarget("example.com:"); err == nil {
		t.Errorf("parseTarget(\"example.com:\") returned port %d with no error; a colon "+
			"with no port after it fell back to the default", port)
	}
}

// TestParseTargetAcceptsValidTargets brackets the range from the other side. An
// extreme fixture alone cannot detect a cutoff that has been loosened or
// tightened by one, and a validator that refuses everything would satisfy the
// rejection tests above.
func TestParseTargetAcceptsValidTargets(t *testing.T) {
	tests := []struct {
		target   string
		wantHost string
		wantPort int
	}{
		{"example.com", "example.com", 443},
		{"example.com:443", "example.com", 443},
		{"example.com:1", "example.com", 1},
		{"example.com:65535", "example.com", 65535},
		{"example.com:8443", "example.com", 8443},
		{"192.0.2.1:8443", "192.0.2.1", 8443},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
	}

	for _, tt := range tests {
		host, port, err := parseTarget(tt.target)
		if err != nil {
			t.Errorf("parseTarget(%q) refused a valid target: %v", tt.target, err)
			continue
		}
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("parseTarget(%q) = %q, %d; want %q, %d",
				tt.target, host, port, tt.wantHost, tt.wantPort)
		}
	}
}
