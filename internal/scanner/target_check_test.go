package scanner

import (
	"errors"
	"strings"
	"testing"
)

// These assertions name CheckTarget and the reason constants, which the target
// check introduced, so they cannot compile against the earlier sources. They
// are kept apart from scan_refuses_before_lookup_test.go so that file stays
// buildable against them and fails at run time instead.

// TestCheckTargetAcceptsHostsAddressesAndPorts brackets the rule from the
// accepting side. A check that refused everything would satisfy every refusal
// test, so the edges of what is accepted are pinned here.
func TestCheckTargetAcceptsHostsAddressesAndPorts(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	tests := []struct {
		target   string
		wantHost string
		wantPort int
	}{
		{"example.com", "example.com", 443},
		{"Example.COM", "Example.COM", 443},
		{"localhost", "localhost", 443},
		{"_service.example", "_service.example", 443},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", 443},
		{"example.com.", "example.com.", 443},
		{"a1-b2.example:8443", "a1-b2.example", 8443},
		{label63 + ".example", label63 + ".example", 443},
		{"example.com:1", "example.com", 1},
		{"example.com:65535", "example.com", 65535},
		{"192.0.2.1", "192.0.2.1", 443},
		{"192.0.2.1:8443", "192.0.2.1", 8443},
		{"[2001:db8::1]", "2001:db8::1", 443},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
		{"[::1]:443", "::1", 443},
		// A link-local address needs its zone to be reached, and 0.4.1 scanned
		// one. The zone is kept in the host, where the dialer reads it.
		{"[fe80::1%lo0]:8443", "fe80::1%lo0", 8443},
		{"[fe80::1%eth0]", "fe80::1%eth0", 443},
		{"[fe80::1%12]:443", "fe80::1%12", 443},
		{"[fe80::1%br-1a2b3c4d5e6f]:443", "fe80::1%br-1a2b3c4d5e6f", 443},
	}

	for _, tt := range tests {
		host, port, err := CheckTarget(tt.target)
		if err != nil {
			t.Errorf("CheckTarget(%q) refused a valid target: %v", tt.target, err)
			continue
		}
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("CheckTarget(%q) = %q, %d; want %q, %d",
				tt.target, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

// TestCheckTargetRefusesEverythingElseWithAFixedReason pins each refusal to one
// reason from the fixed set. The reason is the whole message: nothing in it
// comes from the target, which is what lets it be printed for a line of a
// file that may hold anything.
func TestCheckTargetRefusesEverythingElseWithAFixedReason(t *testing.T) {
	label64 := strings.Repeat("a", 64)
	tests := []struct {
		target string
		reason string
	}{
		{"", ReasonEmpty},
		{"   ", ReasonEmpty},
		{"KEY=value", ReasonNotATarget},
		{"two words", ReasonNotATarget},
		{" example.com", ReasonNotATarget},
		{label64 + ".example", ReasonNotATarget},
		{"-lead.example", ReasonNotATarget},
		{"trail-.example", ReasonNotATarget},
		{"a..example", ReasonNotATarget},
		{".example", ReasonNotATarget},
		{".", ReasonNotATarget},
		{"12345", ReasonNotATarget},
		{"192.0.2.256", ReasonNotATarget},
		{"2001:db8::1", ReasonNotATarget},
		{"[2001:db8::1", ReasonNotATarget},
		{"[2001:db8::1]x", ReasonNotATarget},
		{"[192.0.2.1]:443", ReasonNotATarget},
		{"[not-an-address]", ReasonNotATarget},
		{"fe80::1%lo0", ReasonNotATarget},
		{"[fe80::1%]:443", ReasonNotATarget},
		// A zone that is not an interface name or number is refused with a
		// reason that says so, never with one that denies it is an address.
		{"[fe80::1%a=b]:443", ReasonZone},
		{"[fe80::1%two words]:443", ReasonZone},
		{"[fe80::1%lo0/x]", ReasonZone},
		{"[fe80::1%" + strings.Repeat("a", 16) + "]:443", ReasonZone},
		{"[fe80::1%exa\x1b[2Kmple]:443", ReasonZone},
		{":443", ReasonNotATarget},
		{"user@example.com", ReasonNotATarget},
		{"example.com/path", ReasonNotATarget},
		{"exa\x1b[2Kmple.com", ReasonNotATarget},
		{"example.com:", ReasonPort},
		{"example.com:0", ReasonPort},
		{"example.com:-1", ReasonPort},
		{"example.com:+443", ReasonPort},
		{"example.com: 443", ReasonPort},
		{"example.com:65536", ReasonPort},
		{"example.com:99999999999999999999", ReasonPort},
		{"example.com:abc", ReasonPort},
		{"key: value", ReasonPort},
		{"[2001:db8::1]:", ReasonPort},
		{"[2001:db8::1]:70000", ReasonPort},
		{"https://example.com", ReasonURL},
		{"http://user:FAKE@example.com/", ReasonURL},
	}

	for _, tt := range tests {
		_, _, err := CheckTarget(tt.target)
		if err == nil {
			t.Errorf("CheckTarget(%q) accepted it", tt.target)
			continue
		}
		if err.Error() != tt.reason {
			t.Errorf("CheckTarget(%q) gave %q; want exactly %q", tt.target, err.Error(), tt.reason)
		}
		var targetErr *TargetError
		if !errors.As(err, &targetErr) {
			t.Errorf("CheckTarget(%q) returned %T, not a *TargetError", tt.target, err)
		}
	}
}

// TestParseTargetIsTheSameRule keeps the scanner's own parse from drifting away
// from the check the command applies: one rule, two consumers.
func TestParseTargetIsTheSameRule(t *testing.T) {
	for _, target := range []string{"KEY=value", "key: value", "https://example.com", "", "[2001:db8::1]", "example.com:8443"} {
		cHost, cPort, cErr := CheckTarget(target)
		pHost, pPort, pErr := parseTarget(target)
		if cHost != pHost || cPort != pPort || (cErr == nil) != (pErr == nil) {
			t.Errorf("parseTarget(%q) = %q, %d, %v but CheckTarget gives %q, %d, %v",
				target, pHost, pPort, pErr, cHost, cPort, cErr)
		}
	}
}
