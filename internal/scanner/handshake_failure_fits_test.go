package scanner

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// The error for a scan that completed no handshake ends with one openssl
// s_client command per key exchange group this scanner does not offer, and
// each command repeats the address that the error's headline gives. The CLI
// prints at most sanitize.MaxReportDetail bytes of a scan error and cuts the
// rest, so a long address pushed the last command past the cut, and with it the
// only place its group was named. Run with GODEBUG=fips140=on,tlsmlkem=0, where the scanner
// offers none of the three hybrid groups, a scan of
// scanner-target-example.localhost on a five-digit port ended in
// "-groups SecP256r1MLKEM768 and openssl s_client -connect sca..." and never
// named SecP384r1MLKEM1024.
//
// The mutation each test is written to catch:
//   - the groups are named only in the commands, as before this change:
//     TestAHandshakeFailureNamesEveryGroupWithinTheCut, and
//     TestFIPSChildScanNamesTheHybridGroupsItCannotOffer through a long
//     spelling of 127.0.0.1. The second was observed to fail on the earlier
//     code, which has no handshakeFailureMessage for the first to call.
//   - the groups are named after the sentence saying whether the server is
//     reachable rather than before it, so the longest host names push them
//     past the cut: TestAHandshakeFailureNamesEveryGroupWithinTheCut.
//   - every command is kept, so the cut ends one part-way:
//     TestAHandshakeFailureNamesEveryGroupWithinTheCut.
//   - a command that fits is left out: after the first command,
//     TestAHandshakeFailureNamesEveryGroupWithinTheCut; the first command,
//     TestAHandshakeFailureGivesTheCommandsThatFit and
//     TestFIPSChildScanNamesTheHybridGroupsItCannotOffer.
//   - the groups are named ahead of the commands even when every command fits:
//     TestAHandshakeFailureGivesTheCommandsThatFit.
//   - the sentence naming the groups and the cipher suites is made longer, so
//     that a 47-byte IPv6 address keeps no whole command after the alerts with
//     the longest text: TestAHandshakeFailureKeepsACommandForA47ByteIPv6Address.
//     It was observed to fail with the cipher suites introduced by "such as".

// TestAHandshakeFailureNamesEveryGroupWithinTheCut builds the error for host
// names of every length the scanner accepts: 1 to 253 bytes at port 443 and
// port 65535, and 253 bytes with a trailing dot at port 65535. It also builds
// it for ::1 at port 443 and for two IPv6 addresses written at their longest,
// with the longest zone, at port 65535. For the 254-byte name and the IPv6
// addresses the handshake ends with each of the 256 TLS alert values or with
// the server closing the connection; for the other names, with the alert
// crypto/tls reports for a server sharing no key exchange group, the alert
// whose text is longest, or the server closing the connection. Read as the CLI
// prints it, the error opens with its headline, names every group this scanner
// does not offer, gives each openssl command whole and in the groups' order,
// and after the first command leaves one out only when it would not fit.
func TestAHandshakeFailureNamesEveryGroupWithinTheCut(t *testing.T) {
	x25519, p256, p384 := tlsGroups[groupX25519MLKEM768].name,
		tlsGroups[groupSecP256r1MLKEM768].name, tlsGroups[groupSecP384r1MLKEM1024].name
	groupSets := [][]string{
		{x25519, p256, p384}, // GODEBUG=fips140=on,tlsmlkem=0
		{p256, p384},         // a Go 1.25 build
		{x25519},             // a single group, named in the singular
	}

	alerts := make([]error, 256)
	longest := 0
	for a := range alerts {
		alerts[a] = &net.OpError{Op: "remote error", Err: tls.AlertError(a)}
		if len(alerts[a].Error()) > len(alerts[longest].Error()) {
			longest = a
		}
	}
	t.Logf("the alert with the longest text reads %q", alerts[longest])
	closed := []error{io.EOF, io.ErrUnexpectedEOF}
	every := append(slices.Clone(alerts), closed...)
	some := append([]error{alerts[40], alerts[longest]}, closed...)

	type addressCase struct {
		target  string
		reasons []error
	}
	cases := []addressCase{
		{hostOfLength(253) + ".:65535", every},
		{"[::1]:443", every},
		{"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%abcdefghijklmno]:65535", every},
		{"[0000:0000:0000:0000:0000:ffff:255.255.255.255%abcdefghijklmno]:65535", every},
	}
	for n := 1; n <= 253; n++ {
		cases = append(cases,
			addressCase{hostOfLength(n) + ":443", some}, addressCase{hostOfLength(n) + ":65535", some})
	}

	failures := 0
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf(format, args...)
		if failures++; failures == 10 {
			t.FailNow()
		}
	}
	for _, c := range cases {
		host, port, err := CheckTarget(c.target)
		if err != nil {
			t.Fatalf("the scanner refuses %q, so this test should not cover it: %v", c.target, err)
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		connect := sanitize.ShellWord(addr)
		for _, groups := range groupSets {
			for _, reason := range c.reasons {
				msg := handshakeFailureMessage(addr, reason, groups)
				printed := sanitize.WrapError(errors.New(msg)).Error()

				headline := "TLS handshake with " + addr + " failed (" + reason.Error() + ")."
				if !strings.HasPrefix(printed, headline) {
					fail("for %s after %q, the error does not open with %q: %q",
						addr, reason, headline, printed)
				}
				for _, group := range groups {
					if !strings.Contains(printed, group) {
						fail("for %s after %q, the error as the CLI prints it does not name %s: %q",
							addr, reason, group, printed)
					}
				}

				whole, cut := opensslCommands(printed, connect, groups)
				if cut != "" {
					fail("for %s after %q, the CLI's cut ends the error inside an openssl "+
						"command: %q", addr, reason, cut)
				}
				if len(whole) > len(groups) || !slices.Equal(whole, groups[:len(whole)]) {
					fail("for %s after %q, the commands check %v, not the groups %v in order: %q",
						addr, reason, whole, groups, printed)
					continue
				}
				if n := len(whole); n > 0 && n < len(groups) {
					next := "openssl s_client -connect " + connect + " -groups " + groups[n]
					if len(msg)+len(" and ")+len(next) <= sanitize.MaxReportDetail {
						fail("for %s after %q, the error leaves out %q, which fits: %q",
							addr, reason, next, msg)
					}
				}
			}
		}
	}
}

// TestAHandshakeFailureGivesTheCommandsThatFit pins the commands for three
// addresses after the alert crypto/tls reports for a server that shares no key
// exchange group with the client, for a build offering none of the three
// hybrid groups. A short address gets every command, with the groups named only
// in them, as before. The host name from the report gets a whole command for
// the first group and the whole error within the CLI's limit.
func TestAHandshakeFailureGivesTheCommandsThatFit(t *testing.T) {
	alert := &net.OpError{Op: "remote error", Err: tls.AlertError(40)}
	if got, want := alert.Error(), "remote error: tls: handshake failure"; got != want {
		t.Fatalf("alert 40 reads %q here, not %q as crypto/tls reports it from a server", got, want)
	}
	groups := []string{
		tlsGroups[groupX25519MLKEM768].name,
		tlsGroups[groupSecP256r1MLKEM768].name,
		tlsGroups[groupSecP384r1MLKEM1024].name,
	}

	for _, addr := range []string{"127.0.0.1:65535", "[::1]:65535"} {
		msg := handshakeFailureMessage(addr, alert, groups)
		whole, cut := opensslCommands(msg, sanitize.ShellWord(addr), groups)
		if cut != "" || !slices.Equal(whole, groups) || len(msg) > sanitize.MaxReportDetail {
			t.Errorf("for %s the error should give a whole command for each of %v within %d "+
				"bytes, got %d bytes: %q", addr, groups, sanitize.MaxReportDetail, len(msg), msg)
		}
		if strings.Contains(msg, "This scanner does not offer") {
			t.Errorf("for %s every command fits, so the groups need no naming ahead of "+
				"them: %q", addr, msg)
		}
	}

	addr := "scanner-target-example.localhost:65535"
	msg := handshakeFailureMessage(addr, alert, groups)
	printed := sanitize.WrapError(errors.New(msg)).Error()
	t.Logf("error for %s, %d bytes: %s", addr, len(msg), msg)
	if printed != msg {
		t.Errorf("for %s the CLI cuts the error: %q", addr, printed)
	}
	for _, group := range groups {
		if !strings.Contains(printed, group) {
			t.Errorf("for %s the error does not name %s: %q", addr, group, printed)
		}
	}
	whole, _ := opensslCommands(msg, sanitize.ShellWord(addr), groups)
	if len(whole) == 0 || whole[0] != groups[0] {
		t.Errorf("for %s the error should give a whole command for %s, which fits: %q",
			addr, groups[0], msg)
	}
}

// TestAHandshakeFailureKeepsACommandForA47ByteIPv6Address builds the error for
// three IPv6 addresses that are 47 bytes with their brackets and port 65535:
// one written with all eight groups, one with a zone and one ending in an IPv4
// address. The handshake ends with each of the 256 TLS alert values or with the
// server closing the connection, for each set of groups not offered that
// TestAHandshakeFailureNamesEveryGroupWithinTheCut uses. Read as the CLI prints
// it, every error gives at least one whole openssl command. With the cipher
// suites introduced by "such as" and the three hybrid groups not offered, as
// under GODEBUG=fips140=on,tlsmlkem=0, none was given after alert 113 (bad
// certificate status response) or alert 121 (encrypted client hello required).
func TestAHandshakeFailureKeepsACommandForA47ByteIPv6Address(t *testing.T) {
	x25519, p256, p384 := tlsGroups[groupX25519MLKEM768].name,
		tlsGroups[groupSecP256r1MLKEM768].name, tlsGroups[groupSecP384r1MLKEM1024].name
	groupSets := [][]string{{x25519, p256, p384}, {p256, p384}, {x25519}}

	reasons := []error{io.EOF, io.ErrUnexpectedEOF}
	for a := range 256 {
		reasons = append(reasons, &net.OpError{Op: "remote error", Err: tls.AlertError(a)})
	}

	for _, target := range []string{
		"[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
		"[fe80::ffff:ffff:ffff:ffff%abcdefghijklm]:65535",
		"[0000:0000:0000:0000:0000:ffff:1.20.30.4]:65535",
	} {
		host, port, err := CheckTarget(target)
		if err != nil {
			t.Fatalf("the scanner refuses %q, so this test should not cover it: %v", target, err)
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if len(addr) != 47 {
			t.Fatalf("%s is %d bytes, not the 47 this test is about", addr, len(addr))
		}
		connect := sanitize.ShellWord(addr)

		longest := ""
		for _, groups := range groupSets {
			for _, reason := range reasons {
				msg := handshakeFailureMessage(addr, reason, groups)
				if len(msg) > len(longest) {
					longest = msg
				}
				printed := sanitize.WrapError(errors.New(msg)).Error()
				whole, cut := opensslCommands(printed, connect, groups)
				if len(whole) == 0 {
					t.Errorf("for %s after %q, the error as the CLI prints it gives no whole "+
						"openssl command for %v, %d bytes: %q", addr, reason, groups, len(msg), printed)
				}
				if cut != "" {
					t.Errorf("for %s after %q, the CLI's cut ends the error inside an openssl "+
						"command: %q", addr, reason, cut)
				}
			}
		}
		t.Logf("the longest error for %s is %d bytes: %s", addr, len(longest), longest)
	}
}

// hostOfLength is a host name of exactly n bytes, in labels of at most 50
// letters, so every label is a legal DNS label and none is empty.
func hostOfLength(n int) string {
	var labels []string
	for remaining := n; remaining > 0; {
		size := min(50, remaining)
		if remaining-size == 1 {
			size-- // leave room for a dot and a one-letter label
		}
		labels = append(labels, strings.Repeat("a", size))
		remaining -= size
		if remaining > 0 {
			remaining-- // the dot
		}
	}
	return strings.Join(labels, ".")
}

// opensslCommands reads the openssl commands in msg. Each must be a whole
// "openssl s_client -connect <connect> -groups <group>" for one of groups,
// followed by " and " or by the end of msg. It returns the groups of the whole
// commands in order, and the text from the first command that is not whole,
// which is empty when every command is.
func opensslCommands(msg, connect string, groups []string) (whole []string, cut string) {
	rest := msg
	for {
		i := strings.Index(rest, "openssl s_client")
		if i < 0 {
			return whole, ""
		}
		rest = rest[i:]
		matched := ""
		for _, group := range groups {
			cmd := "openssl s_client -connect " + connect + " -groups " + group
			if rest == cmd || strings.HasPrefix(rest, cmd+" and ") {
				matched = group
				rest = rest[len(cmd):]
				break
			}
		}
		if matched == "" {
			return whole, rest
		}
		whole = append(whole, matched)
	}
}
