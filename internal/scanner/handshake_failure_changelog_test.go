package scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// TestTheChangelogGivesTheHandshakeFailureSizesThisTreeBuilds holds the
// figures the 0.5.0 entries of CHANGELOG.md give for the error of a scan that
// completed no TLS handshake to the error handshakeFailureMessage builds after
// a handshake_failure alert: its size for 127.0.0.1 and ::1 on a five-digit
// port, with and without GODEBUG=tlsmlkem=0, and the longest address for which
// both commands of a default build fit within the CLI's cut.
//
// Those entries gave figures measured before the error gained its sentence
// about cipher suites, which made each of those errors 28 bytes longer, and
// nothing compared them with the error when it did: 398, 390 and 467 bytes,
// where the error was 426, 418 and 495, and room for every command up to a
// host and port of 49 characters and an IPv6 address and port of 47, where it
// was 39 and 38.
//
// The entries describe the build of the release whose section they are in, so
// the figures are checked while the 0.5.0 section opens the changelog, and the
// test is skipped once a later section, such as an [Unreleased] one, opens it.
//
// The mutation it is written to catch: the error's wording changes and these
// figures do not. It was observed to fail on the figures measured before the
// cipher suite sentence, and on the code from before that sentence with the
// figures given now, where it builds 398, 390 and 467 bytes, 49 and 47.
func TestTheChangelogGivesTheHandshakeFailureSizesThisTreeBuilds(t *testing.T) {
	heading, section := changelogHead(t)
	if !strings.HasPrefix(heading, "## [0.5.0]") {
		t.Skipf("CHANGELOG.md opens with %q, not the 0.5.0 section, so the 0.5.0 entries "+
			"may describe a build this tree no longer is", heading)
	}

	alert := &net.OpError{Op: "remote error", Err: tls.AlertError(40)}
	if got, want := alert.Error(), "remote error: tls: handshake failure"; got != want {
		t.Fatalf("alert 40 reads %q here, not %q as crypto/tls reports it from a server", got, want)
	}
	x25519, p256, p384 := tlsGroups[groupX25519MLKEM768].name,
		tlsGroups[groupSecP256r1MLKEM768].name, tlsGroups[groupSecP384r1MLKEM1024].name
	two := []string{p256, p384}           // the groups a default build does not offer
	three := []string{x25519, p256, p384} // GODEBUG=tlsmlkem=0

	// size is the length of the error as the CLI prints it, which the entries
	// give for errors that hold every command and name each group only there.
	size := func(addr string, groups []string) int {
		t.Helper()
		printed := printedHandshakeFailure(addr, alert, groups)
		if !givesEveryCommand(printed, addr, groups) {
			t.Errorf("for %s the error does not give a whole command for each of %v: %q",
				addr, groups, printed)
		}
		for _, group := range groups {
			if n := strings.Count(printed, group); n != 1 {
				t.Errorf("for %s the error names %s %d times, not once in its command: %q",
					addr, group, n, printed)
			}
		}
		return len(printed)
	}
	v4, v6 := "127.0.0.1:65535", "[::1]:65535"
	hostName := func(n int) string { return hostOfLength(n-len(":65535")) + ":65535" }

	// An IPv4 address and port is at most 21 bytes, shorter than the host names
	// that get both commands, so the entry's limit holds for every one of them.
	if longest := "255.255.255.255:65535"; !givesEveryCommand(
		printedHandshakeFailure(longest, alert, two), longest, two) {
		t.Errorf("for %s the error does not give a whole command for each of %v", longest, two)
	}

	claims := []struct {
		words   string // as the changelog words it, with %d for each figure
		figures []any
	}{
		{"the message for the address 127.0.0.1 and a five-digit port is %d bytes",
			[]any{size(v4, two)}},
		{"so against that server both commands fit for a host name or an IPv4 address " +
			"and port of up to %d characters",
			[]any{longestWithEveryCommand(t, 7, 259, hostName, alert, two)}},
		{"the message for a five-digit port is %d bytes, so both commands fit for an " +
			"IPv6 address and port of up to %d characters",
			[]any{size(v6, two), longestWithEveryCommand(t, 23, 63, ipv6TargetOfLength, alert, two)}},
		{"after a handshake_failure alert on a five-digit port, it is %d bytes for " +
			"`127.0.0.1` and %d bytes for `::1`, and %d bytes for `127.0.0.1` with " +
			"`GODEBUG=tlsmlkem=0`",
			[]any{size(v4, two), size(v6, two), size(v4, three)}},
	}
	for _, c := range claims {
		want := fmt.Sprintf(c.words, c.figures...)
		if strings.Contains(section, want) {
			continue
		}
		if said := wordsWithFigures(c.words).FindString(section); said != "" {
			t.Errorf("the 0.5.0 section of CHANGELOG.md says %q, where this tree builds %q", said, want)
		} else {
			t.Errorf("the 0.5.0 section of CHANGELOG.md does not say %q, the figures this "+
				"tree builds", want)
		}
	}
}

// changelogHead returns the heading of the section CHANGELOG.md opens with,
// and the text of that section with each run of white space as one space, so
// a sentence reads the same wherever its lines wrap.
func changelogHead(t *testing.T) (heading, text string) {
	t.Helper()
	path := filepath.Join(repoRoot(t), "CHANGELOG.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "## ") {
			if heading != "" {
				break
			}
			heading = line
			continue
		}
		if heading != "" {
			lines = append(lines, line)
		}
	}
	if heading == "" {
		t.Fatalf("%s has no section heading", path)
	}
	return heading, strings.Join(strings.Fields(strings.Join(lines, " ")), " ")
}

// wordsWithFigures matches words with any figure where they hold %d, so a
// failure can quote what the changelog says instead.
func wordsWithFigures(words string) *regexp.Regexp {
	parts := strings.Split(words, "%d")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return regexp.MustCompile(strings.Join(parts, `\d+`))
}

// longestWithEveryCommand returns the length of the longest target of from to
// to bytes, as target(n) writes them, whose error after reason gives a whole
// command for each of groups as the CLI prints it. The targets that get every
// command must be exactly those up to that length, and the length at which the
// commands stop fitting must lie inside the range.
func longestWithEveryCommand(t *testing.T, from, to int, target func(int) string,
	reason error, groups []string) int {
	t.Helper()
	longest := from - 1
	for n := from; n <= to; n++ {
		host, port, err := CheckTarget(target(n))
		if err != nil {
			t.Fatalf("the scanner refuses %q, so this test should not count it: %v", target(n), err)
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if len(addr) != n {
			t.Fatalf("%s is %d bytes, not %d", addr, len(addr), n)
		}
		if !givesEveryCommand(printedHandshakeFailure(addr, reason, groups), addr, groups) {
			continue
		}
		if longest != n-1 {
			t.Fatalf("the error for the %d-byte %s gives every command, and the error for a "+
				"%d-byte target does not", n, addr, longest+1)
		}
		longest = n
	}
	if longest < from || longest == to {
		t.Fatalf("of the targets from %d to %d bytes, those up to %d bytes get every command, "+
			"so this range does not show where the commands stop fitting", from, to, longest)
	}
	return longest
}

// ipv6TargetOfLength is a bracketed IPv6 address and port 65535 of n bytes, for
// n from 23 to 63: eight groups of one to four digits, 15 to 39 bytes, and from
// 48 bytes a zone of 1 to 15 letters, the longest zone the scanner accepts.
func ipv6TargetOfLength(n int) string {
	inside := n - len("[]:65535")
	addrLen, zone := inside, ""
	switch {
	case inside == 40: // a zone needs a letter after its %
		addrLen, zone = 38, "%z"
	case inside > 40:
		addrLen, zone = 39, "%"+strings.Repeat("z", inside-40)
	}
	digits := addrLen - 7 // the seven colons
	groups := make([]string, 8)
	for i := range groups {
		d := min(4, digits-(7-i)) // each later group keeps one digit
		groups[i] = strings.Repeat("0", d-1) + "1"
		digits -= d
	}
	return "[" + strings.Join(groups, ":") + zone + "]:65535"
}

// printedHandshakeFailure is the error for a handshake with addr that failed
// with reason, as the CLI prints it.
func printedHandshakeFailure(addr string, reason error, notOffered []string) string {
	return sanitize.WrapError(errors.New(handshakeFailureMessage(addr, reason, notOffered))).Error()
}

// givesEveryCommand reports whether printed gives a whole openssl command for
// each of groups, in their order.
func givesEveryCommand(printed, addr string, groups []string) bool {
	whole, cut := opensslCommands(printed, sanitize.ShellWord(addr), groups)
	return cut == "" && slices.Equal(whole, groups)
}
