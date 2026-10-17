package sanitize

import "testing"

// TestShellWordQuotesTheAddressesZshWouldGlob covers the -connect addresses
// the scan error and the policy Fix print. zsh reads the brackets of an IPv6
// address as a glob and refuses the command with "no matches found", with a
// zone or without one, so those are quoted. A host name or an IPv4 address
// with its port is left as it is, and a single quote inside a quoted word is
// closed, escaped and reopened.
func TestShellWordQuotesTheAddressesZshWouldGlob(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"example.com:443", "example.com:443"},
		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"[::1]:56128", "'[::1]:56128'"},
		{"[fe80::1%en0]:8443", "'[fe80::1%en0]:8443'"},
		{"it's", `'it'\''s'`},
		{"", "''"},
	} {
		if got := ShellWord(c.in); got != c.want {
			t.Errorf("ShellWord(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
