package scanner

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// Run with GODEBUG=fips140=on, crypto/tls leaves X25519 out of every
// ClientHello, because FIPS 140-3 mode does not allow it. The scan decided which
// groups it could probe by reading a ClientHello for the three hybrid groups
// only, so it probed X25519 anyway and every probe failed. A server offering
// X25519MLKEM768 and X25519 was reported with X25519MLKEM768 alone, and the
// coverage note named SecP256r1MLKEM768 and SecP384r1MLKEM1024 but not X25519.
// For a server offering only X25519, the handshake failure named those two
// groups as the ones this scanner does not offer, and not X25519.
//
// The mutation these tests are written to catch: groupsNotOffered reads only
// the three hybrid groups, as before this change. On that code
// TestFIPSChildListsX25519AsNotProbed was observed to fail, and in the same
// child process TestGroupsNotOfferedMatchesAHandshake and
// TestAGroupThisBuildCannotNegotiateIsReportedNotProbed, each over X25519.

// fipsServersEnv carries the ports of the servers that
// TestAFIPSBuildListsX25519AsNotProbed starts to its child process, separated
// by a comma.
const fipsServersEnv = "TLS_ANALYZER_TEST_FIPS_SERVERS"

// TestAFIPSBuildListsX25519AsNotProbed is the reproduction of "scanner reports
// X25519 absent under GODEBUG=fips140=on instead of listing it as not probed".
// This process, which is not in FIPS 140-3 mode, serves the report's two
// servers: one offering X25519MLKEM768 and X25519, and one offering only
// X25519. A child process started with GODEBUG=fips140=on scans them, since
// FIPS mode is fixed when a process starts. The child also runs the tests that
// compare the groups listed as not offered with real handshakes, which in FIPS
// mode cover X25519.
func TestAFIPSBuildListsX25519AsNotProbed(t *testing.T) {
	if os.Getenv(fipsChildEnv) != "" {
		t.Skip("this is the child process")
	}
	if fips140.Enabled() {
		t.Skip("this process runs in FIPS 140-3 mode, so its servers cannot offer X25519")
	}

	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
	var ports []string
	for _, groups := range [][]tls.CurveID{{groupX25519MLKEM768, tls.X25519}, {tls.X25519}} {
		_, port := startTLSServerWithConfig(t, &tls.Config{
			Certificates:     []tls.Certificate{cert.serving},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: groups,
		})
		ports = append(ports, strconv.Itoa(port))
	}

	childTests := []string{
		"TestGroupsNotOfferedMatchesAHandshake",
		"TestAGroupThisBuildCannotNegotiateIsReportedNotProbed",
		"TestFIPSChildListsX25519AsNotProbed",
	}
	cmd := exec.Command(os.Args[0], "-test.count=1", "-test.v",
		"-test.run=^("+strings.Join(childTests, "|")+")$")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=on", fipsChildEnv+"=1",
		fipsServersEnv+"="+strings.Join(ports, ","))
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "--- SKIP: TestFIPSChildListsX25519AsNotProbed") {
		t.Skipf("the FIPS child process skipped the scans:\n%s", out)
	}
	if err != nil {
		t.Fatalf("the tests in the FIPS child process failed (%v):\n%s", err, out)
	}
	for _, name := range childTests {
		if !strings.Contains(string(out), "--- PASS: "+name+" ") {
			t.Fatalf("the FIPS child process did not pass %s:\n%s", name, out)
		}
	}
}

// TestFIPSChildListsX25519AsNotProbed runs only in the child process that
// TestAFIPSBuildListsX25519AsNotProbed starts, and scans the servers that test
// serves. The scan of the server offering X25519MLKEM768 and X25519 must find
// X25519MLKEM768 and list X25519 as not probed, and the error for the server
// offering only X25519 must give the openssl command that checks X25519.
func TestFIPSChildListsX25519AsNotProbed(t *testing.T) {
	ports := strings.Split(os.Getenv(fipsServersEnv), ",")
	if os.Getenv(fipsChildEnv) == "" || len(ports) != 2 {
		t.Skip("runs in the child process that TestAFIPSBuildListsX25519AsNotProbed starts")
	}
	if !fips140.Enabled() {
		t.Skip("GODEBUG=fips140=on did not turn on FIPS 140-3 mode in this build")
	}

	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
	x25519, hybrid := tlsGroups[tls.X25519].name, tlsGroups[groupX25519MLKEM768].name
	if negotiatesOnly(t, cert.serving, tls.X25519) {
		t.Skipf("this build negotiates %s in FIPS 140-3 mode, so the scan can probe it", x25519)
	}
	if !negotiatesOnly(t, cert.serving, groupX25519MLKEM768) {
		t.Skipf("this build cannot negotiate %s in FIPS 140-3 mode, so it shares no group "+
			"with the first server", hybrid)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := New(localScanConfig()).Scan(ctx, net.JoinHostPort("127.0.0.1", ports[0]))
	if err != nil {
		t.Fatalf("scan of the server offering %s and %s: %v", hybrid, x25519, err)
	}
	var found []string
	for _, ke := range result.KeyExchanges {
		found = append(found, ke.Name)
	}
	if !slices.Contains(found, hybrid) || slices.Contains(found, x25519) {
		t.Errorf("the scan found %v; it should find %s, and not %s, which this build cannot offer",
			found, hybrid, x25519)
	}
	if notProbed := notProbedGroups(result.ScanWarnings); !slices.Contains(notProbed, x25519) {
		t.Errorf("the scan does not list %s as not probed, so the server's %s reads as absent; "+
			"groups listed as not probed: %q", x25519, x25519, notProbed)
	}

	port, err := strconv.Atoi(ports[1])
	if err != nil {
		t.Fatalf("the port of the server offering only %s: %v", x25519, err)
	}
	addr := net.JoinHostPort("127.0.0.1", ports[1])
	printed := sanitize.WrapError(scanExpectingError(t, "127.0.0.1", port)).Error()
	t.Logf("error for the server offering only %s, as the CLI prints it, %d bytes: %s",
		x25519, len(printed), printed)
	names := make([]string, len(keyExchangeCandidates))
	for i, id := range keyExchangeCandidates {
		names[i] = tlsGroups[id].name
	}
	whole, cut := opensslCommands(printed, sanitize.ShellWord(addr), names)
	if cut != "" {
		t.Errorf("the CLI's cut ends the error inside an openssl command: %q", cut)
	}
	if !slices.Contains(whole, x25519) {
		t.Errorf("the error gives no command that checks %s, the server's only group and one "+
			"this build does not offer; it checks %v: %q", x25519, whole, printed)
	}
}

// notProbedGroups returns the groups a scan's coverage note lists as key
// exchange groups not probed, or nil when it has no such note.
func notProbedGroups(warnings []string) []string {
	const note = "key exchange groups not probed because this build of the scanner cannot offer them: "
	for _, w := range warnings {
		if groups, ok := strings.CutPrefix(w, note); ok {
			return strings.Split(groups, ", ")
		}
	}
	return nil
}
