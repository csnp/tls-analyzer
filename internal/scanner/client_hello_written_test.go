package scanner

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// These tests cover a build whose TLS client can offer none of the hybrid
// post-quantum groups. crypto/tls drops from CurvePreferences every group it
// will not offer, and when none is left it returns "tls: no supported elliptic
// curves for ECDHE" before writing a ClientHello. clientHelloGroups then waited
// out its 5-second deadline for a ClientHello that was never coming, and
// hybridGroupsNotOffered, now groupsNotOffered, returned nil. With
// GODEBUG=fips140=on,tlsmlkem=0 on Go 1.26.3 a scan took 5 seconds longer, a
// failed handshake was reported without the groups this build cannot offer, and
// a completed scan carried no note that the hybrid groups were not probed.
//
// The mutation each test is written to catch:
//   - clientHelloGroups waits for the server's read to time out after the
//     client has returned:
//     TestClientHelloGroupsReturnsAsSoonAsTheClientGivesUp.
//   - clientHelloGroups reports a client that wrote nothing as a ClientHello it
//     could not read, so groupsNotOffered names no group:
//     TestClientHelloGroupsReturnsAsSoonAsTheClientGivesUp and
//     TestAFIPSBuildWithoutMLKEMNamesTheHybridGroupsItCannotOffer.
//
// Both tests were observed to fail on the code before this change.

// TestClientHelloGroupsReturnsAsSoonAsTheClientGivesUp asks for only the hybrid
// groups after GODEBUG has taken each of them out of crypto/tls's defaults, so
// the client has nothing to offer and returns without writing.
func TestClientHelloGroupsReturnsAsSoonAsTheClientGivesUp(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=0,tlssecpmlkem=0")

	start := time.Now()
	groups, ok := clientHelloGroups([]tls.CurveID{
		groupX25519MLKEM768, groupSecP256r1MLKEM768, groupSecP384r1MLKEM1024,
	})
	elapsed := time.Since(start)

	if !ok {
		t.Error("a client that returned before writing a ClientHello was reported as " +
			"a ClientHello that could not be read; it offers none of the groups asked for")
	}
	if len(groups) != 0 {
		t.Errorf("a client that wrote nothing was reported as offering %v", groups)
	}
	// The in-memory server gives the ClientHello 5 seconds to arrive. A client
	// that fails before writing returns in a fraction of that, so 4 seconds
	// separates seeing its error from waiting out the deadline.
	if elapsed >= 4*time.Second {
		t.Errorf("clientHelloGroups took %v for a client that wrote nothing, so it waited "+
			"for the deadline instead of returning when the client did", elapsed)
	}
}

// fipsChildEnv marks the child processes that
// TestAFIPSBuildWithoutMLKEMNamesTheHybridGroupsItCannotOffer and
// TestAFIPSBuildListsX25519AsNotProbed start.
const fipsChildEnv = "TLS_ANALYZER_TEST_FIPS_CHILD"

// TestAFIPSBuildWithoutMLKEMNamesTheHybridGroupsItCannotOffer runs the tests
// that compare the groups named as not offered with real handshakes, in a child
// process started with the issue's GODEBUG=fips140=on,tlsmlkem=0. FIPS mode is
// fixed when a process starts, so it cannot be turned on inside this one. FIPS
// mode also drops X25519, which hybridGroupsNotOffered used to add to the
// groups it asked for so that a ClientHello would always be written.
func TestAFIPSBuildWithoutMLKEMNamesTheHybridGroupsItCannotOffer(t *testing.T) {
	if os.Getenv(fipsChildEnv) != "" {
		t.Skip("this is the child process")
	}

	cmd := exec.Command(os.Args[0], "-test.count=1", "-test.v",
		"-test.run=^(TestGroupsNotOfferedMatchesAHandshake|TestFIPSChildScanNamesTheHybridGroupsItCannotOffer)$")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=on,tlsmlkem=0", fipsChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "--- SKIP: TestFIPSChildScanNamesTheHybridGroupsItCannotOffer") {
		t.Skipf("the child process could not run in FIPS 140-3 mode:\n%s", out)
	}
	if err != nil {
		t.Fatalf("the tests in the FIPS child process failed (%v):\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestFIPSChildScanNamesTheHybridGroupsItCannotOffer") ||
		!strings.Contains(string(out), "--- PASS: TestGroupsNotOfferedMatchesAHandshake") {
		t.Fatalf("the FIPS child process did not run both tests:\n%s", out)
	}
}

// TestFIPSChildScanNamesTheHybridGroupsItCannotOffer runs only in the child
// process started above. A server that offers X25519MLKEM768 and X25519 shares
// no group with this client, and the failure must name the hybrid groups it
// cannot offer. One that also offers P-256 completes the scan, and the result
// must say those groups were not probed rather than leave them looking absent.
func TestFIPSChildScanNamesTheHybridGroupsItCannotOffer(t *testing.T) {
	if os.Getenv(fipsChildEnv) == "" {
		t.Skip("runs in the child process that " +
			"TestAFIPSBuildWithoutMLKEMNamesTheHybridGroupsItCannotOffer starts")
	}
	if !fips140.Enabled() {
		t.Skip("GODEBUG=fips140=on did not turn on FIPS 140-3 mode in this build")
	}

	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
	hybridNames := []string{
		tlsGroups[groupX25519MLKEM768].name,
		tlsGroups[groupSecP256r1MLKEM768].name,
		tlsGroups[groupSecP384r1MLKEM1024].name,
	}

	host, port := startTLSServerWithConfig(t, &tls.Config{
		Certificates:     []tls.Certificate{cert.serving},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{groupX25519MLKEM768, tls.X25519},
	})
	msg := scanExpectingError(t, host, port).Error()
	for _, name := range hybridNames {
		if !strings.Contains(msg, name) {
			t.Errorf("the handshake failure does not name %s, which this build cannot "+
				"offer: %q", name, msg)
		}
	}

	// The same server through a 39-character spelling of 127.0.0.1, read as the
	// CLI prints it. The address is written in the headline and in each of the
	// three commands, so the CLI's cut fell after the second command and the
	// third group went unnamed. A long address takes no name lookup this way.
	long := "0000:0000:0000:0000:0000:ffff:127.0.0.1"
	addr := net.JoinHostPort(long, strconv.Itoa(port))
	printed := sanitize.WrapError(scanExpectingError(t, long, port)).Error()
	t.Logf("error for %s as the CLI prints it, %d bytes: %s", addr, len(printed), printed)
	for _, name := range hybridNames {
		if !strings.Contains(printed, name) {
			t.Errorf("the handshake failure for %s, as the CLI prints it, does not name %s, "+
				"which this build cannot offer: %q", addr, name, printed)
		}
	}
	whole, cut := opensslCommands(printed, sanitize.ShellWord(addr), hybridNames)
	if cut != "" {
		t.Errorf("the CLI's cut ends the error inside an openssl command: %q", cut)
	}
	if len(whole) == 0 {
		t.Errorf("the error for %s gives no openssl command, though one fits within the %d "+
			"bytes the CLI prints: %q", addr, sanitize.MaxReportDetail, printed)
	}

	host, port = startTLSServerWithConfig(t, &tls.Config{
		Certificates:     []tls.Certificate{cert.serving},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{groupX25519MLKEM768, tls.X25519, tls.CurveP256},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := New(localScanConfig()).Scan(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("scan of a server offering P-256: %v", err)
	}
	var note string
	for _, w := range result.ScanWarnings {
		if strings.HasPrefix(w, "key exchange groups not probed") {
			note = w
		}
	}
	for _, name := range hybridNames {
		if !strings.Contains(note, name) {
			t.Errorf("the scan does not say %s was not probed; warnings: %q",
				name, result.ScanWarnings)
		}
	}
}
