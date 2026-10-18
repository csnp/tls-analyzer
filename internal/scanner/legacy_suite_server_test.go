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
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// A server that accepts only cipher suites outside Go's default list, such as
// 3des.badssl.com, rc4.badssl.com or dh1024.badssl.com, fails this scanner's
// default handshake the way a server sharing no key exchange group does. The
// error for it named only the key exchange groups this scanner does not offer,
// which on a Go 1.25 build are the two P-curve hybrids, and said nothing about
// cipher suites, so it pointed the reader away from the cause.
//
// The mutation each test is written to catch:
//   - the cipher suite sentence left out of handshakeFailureMessage:
//     TestALegacyOnlyServerErrorNamesTheCipherSuites, and for each layout of
//     the message, TestEveryLayoutOfTheHandshakeErrorNamesTheCipherSuites.
//   - a family of suites named in that sentence that the default handshake does
//     offer: TestTheDefaultHandshakeOffersNoSuiteTheErrorNames.

// TestALegacyOnlyServerErrorNamesTheCipherSuites is the reproduction of
// "tlsanalyzer rc4.badssl.com cannot be scanned and the error points only at the
// two P-curve hybrid groups", reduced to a local listener that accepts TLS 1.2
// with TLS_ECDHE_ECDSA_WITH_RC4_128_SHA as its only cipher suite.
func TestALegacyOnlyServerErrorNamesTheCipherSuites(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)

	host, port := startTLSServerWithConfig(t, &tls.Config{
		Certificates: []tls.Certificate{cert.serving},
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	})
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// The server has to be one that a client offering RC4 completes a handshake
	// with, and that this scanner's default handshake cannot.
	rc4, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA},
	})
	if err != nil {
		t.Fatalf("a client offering only RC4 could not complete a handshake, so the server in "+
			"this test does not accept RC4: %v", err)
	}
	_ = rc4.Close()
	probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true})
	if err == nil {
		_ = probe.Close()
		t.Skip("this build's default handshake offers RC4, so the server in this test is scannable")
	}

	msg := scanExpectingError(t, host, port).Error()
	t.Logf("error for %s, %d bytes: %s", addr, len(msg), msg)

	if want := "TLS handshake with " + addr + " failed"; !strings.HasPrefix(msg, want) {
		t.Errorf("error should open with %q, got %q", want, msg)
	}
	for _, want := range []string{"cipher suites", "RC4"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not give cipher suites the handshake does not offer, "+
				"such as RC4, as a cause (no %q): %q", want, msg)
		}
	}
	if len(msg) > sanitize.MaxReportDetail {
		t.Errorf("error is %d bytes, over the %d the CLI prints, so its end is cut off: %q",
			len(msg), sanitize.MaxReportDetail, msg)
	}
	for _, group := range hybridGroupsNotOffered() {
		if want := "openssl s_client -connect " + addr + " -groups " + group; !strings.Contains(msg, want) {
			t.Errorf("the error no longer gives %q: %q", want, msg)
		}
	}
}

// TestEveryLayoutOfTheHandshakeErrorNamesTheCipherSuites builds the error for a
// build that offers every hybrid group, for one whose commands all fit, and for
// one whose groups are named ahead of the commands, after a TLS alert and after
// the server closed the connection. Each one, as the CLI prints it, names the
// three families of suites the default handshake lacks.
func TestEveryLayoutOfTheHandshakeErrorNamesTheCipherSuites(t *testing.T) {
	groups := []string{
		tlsGroups[groupX25519MLKEM768].name,
		tlsGroups[groupSecP256r1MLKEM768].name,
		tlsGroups[groupSecP384r1MLKEM1024].name,
	}
	cases := []struct {
		name       string
		addr       string
		notOffered []string
	}{
		{"every hybrid group offered", "127.0.0.1:65535", nil},
		{"every command fits", "127.0.0.1:65535", groups},
		{"groups named ahead of the commands", "scanner-target-example.localhost:65535", groups},
	}
	reasons := []error{
		&net.OpError{Op: "remote error", Err: tls.AlertError(40)},
		io.EOF,
	}

	for _, c := range cases {
		for _, reason := range reasons {
			msg := handshakeFailureMessage(c.addr, reason, c.notOffered)
			printed := sanitize.WrapError(errors.New(msg)).Error()
			for _, family := range []string{"cipher suites", "3DES", "RC4", "DHE"} {
				if !strings.Contains(printed, family) {
					t.Errorf("%s, after %q: the error as the CLI prints it does not name %q: %q",
						c.name, reason, family, printed)
				}
			}
		}
	}
}

// TestTheDefaultHandshakeOffersNoSuiteTheErrorNames reads the ClientHello of the
// handshake the error describes, which is crypto/tls's default configuration,
// and checks that it offers no 3DES, RC4 or DHE suite. crypto/tls implements no
// DHE suite at all, which the second half checks.
func TestTheDefaultHandshakeOffersNoSuiteTheErrorNames(t *testing.T) {
	offered := defaultClientHelloSuites(t)
	if len(offered) == 0 {
		t.Fatal("no ClientHello was read, so this test checks nothing")
	}
	for _, id := range offered {
		name := tls.CipherSuiteName(id)
		for _, family := range []string{"3DES", "RC4", "_DHE_"} {
			if strings.Contains(name, family) {
				t.Errorf("the default handshake offers %s, so the error is wrong to name %s "+
					"as a suite it lacks", name, strings.Trim(family, "_"))
			}
		}
	}

	var implemented []string
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		implemented = append(implemented, suite.Name)
		if strings.Contains(suite.Name, "_DHE_") {
			t.Errorf("crypto/tls implements %s, a DHE suite", suite.Name)
		}
	}
	// A control: the families this build can offer one suite at a time are found
	// by the same reading of the names.
	for _, family := range []string{"3DES", "RC4"} {
		if !slices.ContainsFunc(implemented, func(name string) bool { return strings.Contains(name, family) }) {
			t.Errorf("crypto/tls implements no %s suite here, so the check above cannot see one", family)
		}
	}
}

// defaultClientHelloSuites returns the cipher suites a client with crypto/tls's
// default configuration offers, read by an in-memory server that stops the
// handshake as soon as the ClientHello arrives.
func defaultClientHelloSuites(t *testing.T) []uint16 {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = serverSide.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = serverSide.SetDeadline(deadline)

	var suites []uint16
	errCaptured := errors.New("client hello captured")
	server := tls.Server(serverSide, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			suites = slices.Clone(hello.CipherSuites)
			return nil, errCaptured
		},
	})
	client := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = client.Handshake()
		_ = clientSide.Close()
	}()
	_ = server.Handshake()
	_ = serverSide.Close()
	<-done

	return suites
}
