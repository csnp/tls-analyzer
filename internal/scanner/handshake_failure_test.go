package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
)

// These tests pin the message for a scan that completed no handshake. A port
// that refused the TCP connection and a TLS server that rejected every
// handshake used to produce the same error, "no TLS connection could be
// established ... (host unreachable, port closed, or not speaking TLS)". A
// server whose only key exchange group is SecP256r1MLKEM768, which this
// scanner does not offer, was therefore reported as possibly down.
//
// The mutation each test is written to catch:
//   - noHandshakeError returns the unreachable message for every failure, as
//     the code before this change did:
//     TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable. This one was
//     observed: that test failed on the earlier code with the message above.
//   - noHandshakeError returns the handshake message without dialling TCP
//     first: TestAClosedPortIsStillReportedUnreachable.
//   - the unreachable message writes the host and the port with "%s:%d"
//     instead of the joined address:
//     TestAnUnreachableIPv6AddressIsWrittenInBrackets. This one was observed:
//     both of its cases failed on code that did so.
//   - the "remote error" case in noHandshakeError removed, so a TLS alert gets
//     the wording for an unclassified failure, which says the server may not
//     speak TLS: TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable.
//   - the tls.RecordHeaderError case in noHandshakeError removed:
//     TestAServiceThatDoesNotSpeakTLSIsNamedAsSuch.
//   - noHandshakeError sets its deadline from a ConnectTimeout of 0, which has
//     already passed: TestAZeroConnectTimeoutStillReadsTheReply.
//   - the openssl command names every missing group after one -groups:
//     TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable.
//   - the openssl commands give the address unquoted, as net.JoinHostPort
//     renders it: TestTheOpensslCommandsQuoteAnIPv6Address. This one was
//     observed: that test failed on the earlier code with the address bare.
//   - groupsNotOffered returns nil, as it does when no ClientHello was read:
//     TestGroupsNotOfferedMatchesAHandshake, on any build that does not offer
//     the P-curve hybrids.
//   - groupsNotOffered decides by toolchainSupportsGroup instead of reading a
//     ClientHello: TestGroupsNotOfferedMatchesAHandshake, on a Go 1.26 or later
//     toolchain, which names the P-curve hybrids but keeps them disabled for a
//     module declaring go 1.25.
//   - groupsNotOffered reads only the three hybrid groups, as it did before it
//     read every group the scan probes: TestGroupsNotOfferedMatchesAHandshake,
//     in the FIPS 140-3 child processes that
//     TestAFIPSBuildWithoutMLKEMNamesTheHybridGroupsItCannotOffer and
//     TestAFIPSBuildListsX25519AsNotProbed start, where X25519 is not offered.
//     It was observed to fail in both.

// startTLSServerWithConfig serves cfg on a loopback port for the duration of
// the test. Every accepted connection runs the server side of a handshake, so
// a client that shares nothing with cfg receives the server's alert rather
// than a closed socket.
func startTLSServerWithConfig(t *testing.T, cfg *tls.Config) (host string, port int) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveTLS(t, ln)
}

// serveTLS runs the server side of a handshake on every connection ln accepts
// until the test ends, and returns the host and port ln listens on.
func serveTLS(t *testing.T, ln net.Listener) (host string, port int) {
	t.Helper()

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}(conn)
		}
	}()

	addrHost, addrPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	p, err := strconv.Atoi(addrPort)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	return addrHost, p
}

// startNonTLSServer serves plain HTTP on a loopback port for the duration of
// the test: every connection is read once and answered with an HTTP 400, which
// is not a TLS record.
func startNonTLSServer(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 512)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
			}(conn)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func scanExpectingError(t *testing.T, host string, port int) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := New(localScanConfig()).Scan(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		t.Fatalf("scan of %s:%d returned a result, want an error: %+v", host, port, result)
	}
	if result != nil {
		t.Errorf("expected no result alongside the error, got %+v", result)
	}
	return err
}

// TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable is the
// reproduction of "a server offering only a P-curve ML-KEM hybrid group is
// reported as unreachable", reduced to a local listener. The listener accepts
// TLS 1.3 with SecP256r1MLKEM768 as its only group, the same shape as
// openssl s_server -tls1_3 -groups SecP256r1MLKEM768.
func TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)

	host, port := startTLSServerWithConfig(t, &tls.Config{
		Certificates:     []tls.Certificate{cert.serving},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{groupSecP256r1MLKEM768},
	})

	// The scenario needs a server this build's client cannot complete a
	// handshake with. A build that offers SecP256r1MLKEM768 by default connects
	// here, and then there is no failure message to test.
	probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp",
		net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		_ = probe.Close()
		t.Skip("this build's TLS client completes a handshake using SecP256r1MLKEM768, " +
			"so the server in this test is scannable")
	}

	msg := scanExpectingError(t, host, port).Error()

	if strings.Contains(msg, "host unreachable") {
		t.Errorf("a server that accepted the TCP connection was reported as possibly "+
			"unreachable: %q", msg)
	}
	if strings.Contains(msg, "not speak TLS") || strings.Contains(msg, "not speaking TLS") {
		t.Errorf("a server that answered with a TLS alert was described as possibly not "+
			"speaking TLS: %q", msg)
	}
	wantHeadline := "TLS handshake with " + net.JoinHostPort(host, strconv.Itoa(port)) + " failed"
	if !strings.HasPrefix(msg, wantHeadline) {
		t.Errorf("error should open with %q, got %q", wantHeadline, msg)
	}
	for _, group := range []string{"SecP256r1MLKEM768", "SecP384r1MLKEM1024"} {
		if !strings.Contains(msg, group) {
			t.Errorf("error should name %s as a group this scanner does not offer, got %q",
				group, msg)
		}
	}

	// The CLI truncates an error to sanitize.MaxReportDetail bytes, which cut the
	// openssl command off the end of a longer wording of this message.
	if len(msg) > sanitize.MaxReportDetail {
		t.Errorf("error is %d bytes, over the %d the CLI prints, so its end is cut off: %q",
			len(msg), sanitize.MaxReportDetail, msg)
	}

	// One command per group, as docs/how-it-works.md gives them. s_client
	// negotiates one of the groups named after -groups, so the command this
	// error used to end with, -groups SecP256r1MLKEM768:SecP384r1MLKEM1024,
	// said nothing about SecP384r1MLKEM1024 against a server offering both.
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	alone := make(map[string]bool)
	for _, cmd := range strings.Split(msg, "openssl s_client")[1:] {
		offered := offeredGroups(cmd)
		if len(offered) != 1 {
			t.Errorf("an openssl command in the error offers %d groups, so it cannot "+
				"confirm each one: %q", len(offered), cmd)
			continue
		}
		alone[offered[0]] = true
	}
	notOffered := groupsNotOffered()
	for _, group := range notOffered {
		want := "openssl s_client -connect " + addr + " -groups " + group
		if !alone[group] || !strings.Contains(msg, want) {
			t.Errorf("error should give %q, a command offering %s on its own, got %q",
				want, group, msg)
		}
	}
	if len(notOffered) > 0 && !strings.HasSuffix(msg, "-groups "+notOffered[len(notOffered)-1]) {
		t.Errorf("error should end with the last group's openssl command, got %q", msg)
	}
}

// TestTheOpensslCommandsQuoteAnIPv6Address is the reproduction of "suggested
// openssl command for an IPv6 target does not run when pasted into zsh": the
// server of TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable,
// listening on ::1. net.JoinHostPort brackets an IPv6 address, and zsh reads
// the brackets as a glob pattern, so pasting either command printed "no
// matches found: [::1]:56128" and openssl did not run.
func TestTheOpensslCommandsQuoteAnIPv6Address(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)

	ln, err := tls.Listen("tcp", "[::1]:0", &tls.Config{
		Certificates:     []tls.Certificate{cert.serving},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{groupSecP256r1MLKEM768},
	})
	if err != nil {
		t.Skipf("this machine has no IPv6 loopback address to listen on: %v", err)
	}
	host, port := serveTLS(t, ln)
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	probe, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true})
	if err == nil {
		_ = probe.Close()
		t.Skip("this build's TLS client completes a handshake using SecP256r1MLKEM768, " +
			"so the server in this test is scannable")
	}

	msg := scanExpectingError(t, host, port).Error()
	t.Logf("error for %s, %d bytes: %s", addr, len(msg), msg)

	notOffered := groupsNotOffered()
	if len(notOffered) == 0 {
		t.Fatalf("this build cannot negotiate SecP256r1MLKEM768, the server's only group, "+
			"yet the error gives no openssl command to check it: %q", msg)
	}
	for _, group := range notOffered {
		want := "openssl s_client -connect '" + addr + "' -groups " + group
		if !strings.Contains(msg, want) {
			t.Errorf("error should give %q, with the address quoted so that zsh does not "+
				"read its brackets as a glob, got %q", want, msg)
		}
	}
	if strings.Contains(msg, "-connect "+addr) {
		t.Errorf("an openssl command in the error gives the address unquoted, which zsh "+
			"refuses with \"no matches found: %s\": %q", addr, msg)
	}

	// Quoting adds two bytes to each command, and the CLI cuts a scan error
	// longer than sanitize.MaxReportDetail bytes from the end.
	if len(msg) > sanitize.MaxReportDetail {
		t.Errorf("error is %d bytes, over the %d the CLI prints, so its end is cut off: %q",
			len(msg), sanitize.MaxReportDetail, msg)
	}
}

// TestAZeroConnectTimeoutStillReadsTheReply is the reproduction of
// "tlsanalyzer 127.0.0.1:8080 --timeout 1 misdescribes a plain HTTP server".
// The command derived a connect timeout of 0 from --timeout 1, and
// noHandshakeError turned it into a deadline that had already passed, so its
// handshake failed with an i/o timeout before the server's reply was read and
// the message said the host might not speak TLS or might accept nothing this
// scanner offers. The scan's other dials read 0 as no timeout, and so does this
// one.
func TestAZeroConnectTimeoutStillReadsTheReply(t *testing.T) {
	port := startNonTLSServer(t)

	cfg := localScanConfig()
	cfg.ConnectTimeout = 0
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := New(cfg).Scan(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		t.Fatalf("a plain HTTP server was scanned as TLS: %+v", result)
	}

	msg := err.Error()
	if strings.Contains(msg, "i/o timeout") {
		t.Errorf("a zero connect timeout became an expired deadline: %q", msg)
	}
	if !strings.Contains(msg, "does not appear to speak TLS") {
		t.Errorf("with a zero connect timeout the error should say the service does not "+
			"appear to speak TLS, as it does with the default, got %q", msg)
	}
}

// TestAServiceThatDoesNotSpeakTLSIsNamedAsSuch covers a reachable port whose
// service answers a ClientHello with something other than TLS, here a plain
// HTTP response. Its error says the service does not appear to speak TLS and
// does not send the reader to check key exchange groups.
func TestAServiceThatDoesNotSpeakTLSIsNamedAsSuch(t *testing.T) {
	msg := scanExpectingError(t, "127.0.0.1", startNonTLSServer(t)).Error()

	if strings.Contains(msg, "host unreachable") {
		t.Errorf("a service that accepted the TCP connection was reported as possibly "+
			"unreachable: %q", msg)
	}
	if !strings.Contains(msg, "does not appear to speak TLS") {
		t.Errorf("error should say the service does not appear to speak TLS, got %q", msg)
	}
	if strings.Contains(msg, "SecP256r1MLKEM768") {
		t.Errorf("a service that does not speak TLS should not send the reader to check "+
			"key exchange groups, got %q", msg)
	}
}

// TestAClosedPortIsStillReportedUnreachable keeps the other side of the split:
// a port nothing listens on must not be described as a TLS server that rejected
// the handshake.
func TestAClosedPortIsStillReportedUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	msg := scanExpectingError(t, "127.0.0.1", addr.Port).Error()

	if !strings.Contains(msg, "host unreachable") {
		t.Errorf("a closed port should be reported as unreachable or closed, got %q", msg)
	}
	if strings.Contains(msg, "TLS handshake with") {
		t.Errorf("a closed port was described as a failed TLS handshake: %q", msg)
	}
}

// TestAnUnreachableIPv6AddressIsWrittenInBrackets is the reproduction of
// "tlsanalyzer '[::1]:1' --timeout 2 prints no TLS connection could be
// established to ::1:1". The message for a port that refused the TCP
// connection wrote the host and the port with "%s:%d", so an IPv6 address lost
// its brackets and its port read as part of the address. Each case is skipped
// where this machine has no such address that accepts a listener.
func TestAnUnreachableIPv6AddressIsWrittenInBrackets(t *testing.T) {
	t.Run("loopback", func(t *testing.T) {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("the IPv6 loopback address accepts no listener here: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		checkUnreachableAddress(t, "::1", port)
	})

	t.Run("zone-scoped link-local", func(t *testing.T) {
		notBefore, notAfter := validFrom()
		cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
		ln, host := listenOnALinkLocalAddress(t, &tls.Config{Certificates: []tls.Certificate{cert.serving}})
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		checkUnreachableAddress(t, host, port)
	})
}

// checkUnreachableAddress scans a port nothing listens on and checks that the
// unreachable message names the address as net.JoinHostPort writes it.
func checkUnreachableAddress(t *testing.T, host string, port int) {
	t.Helper()

	msg := scanExpectingError(t, host, port).Error()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if !strings.Contains(msg, "no TLS connection could be established to "+addr+" (") {
		t.Errorf("the unreachable message should name the address as %s, got %q", addr, msg)
	}
}

// TestGroupsNotOfferedMatchesAHandshake checks the groups the error names, and
// the scan lists as not probed, against what crypto/tls does in this build:
// each group the scan probes is listed as not offered exactly when a client
// and a server that both allow only that group cannot negotiate it.
func TestGroupsNotOfferedMatchesAHandshake(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
	notOffered := groupsNotOffered()

	for _, id := range keyExchangeCandidates {
		name := tlsGroups[id].name
		listed := slices.Contains(notOffered, name)
		negotiated := negotiatesOnly(t, cert.serving, id)
		if listed == negotiated {
			t.Errorf("%s: listed as not offered is %v, and a handshake allowing only "+
				"that group negotiated it is %v; exactly one should be true",
				name, listed, negotiated)
		}
	}
}

// negotiatesOnly reports whether an in-memory client and server that both
// allow only id complete a TLS 1.3 handshake using it.
func negotiatesOnly(t *testing.T, cert tls.Certificate, id tls.CurveID) bool {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = serverSide.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = serverSide.SetDeadline(deadline)

	// net.Pipe has no buffer, so a session ticket the client never reads would
	// hold the server's write, and the handshake, until the deadline.
	server := tls.Server(serverSide, &tls.Config{
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{id},
		SessionTicketsDisabled: true,
	})
	client := tls.Client(clientSide, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{id},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Handshake()
		_ = serverSide.Close()
	}()
	clientErr := client.Handshake()
	_ = clientSide.Close()
	<-done

	return clientErr == nil && client.ConnectionState().CurveID == id
}
