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
//   - the "remote error" case in noHandshakeError removed, so a TLS alert gets
//     the wording for an unclassified failure, which says the server may not
//     speak TLS: TestAServerSharingNoKeyExchangeGroupIsNotReportedUnreachable.
//   - the tls.RecordHeaderError case in noHandshakeError removed:
//     TestAServiceThatDoesNotSpeakTLSIsNamedAsSuch.
//   - hybridGroupsNotOffered returns nil, as it does when no ClientHello was
//     read: TestHybridGroupsNotOfferedMatchesAHandshake, on any build that does
//     not offer the P-curve hybrids.
//   - hybridGroupsNotOffered decides by toolchainSupportsGroup instead of
//     reading a ClientHello: TestHybridGroupsNotOfferedMatchesAHandshake, on a
//     Go 1.26 or later toolchain, which names the P-curve hybrids but keeps them
//     disabled for a module declaring go 1.25.

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
	if !strings.HasSuffix(msg, "-groups SecP256r1MLKEM768:SecP384r1MLKEM1024") {
		t.Errorf("error should end with an openssl command offering both groups, got %q", msg)
	}
}

// TestAServiceThatDoesNotSpeakTLSIsNamedAsSuch covers a reachable port whose
// service answers a ClientHello with something other than TLS, here a plain
// HTTP response. Its error says the service does not appear to speak TLS and
// does not send the reader to check key exchange groups.
func TestAServiceThatDoesNotSpeakTLSIsNamedAsSuch(t *testing.T) {
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

	addr := ln.Addr().(*net.TCPAddr)
	msg := scanExpectingError(t, "127.0.0.1", addr.Port).Error()

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

// TestHybridGroupsNotOfferedMatchesAHandshake checks the groups the error names
// against what crypto/tls does in this build: a hybrid group is listed as not
// offered exactly when a client and a server that both allow only that group
// cannot negotiate it.
func TestHybridGroupsNotOfferedMatchesAHandshake(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
	notOffered := hybridGroupsNotOffered()

	for _, id := range []tls.CurveID{
		groupX25519MLKEM768, groupSecP256r1MLKEM768, groupSecP384r1MLKEM1024,
	} {
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
