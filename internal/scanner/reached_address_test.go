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

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// TestScanNamesTheAddressItsConnectionsReached is the reproduction of
// "Quantum score Fix's address-form Verify can connect to an address the scan
// did not reach", at the scanner: the result's IP, from which that Verify and
// the JSON ip field are built, was the first address the host name resolved
// to, while the scan's dials move on to the next address when the first one
// refuses the connection.
//
// localhost has to resolve to two or more loopback addresses on the machine
// running the test, as it does on macOS (::1, then 127.0.0.1); otherwise the
// test is skipped. The server listens on the last of those addresses only, so
// every connection the scan makes is refused at the first and completes at the
// last.
func TestScanNamesTheAddressItsConnectionsReached(t *testing.T) {
	const name = "localhost"
	first, last := twoLoopbackAddresses(t, name)

	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{name}, nil, notBefore, notAfter)
	port := serveOn(t, last, &tls.Config{
		Certificates: []tls.Certificate{cert.serving},
		MinVersion:   tls.VersionTLS12,
	})
	requireNothingListening(t, first, port)

	result := scanLocal(t, localScanConfig(), name, port)
	if result.IP != last.String() {
		t.Errorf("the result's IP is %q; the scan's connections reached %s, and nothing "+
			"listens at %s on port %d", result.IP, last, first, port)
	}
	for _, w := range result.ScanWarnings {
		if strings.Contains(w, "connections reached") {
			t.Errorf("the scan reached one address and warns of more: %s", w)
		}
	}
}

// TestRecordReachedNamesTheFirstAddressAndWarnsOfOthers pins what the result
// says when its connections reached one address and when they reached more
// than one: the addresses are kept in the order they were first reached and
// without repeats, ip is the first, and a result that combines the answers of
// more than one address says so.
func TestRecordReachedNamesTheFirstAddressAndWarnsOfOthers(t *testing.T) {
	var reached reachedAddresses
	for _, addr := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("::1"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("::1"), Port: 443},
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, // never a TLS connection
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("::1"), Port: 8443},
	} {
		reached.record(addr)
	}
	got, want := reached.list(), []string{"::1", "127.0.0.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("recorded %v; want %v, in order and without repeats", got, want)
	}

	none := &types.ScanResult{}
	recordReached(none, nil)
	if none.IP != "" || len(none.ScanWarnings) != 0 {
		t.Errorf("with no address reached, IP %q and warnings %v; want neither", none.IP,
			none.ScanWarnings)
	}

	one := &types.ScanResult{}
	recordReached(one, got[:1])
	if one.IP != "::1" || len(one.ScanWarnings) != 0 {
		t.Errorf("with one address reached, IP %q and warnings %v; want ::1 and no warning",
			one.IP, one.ScanWarnings)
	}

	two := &types.ScanResult{}
	recordReached(two, got)
	if two.IP != "::1" {
		t.Errorf("with two addresses reached, IP %q; want the first, ::1", two.IP)
	}
	if len(two.ScanWarnings) != 1 || !strings.Contains(two.ScanWarnings[0], "2 addresses, ::1 and 127.0.0.1") {
		t.Errorf("with two addresses reached, warnings %v; want one naming both", two.ScanWarnings)
	}

	three := &types.ScanResult{}
	recordReached(three, []string{"::1", "127.0.0.1", "192.0.2.1"})
	if len(three.ScanWarnings) != 1 ||
		!strings.Contains(three.ScanWarnings[0], "3 addresses, ::1, 127.0.0.1 and 192.0.2.1") {
		t.Errorf("with three addresses reached, warnings %v; want one naming all three",
			three.ScanWarnings)
	}
}

// twoLoopbackAddresses resolves name as the scan's dials do and returns its
// first and last address, skipping the test unless there are at least two and
// all of them are loopback addresses, so that a server can listen on one while
// a connection to the other is refused at once.
func twoLoopbackAddresses(t *testing.T, name string) (first, last net.IP) {
	t.Helper()
	ips, err := net.LookupIP(name)
	if err != nil {
		t.Skipf("%s does not resolve here: %v", name, err)
	}
	if len(ips) < 2 {
		t.Skipf("%s resolves to %v here; the test needs two loopback addresses", name, ips)
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			t.Skipf("%s resolves to %v here, not only to loopback addresses", name, ips)
		}
	}
	first, last = ips[0], ips[len(ips)-1]
	if first.Equal(last) {
		t.Skipf("%s resolves to %v here, with the same first and last address", name, ips)
	}
	return first, last
}

// serveOn serves cfg on ip at a port of the kernel's choice for the duration
// of the test, completing the server side of every handshake, and returns the
// port.
func serveOn(t *testing.T, ip net.IP, cfg *tls.Config) int {
	t.Helper()
	ln, err := tls.Listen("tcp", net.JoinHostPort(ip.String(), "0"), cfg)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", ip, err)
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
	return ln.Addr().(*net.TCPAddr).Port
}

// requireNothingListening skips the test when a connection to ip at port is
// accepted, since the scan's dials would then never move on from that address.
func requireNothingListening(t *testing.T, ip net.IP, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), time.Second)
	if err == nil {
		_ = conn.Close()
		t.Skipf("something accepts connections at %s on port %d", ip, port)
	}
}
