package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestAZoneScopedLinkLocalTargetIsScanned is the reproduction of
// "tlsanalyzer '[fe80::1%lo0]:8443' is refused as not being an IP address".
// 0.4.1 scanned such a target, and the target check then refused zones with
// the reason for text that is not a target at all. A link-local address
// cannot be reached without its zone, so refusing the zone refused the host.
//
// The listener is bound to a link-local address of an interface on the machine
// running the test, so the scan goes through the same lookup and dials a user's
// does. The target is written from the address and interface the listener was
// bound to, as a user writes it, and takes only its port from the listener.
// Since Go 1.24 a listener on Linux is a Multipath TCP socket where the kernel
// offers one, and the kernel reports such a socket's link-local address
// without its scope, so ln.Addr() carries no zone there and a target taken
// from it was dialed without one. The test is skipped where no interface has
// a link-local address.
func TestAZoneScopedLinkLocalTargetIsScanned(t *testing.T) {
	notBefore, notAfter := validFrom()
	cert := issueLeaf(t, []string{"localhost"}, nil, notBefore, notAfter)
	ln, host := listenOnALinkLocalAddress(t, &tls.Config{Certificates: []tls.Certificate{cert.serving}})

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

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	target := net.JoinHostPort(host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := New(localScanConfig()).Scan(ctx, target)
	if err != nil {
		t.Fatalf("the zone-scoped link-local target %s was not scanned: %v", target, err)
	}
	if result.Host != host {
		t.Errorf("the report names host %q; want %q, with its zone", result.Host, host)
	}
	if !anyProtocolSupported(result.Protocols) {
		t.Errorf("the scan of a zone-scoped target measured no protocol: %+v", result.Protocols)
	}
}

// listenOnALinkLocalAddress serves cfg on the first link-local IPv6 address
// that accepts a listener, on an interface whose name CheckTarget keeps as a
// zone. It returns the listener and the zone-scoped address it is bound to,
// such as fe80::1%lo0.
func listenOnALinkLocalAddress(t *testing.T, cfg *tls.Config) (net.Listener, string) {
	t.Helper()

	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list network interfaces: %v", err)
	}
	for _, ifc := range interfaces {
		if ifc.Flags&net.FlagUp == 0 || !isZone(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() != nil || !ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			host := ipNet.IP.String() + "%" + ifc.Name
			ln, err := tls.Listen("tcp", net.JoinHostPort(host, "0"), cfg)
			if err != nil {
				continue
			}
			t.Cleanup(func() { _ = ln.Close() })
			return ln, host
		}
	}
	t.Skip("no interface here has a link-local IPv6 address that accepts a listener")
	return nil, ""
}
