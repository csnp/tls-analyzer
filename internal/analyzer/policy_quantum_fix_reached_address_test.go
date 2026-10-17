package analyzer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
)

// TestQuantumScoreFixConnectsToTheAddressTheScanReached is the reproduction of
// "Quantum score Fix's address-form Verify can connect to an address the scan
// did not reach": a TLS 1.3 server offering X25519 and P-256, listening on one
// loopback address only, scanned under cnsa-2.0-2030 as a 213-character
// .localhost name. The scan's dials move on from an address that refuses the
// connection, so the scan completed over the listening address, while the
// result's IP, and the Verify built from it because the host name is too long
// to be written twice, named the first address the name resolved to.
//
// The name has to resolve to two or more loopback addresses on the machine
// running the test, as a .localhost name does on macOS (::1, then 127.0.0.1);
// otherwise the test is skipped. The server listens on the last of them, and
// nothing may be listening at the first on the same port.
func TestQuantumScoreFixConnectsToTheAddressTheScanReached(t *testing.T) {
	host := strings.Repeat(strings.Repeat("a", 50)+".", 4) + "localhost"
	ips, err := net.LookupIP(host)
	if err != nil {
		t.Skipf("%s does not resolve here: %v", host, err)
	}
	if len(ips) < 2 {
		t.Skipf("the .localhost name resolves to %v here; the test needs two loopback addresses", ips)
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			t.Skipf("the .localhost name resolves to %v here, not only to loopback addresses", ips)
		}
	}
	first, last := ips[0], ips[len(ips)-1]
	if first.Equal(last) {
		t.Skipf("the .localhost name resolves to %v here, with the same first and last address", ips)
	}

	ln, err := tls.Listen("tcp", net.JoinHostPort(last.String(), "0"), &tls.Config{
		Certificates:     []tls.Certificate{selfSignedFor(t, host)},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	})
	if err != nil {
		t.Skipf("cannot listen on %s: %v", last, err)
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
	port := ln.Addr().(*net.TCPAddr).Port
	if c, err := net.DialTimeout("tcp", net.JoinHostPort(first.String(), strconv.Itoa(port)),
		time.Second); err == nil {
		_ = c.Close()
		t.Skipf("something accepts connections at %s on port %d", first, port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := scanner.New(scanner.DefaultConfig()).Scan(ctx,
		net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.IP != last.String() {
		t.Errorf("the result's IP is %q; the scan's connections reached %s, and nothing "+
			"listens at %s on port %d", result.IP, last, first, port)
	}

	e := NewPolicyEvaluator()
	policy, found := e.GetPolicy("cnsa-2.0-2030")
	if !found {
		t.Fatal("built-in policy cnsa-2.0-2030 not found")
	}
	var fix string
	for _, v := range e.Evaluate(result, policy).Violations {
		if v.Rule == "quantum.minQuantumScore" {
			fix = v.Remediation
		}
	}
	if fix == "" {
		t.Fatal("no quantum.minQuantumScore violation for a server with classical key exchange")
	}
	connect := net.JoinHostPort(last.String(), strconv.Itoa(port))
	if strings.Contains(connect, "[") {
		connect = "'" + connect + "'"
	}
	verify := "Verify hybrid ML-KEM support: openssl s_client -connect " + connect +
		" -servername " + host + " -groups X25519MLKEM768 </dev/null"
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("the Fix does not end with the Verify that connects to %s, the address the "+
			"scan reached:\n%s", last, fix)
	}
}

// selfSignedFor issues a self-signed ECDSA P-256 certificate for name, valid
// for a day.
func selfSignedFor(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quantum score fix test"},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
