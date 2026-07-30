package scanner

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
	"testing"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The tests in this file name nothing that did not already exist, so they
// compile against the pre-fix sources and fail there at runtime, naming the
// defect. Anything that has to name a new field or config option lives in
// certificate_checks_fields_test.go instead.

// issued is a throwaway certificate plus the CA that signed it, so a test can
// decide for itself whether that chain is trusted. Nothing here reads the trust
// store of the machine running the suite.
type issued struct {
	serving tls.Certificate
	leaf    *x509.Certificate
	chain   []*x509.Certificate
	roots   *x509.CertPool
}

// issueLeaf mints a one-off CA and a leaf under it.
func issueLeaf(t *testing.T, dnsNames []string, ips []net.IP, notBefore, notAfter time.Time) issued {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlsanalyzer test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tlsanalyzer test leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return issued{
		serving: tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
			Leaf:        leafCert,
		},
		leaf:  leafCert,
		chain: []*x509.Certificate{caCert},
		roots: roots,
	}
}

func validFrom() (time.Time, time.Time) {
	return time.Now().Add(-time.Hour), time.Now().Add(90 * 24 * time.Hour)
}

// startLocalTLSServer serves the given certificate on a loopback port for the
// duration of the test. The scanner opens many connections while probing, so
// the accept loop stays up until the listener is closed.
func startLocalTLSServer(t *testing.T, cert tls.Certificate) (host string, port int) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
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
				defer c.Close()
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

func scanLocal(t *testing.T, cfg *Config, host string, port int) *types.ScanResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := New(cfg).Scan(ctx, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("scan %s:%d: %v", host, port, err)
	}
	if result.Certificate == nil {
		t.Fatal("scan returned no certificate, so nothing about the certificate can be asserted")
	}
	return result
}

func findVulnerability(result *types.ScanResult, id string) *types.Vulnerability {
	for i := range result.Vulnerabilities {
		if result.Vulnerabilities[i].ID == id {
			return &result.Vulnerabilities[i]
		}
	}
	return nil
}

func certificateFactor(t *testing.T, result *types.ScanResult) types.GradeFactor {
	t.Helper()
	for _, f := range result.Grade.Factors {
		if f.Category == "Certificate" {
			return f
		}
	}
	t.Fatal("no Certificate factor in the grade breakdown")
	return types.GradeFactor{}
}

func localScanConfig() *Config {
	cfg := DefaultConfig()
	// The quantum assessment is irrelevant here and only lengthens the scan.
	cfg.CheckQuantum = false
	return cfg
}

// TestScanFlagsACertificateIssuedForAnotherName is the reproduction of
// "tlsanalyzer wrong.host.badssl.com reports Certificate 25/25 and a valid
// certificate", reduced to a local server so it needs no network.
//
// The served certificate is valid only for example.invalid, and the scan asks
// for 127.0.0.1, which is the same shape as asking badssl for a name its
// wildcard cannot cover.
func TestScanFlagsACertificateIssuedForAnotherName(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, []string{"example.invalid"}, nil, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	result := scanLocal(t, localScanConfig(), host, port)

	if v := findVulnerability(result, "CERT_NAME_MISMATCH"); v == nil {
		t.Fatal("no CERT_NAME_MISMATCH finding for a certificate valid only for " +
			"example.invalid served to a client asking for 127.0.0.1. Every browser " +
			"refuses this connection; the analyzer reported it as a valid certificate.")
	} else if v.Severity != types.SeverityHigh {
		t.Fatalf("CERT_NAME_MISMATCH severity = %q, want %q", v.Severity, types.SeverityHigh)
	} else if v.Remediation == "" {
		t.Fatal("CERT_NAME_MISMATCH carries no remediation, so the finding is a dead end")
	}

	factor := certificateFactor(t, result)
	if factor.Score != 0 {
		t.Fatalf("Certificate factor = %d/%d (%q), want 0: a certificate that cannot "+
			"authenticate the name it was served for earns nothing in the dimension "+
			"that describes it", factor.Score, factor.MaxScore, factor.Details)
	}
}

// TestScanFlagsAChainThatDoesNotBuildToATrustedRoot is the reproduction of
// "untrusted-root.badssl.com reports Certificate 25/25 and Valid certificate
// from trusted CA", which openssl rejects with error 19.
//
// The CA minted here is thrown away at the end of the test and is in no
// machine's trust store, so the expected verdict is the same everywhere.
func TestScanFlagsAChainThatDoesNotBuildToATrustedRoot(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	result := scanLocal(t, localScanConfig(), host, port)

	if v := findVulnerability(result, "CERT_CHAIN_UNTRUSTED"); v == nil {
		t.Fatal("no CERT_CHAIN_UNTRUSTED finding for a chain built on a CA no trust " +
			"store has ever seen. The report asserted the certificate came from a " +
			"trusted CA without ever verifying a chain.")
	} else if v.Severity != types.SeverityHigh {
		t.Fatalf("CERT_CHAIN_UNTRUSTED severity = %q, want %q", v.Severity, types.SeverityHigh)
	}

	factor := certificateFactor(t, result)
	if factor.Score != 0 {
		t.Fatalf("Certificate factor = %d/%d (%q), want 0", factor.Score, factor.MaxScore, factor.Details)
	}
	if factor.Details == "Valid certificate from trusted CA" {
		t.Fatal("the breakdown still claims a trusted CA for a chain that does not build to one")
	}
}

// TestScanDoesNotFlagANameThatTheCertificateCovers is the acceptance control.
// A guard that fails everything is a false clean of the opposite kind, and it
// would satisfy both tests above on its own.
func TestScanDoesNotFlagANameThatTheCertificateCovers(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	result := scanLocal(t, localScanConfig(), host, port)

	if v := findVulnerability(result, "CERT_NAME_MISMATCH"); v != nil {
		t.Fatalf("CERT_NAME_MISMATCH raised for a certificate carrying the 127.0.0.1 "+
			"IP SAN, which is exactly the name the scan asked for: %s", v.Description)
	}
}

// TestScanReportsTheTrustStoreItUsed keeps the trust verdict honest about being
// machine-dependent. The same host can be trusted on one machine and untrusted
// on another, and an operator reading "not trusted" has to be told that an
// internal CA has to be installed locally for the check to pass.
func TestScanReportsTheTrustStoreItUsed(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)
	result := scanLocal(t, localScanConfig(), host, port)

	found := false
	for _, w := range result.ScanWarnings {
		if contains(w, "trust store") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no scan warning naming the trust store the verdict came from; warnings were %q",
			result.ScanWarnings)
	}
}

// TestScanSaysWhichNameASNIOverrideVerified closes the one reading in which the
// verdict is still ambiguous: --sni asks for a different name, so the
// certificate verdict is about that name and not about the target the report is
// headed with.
func TestScanSaysWhichNameASNIOverrideVerified(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, []string{"elsewhere.invalid"}, nil, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	cfg := localScanConfig()
	cfg.SNI = "elsewhere.invalid"
	result := scanLocal(t, cfg, host, port)

	found := false
	for _, w := range result.ScanWarnings {
		if contains(w, "elsewhere.invalid") && contains(w, host) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no scan warning naming both the requested name and the target, so a reader "+
			"sees a passing certificate verdict under a heading for a different host; "+
			"warnings were %q", result.ScanWarnings)
	}
}

// TestScanDoesNotClaimAnSNISplitWhenThereIsNone is the negative half. A warning
// printed on every scan is a warning nobody reads.
func TestScanDoesNotClaimAnSNISplitWhenThereIsNone(t *testing.T) {
	notBefore, notAfter := validFrom()
	iss := issueLeaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	host, port := startLocalTLSServer(t, iss.serving)

	cfg := localScanConfig()
	cfg.SNI = host // the same name the target already carries
	result := scanLocal(t, cfg, host, port)

	for _, w := range result.ScanWarnings {
		if contains(w, "--sni requested the certificate for") {
			t.Fatalf("scan warned about an SNI override that matches the target: %q", w)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
