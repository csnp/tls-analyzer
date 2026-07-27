// Package scanner provides TLS scanning capabilities.
package scanner

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Version is the scanner library default. Binaries built from cmd/tlsanalyzer
// override the value recorded in reports with their own release version,
// injected at build time.
const Version = "0.3.0"

// Scanner performs TLS analysis on targets.
type Scanner struct {
	config *Config
}

// Config holds scanner configuration.
type Config struct {
	Timeout        time.Duration
	ConnectTimeout time.Duration
	Concurrency    int
	SkipCertVerify bool
	SNI            string
	CheckVulns     bool
	CheckQuantum   bool
	MinTLSVersion  uint16
	MaxTLSVersion  uint16
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Timeout:        30 * time.Second,
		ConnectTimeout: 10 * time.Second,
		Concurrency:    10,
		SkipCertVerify: true, // We're analyzing, not validating
		CheckVulns:     true,
		CheckQuantum:   true,
		MinTLSVersion:  0x0300, // SSL 3.0 - needed to detect insecure configurations
		MaxTLSVersion:  tls.VersionTLS13,
	}
}

// New creates a new Scanner with the given config.
func New(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Scanner{config: cfg}
}

// Scan performs a complete TLS analysis of the target.
func (s *Scanner) Scan(ctx context.Context, target string) (*types.ScanResult, error) {
	start := time.Now()

	host, port, err := parseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	result := &types.ScanResult{
		Target:         target,
		Host:           host,
		Port:           port,
		Timestamp:      start,
		ScannerVersion: Version,
	}

	// Resolve IP
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		result.IP = ips[0].String()
	}

	// Run probes concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Probe protocols
	wg.Add(1)
	go func() {
		defer wg.Done()
		protocols := s.probeProtocols(ctx, host, port)
		mu.Lock()
		result.Protocols = protocols
		mu.Unlock()
	}()

	// Get certificate and cipher suites (from preferred connection)
	var negotiated []types.KeyExchange
	wg.Add(1)
	go func() {
		defer wg.Done()
		cert, chain, ciphers, keyExchanges := s.probeConnection(ctx, host, port)
		mu.Lock()
		result.Certificate = cert
		result.CertChain = chain
		result.CipherSuites = ciphers
		negotiated = keyExchanges
		mu.Unlock()
	}()

	// Enumerate which key exchange groups the server supports, which is a
	// broader question than which one this client negotiated.
	var offered []types.KeyExchange
	var skipped []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		groups, unavailable := s.probeKeyExchangeGroups(ctx, host, port)
		mu.Lock()
		offered = groups
		skipped = unavailable
		mu.Unlock()
	}()

	wg.Wait()

	result.KeyExchanges = mergeKeyExchanges(negotiated, offered)
	if len(skipped) > 0 {
		result.ScanWarnings = append(result.ScanWarnings, fmt.Sprintf(
			"key exchange groups not probed because this build of the scanner cannot offer them: %s",
			strings.Join(skipped, ", ")))
	}

	// Analyze results
	if s.config.CheckVulns {
		result.Vulnerabilities = s.checkVulnerabilities(result)
	}

	if s.config.CheckQuantum {
		result.QuantumRisk = s.assessQuantumRisk(result)
	}

	result.Grade = s.calculateGrade(result)
	result.Recommendations = s.generateRecommendations(result)

	result.Duration = types.Duration{Duration: time.Since(start)}
	return result, nil
}

// probeProtocols checks which TLS versions are supported.
func (s *Scanner) probeProtocols(ctx context.Context, host string, port int) []types.Protocol {
	versions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	// Results are written to a fixed index per version so that the output order
	// always matches the declared version order (highest first), independent of
	// which probe finishes first.
	protocols := make([]types.Protocol, len(versions))
	var wg sync.WaitGroup

	// Check each version concurrently
	for i, v := range versions {
		wg.Add(1)
		go func(idx int, ver uint16, name string) {
			defer wg.Done()

			cfg := &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         ver,
				MaxVersion:         ver,
				ServerName:         s.getSNI(host),
			}

			protocols[idx] = types.Protocol{
				Version:   name,
				Supported: s.tryConnect(ctx, host, port, cfg),
			}
		}(i, v.version, v.name)
	}

	wg.Wait()

	// TLS negotiates the highest version both peers support, so the highest
	// supported version is the one an ordinary client would end up using.
	for i := range protocols {
		if protocols[i].Supported {
			protocols[i].Preferred = true
			break
		}
	}

	return protocols
}

// mergeKeyExchanges combines the group this scan negotiated with the groups the
// server was found to support, marking the negotiated one and keeping the
// strongest entries first so readers see post-quantum support up front.
func mergeKeyExchanges(negotiated, offered []types.KeyExchange) []types.KeyExchange {
	byName := make(map[string]types.KeyExchange, len(negotiated)+len(offered))
	order := make([]string, 0, len(negotiated)+len(offered))

	add := func(ke types.KeyExchange, isNegotiated bool) {
		existing, seen := byName[ke.Name]
		if seen {
			existing.Negotiated = existing.Negotiated || isNegotiated
			byName[ke.Name] = existing
			return
		}
		ke.Negotiated = isNegotiated
		byName[ke.Name] = ke
		order = append(order, ke.Name)
	}

	for _, ke := range negotiated {
		add(ke, true)
	}
	for _, ke := range offered {
		add(ke, false)
	}

	merged := make([]types.KeyExchange, 0, len(order))
	for _, name := range order {
		merged = append(merged, byName[name])
	}

	// Rank post-quantum groups ahead of classical ones, then by key size, so
	// the ordering is deterministic and does not depend on probe timing.
	rank := map[string]int{"pqc": 0, "hybrid": 1, "classical": 2, "unknown": 3}
	sort.SliceStable(merged, func(i, j int) bool {
		ri, rj := rank[merged[i].Type], rank[merged[j].Type]
		if ri != rj {
			return ri < rj
		}
		if merged[i].Bits != merged[j].Bits {
			return merged[i].Bits > merged[j].Bits
		}
		return merged[i].Name < merged[j].Name
	})
	return merged
}

// toolchainSupportsGroup reports whether the running Go toolchain implements a
// supported group. crypto/tls renders groups it knows by name and falls back to
// a numeric form otherwise, so an unnamed group is one this build cannot offer.
// Probing such a group would fail for a reason unrelated to the server, which
// would misreport a capable server as lacking post-quantum support.
func toolchainSupportsGroup(id tls.CurveID) bool {
	return !strings.HasPrefix(id.String(), "CurveID(")
}

// probeKeyExchangeGroups determines which key exchange groups the server
// actually supports, by offering exactly one group per handshake. This reports
// server capability rather than only the group this client happened to
// negotiate, which is what a readiness assessment needs.
//
// Groups this Go build cannot offer are skipped rather than reported
// unsupported; skipped groups are returned so callers can be explicit about
// coverage instead of implying a negative result.
func (s *Scanner) probeKeyExchangeGroups(ctx context.Context, host string, port int) (
	supported []types.KeyExchange, skipped []string) {

	candidates := []tls.CurveID{
		groupX25519MLKEM768,
		groupSecP256r1MLKEM768,
		groupSecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}

	type probeResult struct {
		ke      *types.KeyExchange
		skipped string
	}
	results := make([]probeResult, len(candidates))

	var wg sync.WaitGroup
	for i, id := range candidates {
		if !toolchainSupportsGroup(id) {
			info := tlsGroups[id]
			results[i] = probeResult{skipped: info.name}
			continue
		}

		wg.Add(1)
		go func(idx int, group tls.CurveID) {
			defer wg.Done()

			cfg := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         s.getSNI(host),
				MinVersion:         tls.VersionTLS12,
				CurvePreferences:   []tls.CurveID{group},
			}

			addr := fmt.Sprintf("%s:%d", host, port)
			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: s.config.ConnectTimeout},
				Config:    cfg,
			}

			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			// Confirm the server actually selected the offered group rather
			// than assuming a successful handshake implies it.
			state := conn.(*tls.Conn).ConnectionState()
			if state.CurveID == group {
				results[idx] = probeResult{ke: keyExchangeFromGroup(group)}
			}
		}(i, id)
	}
	wg.Wait()

	for _, r := range results {
		switch {
		case r.ke != nil:
			supported = append(supported, *r.ke)
		case r.skipped != "":
			skipped = append(skipped, r.skipped)
		}
	}
	return supported, skipped
}

// probeConnection connects with best available settings and extracts info.
func (s *Scanner) probeConnection(ctx context.Context, host string, port int) (
	*types.Certificate, []types.Certificate, []types.CipherSuite, []types.KeyExchange) {

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.getSNI(host),
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: s.config.ConnectTimeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil, nil, nil, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Extract certificate info
	var cert *types.Certificate
	var chain []types.Certificate

	if len(state.PeerCertificates) > 0 {
		cert = parseCertificate(state.PeerCertificates[0])
		for _, c := range state.PeerCertificates[1:] {
			chain = append(chain, *parseCertificate(c))
		}
	}

	// Extract cipher suite info
	var ciphers []types.CipherSuite
	cs := parseCipherSuite(state.CipherSuite, state.Version)
	if cs != nil {
		ciphers = append(ciphers, *cs)
	}

	// Extract key exchange info
	var keyExchanges []types.KeyExchange
	ke := parseKeyExchange(state)
	if ke != nil {
		keyExchanges = append(keyExchanges, *ke)
	}

	return cert, chain, ciphers, keyExchanges
}

// tryConnect attempts a TLS connection with the given config.
func (s *Scanner) tryConnect(ctx context.Context, host string, port int, cfg *tls.Config) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: s.config.ConnectTimeout},
		Config:    cfg,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *Scanner) getSNI(host string) string {
	if s.config.SNI != "" {
		return s.config.SNI
	}
	return host
}

// parseCertificate extracts relevant info from an x509 certificate.
func parseCertificate(cert *x509.Certificate) *types.Certificate {
	now := time.Now()

	// Calculate fingerprints
	sha256sum := sha256Fingerprint(cert.Raw)
	sha1sum := sha1Fingerprint(cert.Raw)

	// Extract key usage
	var keyUsage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "digitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "keyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsage = append(keyUsage, "keyAgreement")
	}

	// Extract extended key usage
	var extKeyUsage []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, "codeSigning")
		}
	}

	bits := publicKeyBits(cert.PublicKey)
	algo := cert.PublicKeyAlgorithm.String()

	// A certificate is quantum-safe only if both the key it carries and the
	// signature over it are post-quantum. Go's x509 parser only understands
	// classical algorithms today, so anything it names is quantum-vulnerable;
	// an algorithm it cannot name is reported as unknown rather than assumed safe.
	quantumSafe := isQuantumSafeCertificate(cert)

	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &types.Certificate{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: algo,
		PublicKeyBits:      bits,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		SANs:               cert.DNSNames,
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.String() == cert.Issuer.String(),
		QuantumSafe:        quantumSafe,
		DaysUntilExpiry:    daysUntilExpiry,
		Expired:            now.After(cert.NotAfter),
		Fingerprints: types.Fingerprints{
			SHA256: sha256sum,
			SHA1:   sha1sum,
		},
	}
}

// parseCipherSuite extracts cipher suite details.
func parseCipherSuite(id uint16, version uint16) *types.CipherSuite {
	name := tls.CipherSuiteName(id)
	if name == "" {
		name = fmt.Sprintf("0x%04X", id)
	}

	cs := &types.CipherSuite{
		ID:       id,
		Name:     name,
		Protocol: tlsVersionName(version),
	}

	// Parse cipher suite components
	parseCSComponents(cs, name)

	return cs
}

// parseCSComponents parses cipher suite name into components.
func parseCSComponents(cs *types.CipherSuite, name string) {
	// TLS 1.3 cipher suites
	if strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_") {
		cs.KeyExchange = "any" // TLS 1.3 separates key exchange
		cs.Authentication = "any"
		cs.ForwardSecrecy = true

		// Match the encryption key size specifically. A bare Contains(name,
		// "256") would match the SHA256 suffix of TLS_AES_128_GCM_SHA256 and
		// report a 128-bit cipher as 256-bit.
		switch {
		case strings.Contains(name, "AES_128"):
			cs.Bits = 128
			cs.Encryption = "AES-GCM"
		case strings.Contains(name, "AES_256"):
			cs.Bits = 256
			cs.Encryption = "AES-GCM"
		case strings.Contains(name, "CHACHA20"):
			cs.Bits = 256
			cs.Encryption = "ChaCha20-Poly1305"
		}

		// In TLS 1.3 the key exchange is negotiated separately from the cipher
		// suite, so this flag describes only the bulk cipher's resistance to
		// Grover's algorithm, which halves the effective key length. A 256-bit
		// key retains 128-bit security and meets CNSA 2.0; a 128-bit key does
		// not. The key exchange is reported separately in keyExchanges.
		cs.QuantumSafe = cs.Bits >= 256
		return
	}

	// TLS 1.2 and earlier
	parts := strings.Split(name, "_")
	for i, part := range parts {
		switch {
		case part == "ECDHE" || part == "DHE":
			cs.KeyExchange = part
			cs.ForwardSecrecy = true
		case part == "RSA" && i < 3:
			if cs.KeyExchange == "" {
				cs.KeyExchange = "RSA"
			}
			cs.Authentication = "RSA"
		case part == "ECDSA":
			cs.Authentication = "ECDSA"
		case strings.HasPrefix(part, "AES"):
			cs.Encryption = "AES"
		case part == "CHACHA20":
			cs.Encryption = "ChaCha20"
		case part == "3DES":
			cs.Encryption = "3DES"
			cs.Deprecated = true
			cs.DeprecatedReason = "3DES is deprecated due to small block size"
		case part == "RC4":
			cs.Encryption = "RC4"
			cs.Deprecated = true
			cs.DeprecatedReason = "RC4 is broken"
		case part == "128":
			cs.Bits = 128
		case part == "256":
			cs.Bits = 256
		case part == "SHA256" || part == "SHA384":
			cs.MAC = part
		case part == "SHA":
			cs.MAC = "SHA1"
		case part == "MD5":
			cs.MAC = "MD5"
			cs.Deprecated = true
			cs.DeprecatedReason = "MD5 is broken"
		}
	}

	// For TLS 1.2 and earlier the key exchange is part of the cipher suite
	// itself, and every such exchange in use today (RSA, DHE, ECDHE) falls to
	// Shor's algorithm. A strong bulk cipher does not rescue the handshake, so
	// these suites are never quantum-safe regardless of key size.
	cs.QuantumSafe = false
}

// IANA TLS Supported Groups code points for the hybrid post-quantum key
// exchanges (RFC 8446 registry). These are declared here rather than taken from
// crypto/tls because the standard library only exports SecP256r1MLKEM768 and
// SecP384r1MLKEM1024 from Go 1.26, and this module keeps a Go 1.25 floor.
// TestHybridGroupCodePoints asserts these stay in step with the standard library.
const (
	groupSecP256r1MLKEM768  tls.CurveID = 4587
	groupX25519MLKEM768     tls.CurveID = 4588
	groupSecP384r1MLKEM1024 tls.CurveID = 4589
)

// groupInfo describes a TLS key exchange group.
type groupInfo struct {
	name         string
	kind         string // "classical", "hybrid", or "pqc"
	curve        string
	bits         int // classical security strength of the group
	pqcAlgorithm string
	classical    string
}

// tlsGroups maps negotiated TLS supported groups to their properties. A hybrid
// group combines a classical exchange with an ML-KEM encapsulation, so the
// session key stays secret unless an attacker breaks both.
var tlsGroups = map[tls.CurveID]groupInfo{
	tls.CurveP256: {name: "secp256r1", kind: "classical", curve: "P-256", bits: 256},
	tls.CurveP384: {name: "secp384r1", kind: "classical", curve: "P-384", bits: 384},
	tls.CurveP521: {name: "secp521r1", kind: "classical", curve: "P-521", bits: 521},
	tls.X25519:    {name: "X25519", kind: "classical", curve: "X25519", bits: 256},
	groupX25519MLKEM768: {
		name: "X25519MLKEM768", kind: "hybrid", curve: "X25519", bits: 256,
		pqcAlgorithm: "ML-KEM-768", classical: "X25519",
	},
	groupSecP256r1MLKEM768: {
		name: "SecP256r1MLKEM768", kind: "hybrid", curve: "P-256", bits: 256,
		pqcAlgorithm: "ML-KEM-768", classical: "P-256",
	},
	groupSecP384r1MLKEM1024: {
		name: "SecP384r1MLKEM1024", kind: "hybrid", curve: "P-384", bits: 384,
		pqcAlgorithm: "ML-KEM-1024", classical: "P-384",
	},
}

// keyExchangeFromGroup builds a KeyExchange from a negotiated supported group.
func keyExchangeFromGroup(id tls.CurveID) *types.KeyExchange {
	info, known := tlsGroups[id]
	if !known {
		// Report the raw code point rather than guessing. An unrecognized group
		// is not evidence of quantum safety.
		return &types.KeyExchange{
			Name:        fmt.Sprintf("unknown group 0x%04X", uint16(id)),
			Type:        "unknown",
			QuantumSafe: false,
		}
	}

	return &types.KeyExchange{
		Name:            info.name,
		Type:            info.kind,
		Curve:           info.curve,
		Bits:            info.bits,
		QuantumSafe:     info.kind == "hybrid" || info.kind == "pqc",
		PQCAlgorithm:    info.pqcAlgorithm,
		HybridClassical: info.classical,
	}
}

// parseKeyExchange extracts key exchange info from connection state.
// TLS 1.3 negotiates the key exchange as a supported group independent of the
// cipher suite; ConnectionState.CurveID (Go 1.25+) reports which one was used.
func parseKeyExchange(state tls.ConnectionState) *types.KeyExchange {
	if state.CurveID == 0 {
		// No key agreement took place (for example a TLS 1.2 static RSA
		// exchange), so there is no group to report.
		return nil
	}

	return keyExchangeFromGroup(state.CurveID)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0x0300: // SSL 3.0
		return "SSL 3.0"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func parseTarget(target string) (string, int, error) {
	// Add default port if not specified
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}

	port := 443
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	return host, port, nil
}

// sha256Fingerprint returns the SHA-256 fingerprint of a DER-encoded
// certificate as lowercase hex, matching `openssl x509 -fingerprint -sha256`.
func sha256Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// sha1Fingerprint returns the SHA-1 fingerprint of a DER-encoded certificate as
// lowercase hex. SHA-1 is collision-broken and is reported only because some
// certificate inventories and pinning configurations still key off it.
func sha1Fingerprint(der []byte) string {
	sum := sha1.Sum(der)
	return hex.EncodeToString(sum[:])
}

// publicKeyBits returns the key size in bits for a certificate public key.
// For elliptic curve keys this is the curve size, not the encoded point length.
// Returns 0 only when the key type is genuinely unrecognized.
func publicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve == nil || k.Params() == nil {
			return 0
		}
		return k.Params().BitSize
	case ed25519.PublicKey:
		return len(k) * 8
	case *ecdh.PublicKey:
		switch k.Curve() {
		case ecdh.X25519():
			return 256
		case ecdh.P256():
			return 256
		case ecdh.P384():
			return 384
		case ecdh.P521():
			return 521
		}
		return 0
	default:
		return 0
	}
}

// isQuantumSafeCertificate reports whether a certificate is protected against
// cryptanalytically relevant quantum computers. Every algorithm Go's x509
// package can currently parse is breakable by Shor's algorithm, so this returns
// false for all recognized algorithms and false (not true) for unrecognized
// ones: an unknown algorithm is not evidence of post-quantum protection.
func isQuantumSafeCertificate(cert *x509.Certificate) bool {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA, x509.ECDSA, x509.Ed25519, x509.DSA:
		return false
	default:
		return false
	}
}
