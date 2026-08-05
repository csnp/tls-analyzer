// Package scanner provides TLS scanning capabilities.
package scanner

import (
	"bytes"
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
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// Version is the scanner library default. Binaries built from cmd/tlsanalyzer
// override the value recorded in reports with their own release version,
// injected at build time.
const Version = "0.4.1"

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

	// TrustRoots is the pool used to decide whether a presented certificate
	// chain is trusted. nil means the scanning host's own trust store, which is
	// what a client on that host would use. Tests set it so that the verdict
	// does not depend on the trust store of the machine running them.
	TrustRoots *x509.CertPool
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

	// Resolve IP. A name that does not resolve was never measured, and must not
	// be presented as a scan result.
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	result.IP = ips[0].String()

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

	// Enumerate the cipher suites the server accepts, rather than reporting
	// only the one this client happened to negotiate.
	var offeredCiphers []types.CipherSuite
	wg.Add(1)
	go func() {
		defer wg.Done()
		ciphers, _ := s.probeCipherSuites(ctx, host, port)
		mu.Lock()
		offeredCiphers = ciphers
		mu.Unlock()
	}()

	wg.Wait()

	result.CipherSuites = mergeCipherSuites(result.CipherSuites, offeredCiphers)

	// A host that resolved but never completed a handshake was not measured
	// either. Reporting it as a graded result made an unreachable, firewalled or
	// non-TLS host indistinguishable from one measured to be insecure, and in a
	// --targets sweep every typo produced a confident failing row.
	if !anyProtocolSupported(result.Protocols) && result.Certificate == nil &&
		len(negotiated) == 0 && len(offered) == 0 {
		return nil, fmt.Errorf(
			"no TLS connection could be established to %s:%d (host unreachable, "+
				"port closed, or not speaking TLS)", host, port)
	}

	result.KeyExchanges = mergeKeyExchanges(negotiated, offered)
	if len(skipped) > 0 {
		result.ScanWarnings = append(result.ScanWarnings, fmt.Sprintf(
			"key exchange groups not probed because this build of the scanner cannot offer them: %s",
			strings.Join(skipped, ", ")))
	}

	// The protocol probe range, for the same reason: a version this scanner
	// cannot offer is absent from the results, and absence must not be read as
	// the server having it disabled. A policy that names SSL 2.0 or SSL 3.0
	// explicitly records the rule as not evaluated; a policy that only implies
	// them through a minimum version cannot, because every policy sets one and
	// marking them all incomplete would make that signal meaningless.
	result.ScanWarnings = append(result.ScanWarnings,
		"protocol support is probed for TLS 1.0 through TLS 1.3 only. Go's TLS stack "+
			"cannot offer SSL 2.0 or SSL 3.0, so this scan says nothing either way "+
			"about them, and a minimum-version rule is evaluated against the TLS "+
			"versions above. Confirm SSL 2.0 and SSL 3.0 are disabled with a scanner "+
			"built with legacy protocol support, such as nmap's ssl-enum-ciphers script")

	// Be explicit about the one enumeration this scanner cannot perform, so a
	// suite that is simply unobservable is never read as unsupported.
	result.ScanWarnings = append(result.ScanWarnings,
		"cipher suite enumeration is limited to the suites this scanner's TLS stack "+
			"can offer. TLS 1.3 suites cannot be probed individually at all, since Go "+
			"always offers all three and ignores per-suite configuration, so only the "+
			"negotiated TLS 1.3 suite is reported. Some TLS 1.2 suites Go does not "+
			"implement, such as the CBC-SHA256 and CBC-SHA384 families, cannot be "+
			"probed either, so a server may accept suites that do not appear here.")

	// And say whose preference the negotiated suite reflects, because the
	// enumeration limit above does not imply it. The suite marked as negotiated
	// is the one this scanner's client preference produced, not the server's:
	// openssl offering AES-256 first negotiates TLS_AES_256_GCM_SHA384 with the
	// same hosts for which this scanner reports TLS_AES_128_GCM_SHA256.
	result.ScanWarnings = append(result.ScanWarnings,
		"the suite marked negotiated is the one this scanner's own client preference "+
			"selected, not the server's preferred suite, which this scanner cannot "+
			"observe. A server offering both usually prefers AES-256 to a client that "+
			"offers AES-256 first")

	// The trust verdict depends on the machine the scan runs from, so say so.
	// The same host can be trusted on one machine and untrusted on another, and
	// a certificate issued by an internal CA is untrusted here unless that CA is
	// installed locally.
	if result.Certificate != nil {
		result.ScanWarnings = append(result.ScanWarnings,
			"the certificate chain is verified against the trust store of the machine running "+
				"this scan, so a certificate issued by an internal CA is reported untrusted "+
				"unless that CA is installed here")

		// Revocation is the check a reader is most likely to assume happened once
		// the chain verdict says the chain is trusted, and it is the one this
		// scanner does not perform. The rest of this section enumerates what the
		// scan does not cover, so leaving revocation out of it invites the reader
		// to treat the list as complete and the omission as a non-issue. Nothing
		// in the report claims a certificate is unrevoked; this says so out loud.
		result.ScanWarnings = append(result.ScanWarnings,
			"revocation is not checked. This scanner does not fetch CRLs or query OCSP, so a "+
				"chain reported as trusted may still have been revoked. Check revocation "+
				"separately, for example with 'openssl ocsp' or your CA's status endpoint")
	}

	// --sni asks the server for a different name than the target, so the
	// certificate verdict is about that other name. Both appear in the report,
	// but only together, so state the split rather than leaving a reader to
	// notice that "Target: example.com" and "valid for cloudflare.com" are not
	// the same claim.
	if s.config.SNI != "" && !strings.EqualFold(s.config.SNI, host) {
		// Both values are untrusted: --sni is typed at the command line and the
		// target may come from a --targets file someone else wrote. The reporter
		// sanitises every warning, which is what stops an escape sequence here
		// rewriting the report; bounding each value as well is what stops a long
		// one pushing the tool's own words past the report's 500-byte cap, since
		// this sentence ends with prose rather than beginning with it. A name
		// this long is not one anybody typed, and the truncation is visible.
		result.ScanWarnings = append(result.ScanWarnings, fmt.Sprintf(
			"--sni requested the certificate for %s, so the certificate checks answer for that "+
				"name and not for the target %s",
			sanitize.ForReport(s.config.SNI, maxWarningValue),
			sanitize.ForReport(host, maxWarningValue)))
	}

	if !s.config.CheckVulns {
		result.ScanWarnings = append(result.ScanWarnings,
			"vulnerability checks were skipped, so the grade carries no vulnerability penalties")
	}
	if !s.config.CheckQuantum {
		result.ScanWarnings = append(result.ScanWarnings,
			"quantum risk assessment was skipped and is excluded from the grade")
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

// hasTLS13 reports whether the target negotiated or accepted TLS 1.3.
func hasTLS13(protocols []types.Protocol) bool {
	for _, p := range protocols {
		if p.Version == "TLS 1.3" && p.Supported {
			return true
		}
	}
	return false
}

// mergeCipherSuites combines the negotiated suite with the enumerated ones,
// keeping the strongest first and removing duplicates.
func mergeCipherSuites(negotiated, offered []types.CipherSuite) []types.CipherSuite {
	seen := make(map[uint16]bool, len(negotiated)+len(offered))
	merged := make([]types.CipherSuite, 0, len(negotiated)+len(offered))

	for _, list := range [][]types.CipherSuite{negotiated, offered} {
		for _, cs := range list {
			if seen[cs.ID] {
				continue
			}
			seen[cs.ID] = true
			merged = append(merged, cs)
		}
	}

	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Bits != merged[j].Bits {
			return merged[i].Bits > merged[j].Bits
		}
		return merged[i].Name < merged[j].Name
	})
	return merged
}

// anyProtocolSupported reports whether at least one TLS version handshake
// succeeded, which is the minimum evidence that a scan measured anything.
func anyProtocolSupported(protocols []types.Protocol) bool {
	for _, p := range protocols {
		if p.Supported {
			return true
		}
	}
	return false
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

			addr := net.JoinHostPort(host, strconv.Itoa(port))
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

// probeCipherSuites enumerates which TLS 1.2 and earlier cipher suites the
// server accepts, by offering exactly one suite per handshake.
//
// Reporting only the single negotiated suite made the tool assert things it had
// not measured: a grade rationale of "all ciphers have forward secrecy" after
// asking once, and a CNSA 2.0 violation for a 128-bit cipher against servers
// that also offer AES-256.
//
// TLS 1.3 suites cannot be enumerated this way. Go's crypto/tls ignores
// Config.CipherSuites for TLS 1.3 and always offers all three, so the only TLS
// 1.3 suite observable from here is the negotiated one. That limit is reported
// to the caller rather than hidden, so an absent suite is never mistaken for an
// unsupported one.
func (s *Scanner) probeCipherSuites(ctx context.Context, host string, port int) (
	supported []types.CipherSuite, tls13Enumerable bool) {

	candidates := tls.CipherSuites()
	candidates = append(candidates, tls.InsecureCipherSuites()...)

	type slot struct {
		cs *types.CipherSuite
	}
	results := make([]slot, len(candidates))

	var wg sync.WaitGroup
	for i, suite := range candidates {
		// TLS 1.3 suites are not configurable; skip them here and let the
		// negotiated-connection probe report the one actually used.
		if isTLS13Suite(suite.ID) {
			continue
		}

		wg.Add(1)
		go func(idx int, id uint16) {
			defer wg.Done()

			cfg := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         s.getSNI(host),
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites:       []uint16{id},
			}

			addr := net.JoinHostPort(host, strconv.Itoa(port))
			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: s.config.ConnectTimeout},
				Config:    cfg,
			}

			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			state := conn.(*tls.Conn).ConnectionState()
			if state.CipherSuite != id {
				return
			}
			results[idx] = slot{cs: parseCipherSuite(id, state.Version)}
		}(i, suite.ID)
	}
	wg.Wait()

	for _, r := range results {
		if r.cs != nil {
			supported = append(supported, *r.cs)
		}
	}

	sort.SliceStable(supported, func(i, j int) bool {
		if supported[i].Bits != supported[j].Bits {
			return supported[i].Bits > supported[j].Bits
		}
		return supported[i].Name < supported[j].Name
	})

	return supported, false
}

// isTLS13Suite reports whether a cipher suite identifier belongs to TLS 1.3.
func isTLS13Suite(id uint16) bool {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return true
	}
	return false
}

// probeConnection connects with best available settings and extracts info.
func (s *Scanner) probeConnection(ctx context.Context, host string, port int) (
	*types.Certificate, []types.Certificate, []types.CipherSuite, []types.KeyExchange) {

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.getSNI(host),
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
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
		// One instant for every judgement about this connection's certificates.
		// The expiry flags, the chain verdict and the reason text each used to
		// read the clock separately, so a certificate crossing a boundary between
		// two of those reads produced a report whose certificate section and chain
		// line contradicted each other, in one direction blaming a CA that was
		// fine.
		now := time.Now()

		cert = parseCertificateAt(state.PeerCertificates[0], now)

		// The handshake above deliberately skipped verification. Run the two
		// checks it skipped, separately, so neither answer is inferred from the
		// other and neither is silently absent.
		verifyCertificateName(state.PeerCertificates[0], cert, cfg.ServerName)
		verifyCertificateChainAt(
			state.PeerCertificates[0], state.PeerCertificates[1:], cert,
			s.config.TrustRoots, now)

		for _, c := range state.PeerCertificates[1:] {
			chain = append(chain, *parseCertificateAt(c, now))
		}
	}

	// Extract cipher suite info
	var ciphers []types.CipherSuite
	cs := parseCipherSuite(state.CipherSuite, state.Version)
	if cs != nil {
		cs.Negotiated = true
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
	addr := net.JoinHostPort(host, strconv.Itoa(port))
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

// verifyCertificateName records whether the leaf certificate is valid for the
// name that was actually requested from the server.
//
// This is a name check only: it never consults a trust store, so it stays
// independent of verifyCertificateChain and both can be reported separately.
//
// The authoritative name is the one sent in the ClientHello, which is the
// --sni value when one was given and the target host otherwise. That is the
// name the server was asked for, so it is the name its answer has to match,
// and it keeps --sni usable as a deliberate virtual-host probe rather than as
// a way to switch the check off. Before this existed, both
// "tlsanalyzer wrong.host.badssl.com" and
// "tlsanalyzer example.com --sni cloudflare.com" were reported as valid
// certificates and awarded 25 of 25, while every browser rejects them.
func verifyCertificateName(leaf *x509.Certificate, parsed *types.Certificate, requestedName string) {
	parsed.RequestedName = requestedName

	if requestedName == "" {
		parsed.NameMatch = types.CheckNotPerformed
		parsed.NameMismatchReason = "no name was requested, so there is nothing to verify against"
		return
	}

	if err := leaf.VerifyHostname(requestedName); err != nil {
		parsed.NameMatch = types.CheckFailed
		parsed.NameMismatchReason = err.Error()
		return
	}

	parsed.NameMatch = types.CheckPassed
}

// verifyCertificateChain records whether the presented chain builds to a root
// the scanning host trusts, for server authentication.
//
// roots is nil in normal operation, which x509 reads as the host's own trust
// store. Tests pass an explicit pool so the suite never depends on the trust
// store of the machine it runs on.
//
// The LEAF's own validity window is deliberately not reported here. An expired
// leaf fails chain verification too, and reporting that as a second, differently
// worded trust failure would state one defect twice; the leaf's window has its
// own finding and its own place in the score.
//
// That exemption is about the leaf and only the leaf. Go returns
// CertificateInvalidError{Reason: Expired} for ANY certificate in the chain and
// names the offender in invalid.Cert, while Certificate.Expired and
// Certificate.NotYetValid are derived from the leaf alone. Applying the
// exemption without checking which certificate it describes swallowed an expired
// INTERMEDIATE, the most common real-world chain failure there is: a valid root,
// an expired intermediate and a perfectly current leaf reported the chain as not
// evaluated, scored the certificate dimension 25 of 25 as "Certificate is
// current", graded A 91/100 with zero findings, and passed the policy gate with
// exit 0. Nothing anywhere reported the window the reason string promised was
// "reported on its own", because for the leaf there was nothing to report.
func verifyCertificateChain(
	leaf *x509.Certificate,
	intermediates []*x509.Certificate,
	parsed *types.Certificate,
	roots *x509.CertPool,
) {
	verifyCertificateChainAt(leaf, intermediates, parsed, roots, time.Now())
}

// verifyCertificateChainAt is verifyCertificateChain as of a given instant.
//
// The instant governs the judgements THIS package makes: which end of its window
// a certificate is outside, and whether the leaf's own expiry is the thing being
// reported. It does NOT govern x509.Verify, which is not passed a CurrentTime
// and so reads the system clock itself. So a leaf that expires in the gap
// between the captured instant and the Verify call is current by this package's
// reckoning and expired by the verifier's, and the report then says the leaf is
// current while blaming the trust store for a certificate it never saw.
//
// In production the gap is the microseconds between capturing the instant and
// the call, so reaching it needs a leaf expiring inside that window. Passing
// CurrentTime closes it (both verifiers honour it; darwin calls
// SecTrustSetVerifyDate) but changes what every test driving a synthetic clock
// measures, so it is deferred to 0.4.1 rather than made late in a release.
// Stated here rather than left as "one clock for the whole verdict", which is
// what this comment used to claim and is not true.
func verifyCertificateChainAt(
	leaf *x509.Certificate,
	intermediates []*x509.Certificate,
	parsed *types.Certificate,
	roots *x509.CertPool,
	now time.Time,
) {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err == nil {
		parsed.ChainTrust = types.CheckPassed
		return
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		applyValidityWindowVerdict(leaf, invalid.Cert, intermediates, now, parsed)
		return
	}

	parsed.ChainTrust = types.CheckFailed
	parsed.ChainTrustReason = err.Error()
}

// applyValidityWindowVerdict decides what a validity-window failure somewhere in
// the chain means, given the leaf and whichever certificate the verifier blamed.
//
// It is a separate function because the decision has to hold for BOTH verifiers
// Go can use, and only one of them tells the truth about which certificate
// failed. When Roots is nil, which is what every real scan passes, Go routes to
// the platform verifier on darwin, windows and ios (verify.go: "Use platform
// verifiers, where available, if Roots is from SystemCertPool"). Those verifiers
// construct CertificateInvalidError{c, Expired, ...} with c bound to the LEAF
// whatever actually failed (root_darwin.go, root_windows.go), so on the
// platforms most operators run, invalid.Cert names the leaf even when an
// intermediate is the expired one.
//
// A first version of this fix compared invalid.Cert against the leaf and was
// therefore inert exactly where it mattered: on macOS the comparison always
// succeeded, the exemption always fired, and an expired intermediate still
// graded A 91/100 with zero findings. The whole suite stayed green because every
// test passes an explicit pool, which is the one configuration that reaches the
// pure-Go verifier.
//
// So the decision is made on the leaf's OWN window, read from the leaf here
// rather than from the parsed result: if the verifier reports a window failure
// and the leaf is inside its window, the certificate at fault is by definition
// not the leaf, whichever verifier answered.
//
// Reading it from the leaf rather than from parsed.Expired is deliberate. This
// function must not depend on the caller having populated the result first,
// because a hidden ordering coupling is the same shape of latent defect as the
// one being fixed, and the existing suite calls this with an empty result.
func applyValidityWindowVerdict(
	leaf *x509.Certificate,
	blamed *x509.Certificate,
	presented []*x509.Certificate,
	now time.Time,
	parsed *types.Certificate,
) {
	// The leaf's own window is reported on its own, by the expiry finding and by
	// the certificate dimension, so the chain check steps aside rather than
	// stating one defect twice.
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		parsed.ChainTrust = types.CheckNotPerformed
		parsed.ChainTrustReason = "not evaluated because the certificate is outside its validity period, " +
			"which is reported on its own"
		return
	}

	// The leaf is current, so something else in the chain is not. Nothing else
	// looks at those certificates, so this is the only place it can be reported.
	parsed.ChainTrust = types.CheckFailed

	// Prefer the verifier's answer when it identified a certificate other than
	// the leaf, since that is the one it actually rejected.
	if blamed != nil && !bytes.Equal(blamed.Raw, leaf.Raw) {
		parsed.ChainTrustReason = chainCertOutsideValidityReason(blamed, now)
		return
	}

	// Otherwise find the offender ourselves rather than telling the operator to
	// go and look. The platform verifier blames the leaf whatever failed, so its
	// answer is no answer at all; but the server presented the rest of the chain
	// on this same connection, and a certificate outside its window is visible
	// from the dates it carries. An earlier version of this branch printed "this
	// platform's verifier does not report which one, inspect the chain with
	// openssl", which sent the operator to fetch data the scanner was already
	// holding.
	for _, candidate := range presented {
		if candidate == nil || bytes.Equal(candidate.Raw, leaf.Raw) {
			continue
		}
		if now.After(candidate.NotAfter) || now.Before(candidate.NotBefore) {
			// Hedged, because the server chose this list and the platform verifier
			// did not say which certificate it rejected. This one is genuinely
			// outside its window and genuinely presented, both observed here; that
			// it is the reason the path failed is a further claim this code cannot
			// make, and a server can ship an expired extra certificate that is not
			// on the failing path at all.
			parsed.ChainTrustReason = chainCertOutsideValidityReason(candidate, now) +
				". That certificate was presented by this server and is outside its own " +
				"validity period; this platform's verifier does not say which certificate " +
				"it rejected, so check the rest of the chain too"
			return
		}
	}

	// Nothing the server presented is outside its window, so the offender is a
	// certificate this scan never saw: the platform verifier builds paths from
	// its own store, and can reject on a certificate the server did not send.
	// Say that rather than naming one, and do not say "expired": x509 reports the
	// same reason for both ends of the window and this branch is precisely the
	// one where nobody told us which end.
	parsed.ChainTrustReason = "a certificate in the chain is outside its validity period, so the " +
		"chain does not build to a trusted root. The leaf is current, and every certificate " +
		"this server presented is too, so the one at fault is a root or intermediate supplied " +
		"by this machine's trust store rather than by the server"
}

// chainCertOutsideValidityReason describes a chain certificate other than the
// leaf whose validity window has failed.
//
// x509 reports Expired for both ends of the window, so the message states which
// end it is rather than assuming expiry. The subject is named because the
// operator has to find that certificate to replace it, and it is not the one
// they were looking at.
func chainCertOutsideValidityReason(cert *x509.Certificate, now time.Time) string {
	if cert == nil {
		return "a certificate in the chain other than the leaf is outside its validity period"
	}

	name := chainCertName(cert)
	switch {
	case now.After(cert.NotAfter):
		return fmt.Sprintf(
			"the chain certificate %q expired on %s, so the chain does not build to a trusted root",
			name, cert.NotAfter.UTC().Format("2006-01-02"))
	case now.Before(cert.NotBefore):
		return fmt.Sprintf(
			"the chain certificate %q is not valid until %s, so the chain does not build to a trusted root",
			name, cert.NotBefore.UTC().Format("2006-01-02"))
	default:
		return fmt.Sprintf(
			"the chain certificate %q is outside its validity period, so the chain does not "+
				"build to a trusted root", name)
	}
}

// chainCertName identifies a certificate for a human who has to go and find it.
//
// The common name alone is not enough. CA certificates identified only by
// organization are real, particularly among the legacy cross-signed roots that
// expire and break chains, and naming one of those produced the literal empty
// string: `the chain certificate "" expired on ...`, which tells the operator
// nothing at exactly the moment the message exists to help. x509's own
// UnknownAuthorityError falls back the same way, to organization and then to the
// serial number.
func chainCertName(cert *x509.Certificate) string {
	// Decide emptiness on the SCRUBBED value, because that is what the reader
	// sees. Testing the raw value let a common name of 300 control bytes count as
	// present, so no fallback fired, and scrubbing then emptied it: the reason
	// rendered as `the chain certificate "" expired on ...`, which is the exact
	// literal this fallback exists to prevent. A value is present only if it
	// survives the transformation the report applies to it.
	// Common name, then organization, then organizational unit, then the serial.
	//
	// The middle steps used to be a single one, Subject.String(), which is a
	// FORMATTED string carrying structural punctuation of its own. A subject whose
	// values all scrub away still renders as "CN=", so the fallback did not fire
	// and the reason named the certificate "CN=" instead of "": less obviously
	// broken and exactly as useless, which is the shape of a fix applied to the
	// symptom rather than the defect.
	//
	// Reading the attributes individually avoids that. The organizational unit is
	// here because dropping straight to the serial for a certificate carrying one
	// is a real loss of message quality: several long-lived roots are identified
	// by OU alone, and a serial number is the worst identifier for a human who has
	// to go and find the certificate. x509's own UnknownAuthorityError stops at
	// organization, which is the precedent this followed at first, but matching it
	// is a weaker reason than naming the certificate well.
	candidates := []string{cert.Subject.CommonName}
	candidates = append(candidates, cert.Subject.Organization...)
	candidates = append(candidates, cert.Subject.OrganizationalUnit...)
	for _, candidate := range candidates {
		if scrubbed := sanitize.ForReport(candidate, sanitize.MaxReportDetail); scrubbed != "" {
			return truncateChainCertName(scrubbed)
		}
	}
	return "serial " + cert.SerialNumber.String()
}

// maxChainCertName bounds the server-chosen part of a chain-failure reason.
//
// The report caps the whole rendered line, and the name sits at the FRONT of the
// sentence this package builds, so without a bound of its own a server could
// push the tool's own words off the end. Measured: an intermediate whose common
// name was 474 bytes ending "and this certificate is valid; the chain builds to
// a trusted root" produced a chain-trust line containing that phrase and neither
// the word "expired" nor the date.
//
// The bound is applied to the name AS %q WILL RENDER IT, not to its byte length.
// Capping the raw name was not enough: %q expands a control byte to four
// printable ones, so 120 raw control bytes rendered as 473 and blew the report's
// own budget. Scrubbing first was not enough either, which is the correction
// this release makes: scrubbing removes control bytes but leaves the Unicode
// FORMAT characters alone, and %q escapes those to six characters each, so a
// scrubbed 120-byte name still rendered to roughly 300 and truncated the hedge
// off the end of the composed reason. Measuring what %q produces is the only
// bound that holds for every input.
const maxChainCertName = 120

// maxWarningValue bounds an untrusted value interpolated into a scan warning.
//
// Smaller than the report's field budget because a warning is tool prose with
// values inside it, and the prose has to survive: the sentence does not end with
// the value. A DNS name may legally reach 253 bytes, but one longer than this is
// not a name anyone typed, and the truncation is visible to the reader.
const maxWarningValue = 120

func truncateChainCertName(name string) string {
	if quotedWidth(name) <= maxChainCertName {
		return name
	}
	// Cut on a rune boundary; slicing bytes would emit invalid UTF-8. The budget
	// is spent in RENDERED characters, so a rune that %q will escape costs what
	// its escape costs rather than what it occupies in memory.
	var b strings.Builder
	total := 0
	for _, r := range name {
		w := quotedWidth(string(r))
		if total+w > maxChainCertName-3 {
			break
		}
		b.WriteRune(r)
		total += w
	}
	return b.String() + "..."
}

// quotedWidth reports how many characters %q renders s as, excluding the
// surrounding quotes.
//
// strconv.Quote escapes each rune independently, so for VALID UTF-8 the widths
// sum and a caller can spend the budget one rune at a time. That does not hold
// for invalid UTF-8: a lone 0xff renders as one escape whole-string but decodes
// to U+FFFD when ranged, so the per-rune sum undercounts. The only caller feeds
// this sanitize.ForReport output, which is always valid UTF-8 because ranging a
// string yields U+FFFD for every invalid byte. A caller passing raw input would
// get a silent undercount and a result over the bound.
func quotedWidth(s string) int {
	return len(strconv.Quote(s)) - 2
}

// parseCertificate extracts relevant info from an x509 certificate, as of now.
//
// Production uses parseCertificateAt so that the judgements this package makes
// about one connection share a single instant; this wrapper keeps the simpler
// signature for callers that do not care. x509.Verify is the exception and reads
// its own clock, which verifyCertificateChainAt records.
func parseCertificate(cert *x509.Certificate) *types.Certificate {
	return parseCertificateAt(cert, time.Now())
}

// parseCertificateAt extracts relevant info as of the given instant.
func parseCertificateAt(cert *x509.Certificate, now time.Time) *types.Certificate {

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
		// Both checks start as not performed. Only the leaf is checked, by the
		// caller; a certificate in the presented chain keeps this state, so
		// nothing anywhere can read an unchecked certificate as a passing one.
		NameMatch:  types.CheckNotPerformed,
		ChainTrust: types.CheckNotPerformed,

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
		NotYetValid:        now.Before(cert.NotBefore),
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
			cs.Encryption = "ChaCha20-Poly1305"
			// ChaCha20 is defined only with a 256-bit key, and the suite name
			// carries no key-size token, so it must be set here or the suite
			// reports 0 bits and reads as weaker than AES-128.
			cs.Bits = 256
		case part == "3DES":
			cs.Encryption = "3DES"
			// Three-key 3DES carries a 168-bit key, but meet-in-the-middle
			// reduces its effective strength to 112 bits, and the 64-bit block
			// makes it vulnerable to Sweet32. Report the key size for
			// consistency with the other suites and state the real strength in
			// the deprecation reason rather than overstating it in a number.
			cs.Bits = 168
			cs.Deprecated = true
			cs.DeprecatedReason = "3DES has only 112-bit effective strength and a " +
				"64-bit block, which exposes it to Sweet32 (CVE-2016-2183)"
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

	// A port that is not a number silently fell back to 443, so
	// "example.com:abc" reported Target example.com:abc and Port 443 and scanned
	// a port the user never named. The same class as the --format fallback fixed
	// in 0.3.0: an unusable argument must be refused, not reinterpreted.
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return "", 0, fmt.Errorf(
			"invalid port %q: must be a number between 1 and 65535", portStr)
	}
	if err := ValidatePort(port); err != nil {
		return "", 0, err
	}

	return host, port, nil
}

// ValidatePort rejects a port outside the TCP range.
//
// An out-of-range port reached the dialer and produced "no TLS connection could
// be established to example.com:-5 (host unreachable, port closed, or not
// speaking TLS)", which describes the host rather than the rejected argument.
// This is the single check behind both the -p/--port flag and a port written
// into the target, so neither route can accept what the other refuses.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	return nil
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
