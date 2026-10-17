package analyzer

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The quantum.minQuantumScore Fix ends with an openssl Verify, and the report
// caps a Fix at sanitize.MaxReportDetail bytes by cutting its end. Only the
// certificate note gave way to the command, so for longer host or --sni names
// the Verify was cut mid-command in every format. Measured through Evaluate
// with port 443, no --sni and an ECDSA certificate, the first host name length
// whose Verify was cut was 64 for a classical server under cnsa-2.0-2030, 35
// under cnsa-2.0-2035, and 111 and 83 for a hybrid server.
//
// The Fix also recommended pure ML-KEM key exchange on its score alone, which
// this scanner cannot detect: it never offers a pure ML-KEM group, so a server
// that accepts one is still scored as before.

// hostOfLength is a host name of exactly n bytes, in labels of at most 50
// letters, so every label is a legal DNS label and none is empty.
func hostOfLength(n int) string {
	var labels []string
	for remaining := n; remaining > 0; {
		size := min(50, remaining)
		if remaining-size == 1 {
			size-- // leave room for a dot and a one-letter label
		}
		labels = append(labels, strings.Repeat("a", size))
		remaining -= size
		if remaining > 0 {
			remaining-- // the dot
		}
	}
	return strings.Join(labels, ".")
}

type fixCase struct {
	keyExchange types.KeyExchange
	policy      string
	port        int
	host        string
	serverName  string // empty: the scan sent the host itself
}

// fixFor evaluates the case and returns its quantum.minQuantumScore Fix, or ok
// false when the posture already meets the policy's minimum.
func fixFor(t *testing.T, c fixCase) (fix string, ok bool) {
	t.Helper()
	scan := quantumPostureScan([]types.KeyExchange{c.keyExchange}, "ECDSA")
	scan.Host, scan.Port = c.host, c.port
	e := NewPolicyEvaluator()
	e.ServerName = c.serverName
	policy, found := e.GetPolicy(c.policy)
	if !found {
		t.Fatalf("built-in policy %s not found", c.policy)
	}
	if scan.QuantumRisk.Score >= policy.Rules.Quantum.MinQuantumScore {
		return "", false
	}
	for _, v := range e.Evaluate(scan, policy).Violations {
		if v.Rule == "quantum.minQuantumScore" {
			return v.Remediation, true
		}
	}
	t.Fatalf("%+v: no quantum.minQuantumScore violation", c)
	return "", false
}

// expectedVerify is the command the Fix must end with, built here rather than
// by the evaluator: a classical server is asked about the hybrid group it is
// told to enable, and a hybrid server about pure ML-KEM.
func expectedVerify(c fixCase) string {
	label, group := "Verify pure ML-KEM support: ", "MLKEM1024"
	if c.keyExchange.Type == "classical" {
		label, group = "Verify hybrid ML-KEM support: ", "X25519MLKEM768"
	}
	name := c.serverName
	if name == "" {
		name = c.host
	}
	cmd := "openssl s_client -connect " + net.JoinHostPort(c.host, strconv.Itoa(c.port))
	if net.ParseIP(name) == nil {
		cmd += " -servername " + name
	}
	return label + cmd + " -groups " + group + " </dev/null"
}

// TestQuantumScoreFixEndsWithTheWholeVerifyWheneverItFits covers classical
// and hybrid servers under each policy whose minimum they miss, at port 443 and
// a five-digit port, for every host name length whose Verify fits the cap on
// its own, with and without a --sni name.
func TestQuantumScoreFixEndsWithTheWholeVerifyWheneverItFits(t *testing.T) {
	checked := map[string]int{}
	for _, ke := range []types.KeyExchange{classicalKeyExchange, hybridKeyExchange} {
		for _, policy := range []string{"cnsa-2.0-2027", "cnsa-2.0-2030", "cnsa-2.0-2035"} {
			for _, port := range []int{443, 19631} {
				for n := 1; n <= 254; n++ {
					for _, c := range []fixCase{
						{keyExchange: ke, policy: policy, port: port, host: hostOfLength(n)},
						{keyExchange: ke, policy: policy, port: port, host: "127.0.0.1",
							serverName: hostOfLength(n)},
					} {
						verify := expectedVerify(c)
						if len(verify) > sanitize.MaxReportDetail {
							continue // longer than the cap on its own; see the docs
						}
						fix, fires := fixFor(t, c)
						if !fires {
							continue
						}
						checked[ke.Type+" "+policy]++
						if !strings.HasSuffix(fix, verify) {
							t.Errorf("%s server, %s, host %d bytes, --sni %d bytes, port %d: the Fix "+
								"does not end with the whole Verify %q:\n%s", ke.Type, policy,
								len(c.host), len(c.serverName), port, verify, fix)
						}
						if len(fix) > sanitize.MaxReportDetail {
							t.Errorf("%s server, %s, host %d bytes: the Fix is %d bytes, over the "+
								"%d-byte cap", ke.Type, policy, len(c.host), len(fix), sanitize.MaxReportDetail)
						}
						// What to do, even without its score, outlasts every other
						// sentence: it goes only when it no longer fits beside the Verify.
						opening := "Hybrid ML-KEM key exchange is already in place"
						if ke.Type == "classical" {
							opening = "Enable hybrid ML-KEM key exchange"
						}
						if len(opening)+2+len(verify) <= sanitize.MaxReportDetail &&
							!strings.HasPrefix(fix, opening) {
							t.Errorf("%s server, %s, host %d bytes, --sni %d bytes: the Fix does not "+
								"open with %q although it fits:\n%s", ke.Type, policy, len(c.host),
								len(c.serverName), opening, fix)
						}
						if strings.Contains(strings.ToLower(fix), "pure ml-kem key exchange would reach") &&
							!strings.Contains(fix, undetectedPureMLKEM) {
							t.Errorf("%s server, %s, host %d bytes: the pure ML-KEM step is named "+
								"without saying the scanner cannot detect it:\n%s", ke.Type, policy, len(c.host), fix)
						}
					}
				}
			}
		}
	}

	// The measured cases from the report, each of which cut the Verify before.
	for _, want := range []string{"classical cnsa-2.0-2030", "classical cnsa-2.0-2035",
		"hybrid cnsa-2.0-2030", "hybrid cnsa-2.0-2035", "classical cnsa-2.0-2027"} {
		if checked[want] == 0 {
			t.Errorf("no %s case fired the rule, so that case was not checked", want)
		}
	}
}

// TestQuantumScoreFixKeepsTheVerifyForTheReportedSNI is the end-to-end
// reproduction: a classical server on 127.0.0.1 at a five-digit port, scanned
// with a 61-character --sni name under cnsa-2.0-2035. Its Fix was 500 bytes and
// ended "-groups X25519MLKEM768 </dev/...".
func TestQuantumScoreFixKeepsTheVerifyForTheReportedSNI(t *testing.T) {
	c := fixCase{
		keyExchange: classicalKeyExchange, policy: "cnsa-2.0-2035", port: 19631,
		host: "127.0.0.1", serverName: "internal-billing-api-1234567890.us-west-2.elb.amazonaws.com",
	}
	fix, fires := fixFor(t, c)
	if !fires {
		t.Fatal("the rule does not fire for a classical server under cnsa-2.0-2035")
	}
	if verify := expectedVerify(c); !strings.HasSuffix(fix, verify) {
		t.Errorf("the Fix does not end with the whole Verify %q:\n%s", verify, fix)
	}
	// The first step is the one sentence that has to survive: it is what the
	// server should do.
	if !strings.HasPrefix(fix, "Enable hybrid ML-KEM key exchange first") {
		t.Errorf("the Fix lost the step it starts with:\n%s", fix)
	}
}

// undetectedPureMLKEM is what the pure ML-KEM step has to go on to say.
const undetectedPureMLKEM = "but this version cannot detect it and would still report"

// TestQuantumScoreFixSaysPureMLKEMWillNotChangeTheScore covers the step this
// scanner cannot see. The Fix may still name it, since the Verify checks it
// directly, but it has to say the reported score would not move. In each case
// below the posture the step is counted from is hybrid key exchange with a
// classical certificate, so the score still reported is that posture's.
func TestQuantumScoreFixSaysPureMLKEMWillNotChangeTheScore(t *testing.T) {
	stillReported := scanner.QuantumScoreFor(scanner.QuantumHybridKeyExchangeScore,
		scanner.QuantumClassicalCertificateScore)
	for _, c := range []fixCase{
		{keyExchange: hybridKeyExchange, policy: "cnsa-2.0-2030", port: 443, host: "example.com"},
		{keyExchange: hybridKeyExchange, policy: "cnsa-2.0-2035", port: 443, host: "example.com"},
		{keyExchange: classicalKeyExchange, policy: "cnsa-2.0-2035", port: 443, host: "example.com"},
	} {
		fix, fires := fixFor(t, c)
		if !fires {
			t.Fatalf("%s server under %s: the rule does not fire", c.keyExchange.Type, c.policy)
		}
		withPure := scanner.QuantumScoreFor(fullPQCDimensionScore, scanner.QuantumClassicalCertificateScore)
		step := "pure ML-KEM key exchange would reach " + strconv.Itoa(withPure) + ", " + undetectedPureMLKEM
		if !strings.Contains(strings.ToLower(fix), strings.ToLower(step)) {
			t.Errorf("%s server under %s: the Fix does not say %q:\n%s",
				c.keyExchange.Type, c.policy, step, fix)
			continue
		}
		if got := firstNumberAfter(t, fix, undetectedPureMLKEM); got != stillReported {
			t.Errorf("%s server under %s: the score still reported is quoted as %d, want %d:\n%s",
				c.keyExchange.Type, c.policy, got, stillReported, fix)
		}
	}

	// The control: when hybrid key exchange alone meets the minimum, the Fix
	// names no pure ML-KEM step and so has nothing to qualify.
	fix, fires := fixFor(t, fixCase{keyExchange: classicalKeyExchange, policy: "cnsa-2.0-2027",
		port: 443, host: "example.com"})
	if !fires {
		t.Fatal("the rule does not fire for a classical server under cnsa-2.0-2027")
	}
	if strings.Contains(strings.ToLower(fix), "pure ml-kem") {
		t.Errorf("a Fix whose first step meets the minimum names pure ML-KEM:\n%s", fix)
	}
}
