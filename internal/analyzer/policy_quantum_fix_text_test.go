package analyzer

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The quantum.minQuantumScore Fix used to be one fixed sentence, "Enable PQC
// key exchange to improve quantum readiness", whatever the score was made of.
// cnsa-2.0-2030 asks for 70 and hybrid ML-KEM key exchange with a classical
// certificate scores 64, so a server that had already taken that step was told
// to take it again and was never told that the two steps left are pure ML-KEM
// key exchange and a post-quantum certificate.
//
// The expected numbers here come from scanner.QuantumScoreFor and the weights
// and dimension scores quantum.go exports, not from the evaluator, so the test
// does not recompute the expression the Fix is built from.

// fullPQCDimensionScore is what the grader gives a pure post-quantum key
// exchange, or an ML-DSA or SLH-DSA certificate, on its own dimension.
// quantum.go exports no name for it, so it is stated here.
const fullPQCDimensionScore = 100

var (
	hybridKeyExchange = types.KeyExchange{
		Name: "X25519MLKEM768", Type: "hybrid", HybridClassical: "X25519", PQCAlgorithm: "ML-KEM-768",
	}
	classicalKeyExchange = types.KeyExchange{Name: "X25519", Type: "classical"}
)

// quantumPostureScan is a scan with the given key exchanges and certificate
// algorithm, whose quantum assessment comes from the grader itself.
func quantumPostureScan(keyExchanges []types.KeyExchange, certificateAlgorithm string) *types.ScanResult {
	scan := scanForRuleValues()
	scan.KeyExchanges = keyExchanges
	scan.Certificate.PublicKeyAlgorithm = certificateAlgorithm
	scan.QuantumRisk = scanner.AssessQuantumRisk(scan)
	return scan
}

func minQuantumScoreFix(t *testing.T, e *PolicyEvaluator, scan *types.ScanResult, policyName string) string {
	t.Helper()
	policy, ok := e.GetPolicy(policyName)
	if !ok {
		t.Fatalf("built-in policy %s not found", policyName)
	}
	if scan.QuantumRisk.Score >= policy.Rules.Quantum.MinQuantumScore {
		t.Fatalf("the posture scores %d and %s asks for %d, so the rule does not fire and "+
			"this test would check nothing", scan.QuantumRisk.Score, policyName,
			policy.Rules.Quantum.MinQuantumScore)
	}
	pr := e.Evaluate(scan, policy)
	var fixes []string
	for _, v := range pr.Violations {
		if v.Rule == "quantum.minQuantumScore" {
			fixes = append(fixes, v.Remediation)
		}
	}
	if len(fixes) != 1 {
		t.Fatalf("want exactly one quantum.minQuantumScore violation, got %d: %+v", len(fixes), pr.Violations)
	}
	return fixes[0]
}

var numberPattern = regexp.MustCompile(`\d+`)

// firstNumberAfter returns the first whole number in s after the first
// occurrence of phrase, compared without regard to case, so each score is tied
// to the step it belongs to rather than merely appearing somewhere.
func firstNumberAfter(t *testing.T, s, phrase string) int {
	t.Helper()
	i := strings.Index(strings.ToLower(s), strings.ToLower(phrase))
	if i < 0 {
		t.Fatalf("Fix does not mention %q:\n%s", phrase, s)
	}
	m := numberPattern.FindString(s[i+len(phrase):])
	if m == "" {
		t.Fatalf("no number follows %q in the Fix:\n%s", phrase, s)
	}
	n, _ := strconv.Atoi(m)
	return n
}

func TestQuantumScoreFixForAHybridServerNamesTheStepsLeft(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{hybridKeyExchange}, "ECDSA")

	current := scanner.QuantumScoreFor(scanner.QuantumHybridKeyExchangeScore, scanner.QuantumClassicalCertificateScore)
	withPureKeyExchange := scanner.QuantumScoreFor(fullPQCDimensionScore, scanner.QuantumClassicalCertificateScore)
	withPQCertificate := scanner.QuantumScoreFor(scanner.QuantumHybridKeyExchangeScore, fullPQCDimensionScore)
	if scan.QuantumRisk.Score != current {
		t.Fatalf("the grader scores hybrid with ECDSA at %d, QuantumScoreFor says %d", scan.QuantumRisk.Score, current)
	}

	fix := minQuantumScoreFix(t, NewPolicyEvaluator(), scan, "cnsa-2.0-2030")

	if strings.Contains(fix, "Enable PQC key exchange") {
		t.Errorf("Fix tells a server that already negotiates hybrid ML-KEM to enable PQC key exchange:\n%s", fix)
	}
	if got := firstNumberAfter(t, fix, "already in place"); got != current {
		t.Errorf("score quoted for the hybrid key exchange already in place = %d, want %d:\n%s", got, current, fix)
	}
	if got := firstNumberAfter(t, fix, "pure ML-KEM key exchange"); got != withPureKeyExchange {
		t.Errorf("score quoted for pure ML-KEM key exchange = %d, want %d:\n%s", got, withPureKeyExchange, fix)
	}
	if got := firstNumberAfter(t, fix, "post-quantum certificate"); got != withPQCertificate {
		t.Errorf("score quoted for a post-quantum certificate = %d, want %d:\n%s", got, withPQCertificate, fix)
	}
	// The certificate step cannot be bought yet. The assessment already says
	// so; the Fix repeats its words rather than making a second claim.
	if !strings.Contains(scan.QuantumRisk.TimeToAction, scanner.QuantumCertificateAvailability) {
		t.Fatalf("the assessment's recommended action %q no longer carries the certificate wording "+
			"the Fix quotes", scan.QuantumRisk.TimeToAction)
	}
	if !strings.Contains(strings.ToLower(fix), strings.ToLower(scanner.QuantumCertificateAvailability)) {
		t.Errorf("Fix does not carry the assessment's own words on certificates %q:\n%s",
			scanner.QuantumCertificateAvailability, fix)
	}
	const verify = "openssl s_client -connect example.com:443 -servername example.com -groups MLKEM1024 </dev/null"
	if !strings.Contains(fix, "Verify") || !strings.HasSuffix(fix, verify) {
		t.Errorf("Fix does not end with the runnable Verify %q:\n%s", verify, fix)
	}
}

func TestQuantumScoreFixForAClassicalServerStartsWithHybridKeyExchange(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{classicalKeyExchange}, "ECDSA")
	withHybrid := scanner.QuantumScoreFor(scanner.QuantumHybridKeyExchangeScore, scanner.QuantumClassicalCertificateScore)

	fix := minQuantumScoreFix(t, NewPolicyEvaluator(), scan, "cnsa-2.0-2030")

	if !strings.HasPrefix(fix, "Enable hybrid ML-KEM key exchange") {
		t.Errorf("Fix for a classical-only server does not start with hybrid ML-KEM key exchange:\n%s", fix)
	}
	if strings.Contains(fix, "already in place") {
		t.Errorf("Fix claims something is already in place on a classical-only server:\n%s", fix)
	}
	// The sentence naming the hybrid step carries the score it reaches.
	firstSentence, _, _ := strings.Cut(fix, ". ")
	if !regexp.MustCompile(`\b` + strconv.Itoa(withHybrid) + `\b`).MatchString(firstSentence) {
		t.Errorf("the hybrid step does not quote the %d it reaches:\n%s", withHybrid, fix)
	}
	const verify = "openssl s_client -connect example.com:443 -servername example.com -groups X25519MLKEM768 </dev/null"
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("Fix does not end with the runnable Verify %q:\n%s", verify, fix)
	}
}

// TestQuantumScoreFixQuotesTheConnectAddressForTheShell covers an IPv6 target.
// Unquoted, zsh reads [::1]:443 as a glob and refuses the command before
// openssl runs, so the printed Verify would not run. The scanner sends no SNI
// for an IP address, so neither does the Verify.
func TestQuantumScoreFixQuotesTheConnectAddressForTheShell(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{hybridKeyExchange}, "ECDSA")
	scan.Host, scan.Port = "::1", 8443

	fix := minQuantumScoreFix(t, NewPolicyEvaluator(), scan, "cnsa-2.0-2030")

	const verify = "openssl s_client -connect '[::1]:8443' -groups MLKEM1024 </dev/null"
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("Fix does not end with the runnable Verify %q:\n%s", verify, fix)
	}
}

// TestQuantumScoreFixAsksForTheNameTheScanDid is the reported reproduction: a
// scan of 127.0.0.1 with --sni localhost has to be verified with the same name.
func TestQuantumScoreFixAsksForTheNameTheScanDid(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{hybridKeyExchange}, "ECDSA")
	scan.Host, scan.Port = "127.0.0.1", 19445
	e := NewPolicyEvaluator()
	e.ServerName = "localhost"

	fix := minQuantumScoreFix(t, e, scan, "cnsa-2.0-2030")

	const verify = "openssl s_client -connect 127.0.0.1:19445 -servername localhost -groups MLKEM1024 </dev/null"
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("Fix does not end with the runnable Verify %q:\n%s", verify, fix)
	}
}

// TestQuantumScoreFixQuotesAHostileServerName: --sni is typed at the command
// line and the report offers this command to be pasted, so a value carrying a
// command separator or an escape sequence must reach the shell as one inert
// word.
func TestQuantumScoreFixQuotesAHostileServerName(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{hybridKeyExchange}, "ECDSA")
	e := NewPolicyEvaluator()
	e.ServerName = "a.example;touch /tmp/x\x1b[2J'"

	fix := minQuantumScoreFix(t, e, scan, "cnsa-2.0-2030")

	const verify = `-servername 'a.example;touch /tmp/x [2J'\''' -groups MLKEM1024 </dev/null`
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("Fix does not end with the quoted Verify %q:\n%s", verify, fix)
	}
}

// TestQuantumScoreFixKeepsTheVerifyWithinTheReportCap: the report caps a Fix
// at sanitize.MaxReportDetail bytes by cutting the end, which is where the
// Verify is, so a long host name must cost the optional note and not the
// command.
func TestQuantumScoreFixKeepsTheVerifyWithinTheReportCap(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{hybridKeyExchange}, "ECDSA")
	host := strings.Repeat("a", 63) + ".example.com"
	scan.Host = host

	fix := minQuantumScoreFix(t, NewPolicyEvaluator(), scan, "cnsa-2.0-2030")

	verify := "openssl s_client -connect " + host + ":443 -servername " + host + " -groups MLKEM1024 </dev/null"
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("Fix does not end with the whole Verify %q:\n%s", verify, fix)
	}
	if len(fix) > sanitize.MaxReportDetail {
		t.Errorf("Fix is %d bytes, over the %d-byte report cap", len(fix), sanitize.MaxReportDetail)
	}
}

// TestQuantumScoreFixWhenNoSingleStepIsEnough uses cnsa-2.0-2035, whose
// minimum neither the pure key exchange step nor the certificate step reaches
// alone from a hybrid server.
func TestQuantumScoreFixWhenNoSingleStepIsEnough(t *testing.T) {
	scan := quantumPostureScan([]types.KeyExchange{hybridKeyExchange}, "ECDSA")
	e := NewPolicyEvaluator()
	policy, _ := e.GetPolicy("cnsa-2.0-2035")
	minimum := policy.Rules.Quantum.MinQuantumScore
	withPureKeyExchange := scanner.QuantumScoreFor(fullPQCDimensionScore, scanner.QuantumClassicalCertificateScore)
	withPQCertificate := scanner.QuantumScoreFor(scanner.QuantumHybridKeyExchangeScore, fullPQCDimensionScore)
	if withPureKeyExchange >= minimum || withPQCertificate >= minimum {
		t.Skipf("cnsa-2.0-2035 asks for %d, which one step reaches, so this case does not arise", minimum)
	}

	fix := minQuantumScoreFix(t, e, scan, "cnsa-2.0-2035")

	both := scanner.QuantumScoreFor(fullPQCDimensionScore, fullPQCDimensionScore)
	if got := firstNumberAfter(t, fix, "reaching"); got != both {
		t.Errorf("score quoted for both steps = %d, want %d:\n%s", got, both, fix)
	}
}
