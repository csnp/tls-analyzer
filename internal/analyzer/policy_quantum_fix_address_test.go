package analyzer

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
)

// The quantum.minQuantumScore Verify names the host twice, in -connect and in
// -servername, so with no --sni name and a host name of about 200 characters
// the Verify alone was longer than the report cap and its end was still cut.
// Through Evaluate on port 443 the first host name length cut was 197 for a
// classical server and 201 for a hybrid one. Scanned end to end as a
// 213-character name resolving to ::1, a classical server's Fix was 500 bytes
// ending "aaaa.local...". Such a Verify now connects to the address the scan
// resolved the host to and names the host once, as the -servername.

// longestIPv6Text is the longest text an IPv6 address prints as. In -connect it
// also takes brackets and, for the brackets, quotes.
const longestIPv6Text = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

// expectedVerifyAt is expectedVerify connecting to ip instead of the host.
func expectedVerifyAt(c fixCase, ip string) string {
	label, group := "Verify pure ML-KEM support: ", "MLKEM1024"
	if c.keyExchange.Type == "classical" {
		label, group = "Verify hybrid ML-KEM support: ", "X25519MLKEM768"
	}
	name := c.serverName
	if name == "" {
		name = c.host
	}
	connect := net.JoinHostPort(ip, strconv.Itoa(c.port))
	if strings.Contains(connect, "[") {
		connect = "'" + connect + "'"
	}
	cmd := "openssl s_client -connect " + connect
	if net.ParseIP(name) == nil {
		cmd += " -servername " + name
	}
	return label + cmd + " -groups " + group + " </dev/null"
}

// TestQuantumScoreFixConnectsToTheScannedAddressWhenTheVerifyIsTooLong covers
// classical and hybrid servers under each policy whose minimum they miss, at
// port 443 and port 65535, resolved to an IPv4 address and to the longest IPv6
// address text, for every host name length from 1 to 254 bytes (254 with a
// trailing dot), with no --sni name and with a different 253-byte one. The Fix
// keeps the Verify that connects to the host whenever that Verify fits the cap
// on its own, and otherwise ends with the whole Verify that connects to the
// address.
func TestQuantumScoreFixConnectsToTheScannedAddressWhenTheVerifyIsTooLong(t *testing.T) {
	var hosts []string
	for n := 1; n <= 253; n++ {
		hosts = append(hosts, hostOfLength(n))
	}
	hosts = append(hosts, hostOfLength(253)+".")
	otherName := strings.ReplaceAll(hostOfLength(253), "a", "b")

	checked, atAddress := map[string]int{}, map[string]int{}
	for _, ke := range []types.KeyExchange{classicalKeyExchange, hybridKeyExchange} {
		for _, policy := range []string{"cnsa-2.0-2027", "cnsa-2.0-2030", "cnsa-2.0-2035"} {
			for _, port := range []int{443, 65535} {
				for _, ip := range []string{"203.0.113.10", longestIPv6Text} {
					for _, host := range hosts {
						for _, serverName := range []string{"", otherName} {
							c := fixCase{keyExchange: ke, policy: policy, port: port, host: host,
								serverName: serverName, ip: ip}
							fix, fires := fixFor(t, c)
							if !fires {
								continue
							}
							checked[ke.Type+" "+policy]++
							verify := expectedVerify(c)
							if len(verify) > sanitize.MaxReportDetail {
								verify = expectedVerifyAt(c, ip)
								atAddress[ke.Type+" "+policy]++
							}
							if !strings.HasSuffix(fix, verify) {
								t.Errorf("%s server, %s, host %d bytes, --sni %d bytes, port %d, address %s: "+
									"the Fix does not end with the whole Verify %q:\n%s", ke.Type, policy,
									len(host), len(serverName), port, ip, verify, fix)
								continue
							}
							if len(fix) > sanitize.MaxReportDetail {
								t.Errorf("%s server, %s, host %d bytes, --sni %d bytes: the Fix is %d bytes, "+
									"over the %d-byte cap", ke.Type, policy, len(host), len(serverName),
									len(fix), sanitize.MaxReportDetail)
							}
							opening := "Hybrid ML-KEM key exchange is already in place"
							if ke.Type == "classical" {
								opening = "Enable hybrid ML-KEM key exchange"
							}
							if len(opening)+2+len(verify) <= sanitize.MaxReportDetail &&
								!strings.HasPrefix(fix, opening) {
								t.Errorf("%s server, %s, host %d bytes, --sni %d bytes: the Fix does not "+
									"open with %q although it fits:\n%s", ke.Type, policy, len(host),
									len(serverName), opening, fix)
							}
						}
					}
				}
			}
		}
	}

	for _, want := range []string{"classical cnsa-2.0-2027", "classical cnsa-2.0-2030",
		"classical cnsa-2.0-2035", "hybrid cnsa-2.0-2030", "hybrid cnsa-2.0-2035"} {
		if checked[want] == 0 || atAddress[want] == 0 {
			t.Errorf("%s: %d cases fired the rule and %d needed the address form, so that case "+
				"was not checked", want, checked[want], atAddress[want])
		}
	}
}

// TestQuantumScoreFixKeepsTheVerifyForTheReportedLongHost is the end-to-end
// reproduction: a classical server scanned as a 213-character host name that
// resolved to ::1, at port 19641 under cnsa-2.0-2030.
func TestQuantumScoreFixKeepsTheVerifyForTheReportedLongHost(t *testing.T) {
	host := strings.Repeat(strings.Repeat("a", 50)+".", 4) + "localhost"
	c := fixCase{keyExchange: classicalKeyExchange, policy: "cnsa-2.0-2030", port: 19641,
		host: host, ip: "::1"}
	fix, fires := fixFor(t, c)
	if !fires {
		t.Fatal("the rule does not fire for a classical server under cnsa-2.0-2030")
	}
	verify := "Verify hybrid ML-KEM support: openssl s_client -connect '[::1]:19641' -servername " +
		host + " -groups X25519MLKEM768 </dev/null"
	if !strings.HasSuffix(fix, verify) {
		t.Errorf("the Fix does not end with the whole Verify %q:\n%s", verify, fix)
	}
	if !strings.HasPrefix(fix, "Enable hybrid ML-KEM key exchange first") {
		t.Errorf("the Fix lost the step it starts with:\n%s", fix)
	}
	if len(fix) > sanitize.MaxReportDetail {
		t.Errorf("the Fix is %d bytes, over the %d-byte cap", len(fix), sanitize.MaxReportDetail)
	}
}

// TestQuantumScoreFixConnectsOnlyToARecordedAddress: the address form is built
// from the scan's IP field only when that field holds an IP address, so text
// that is not one never reaches the command.
func TestQuantumScoreFixConnectsOnlyToARecordedAddress(t *testing.T) {
	notAnAddress := "example.org;true"
	c := fixCase{keyExchange: classicalKeyExchange, policy: "cnsa-2.0-2030", port: 443,
		host: hostOfLength(230), ip: notAnAddress}
	fix, fires := fixFor(t, c)
	if !fires {
		t.Fatal("the rule does not fire for a classical server under cnsa-2.0-2030")
	}
	if strings.Contains(fix, notAnAddress) {
		t.Errorf("the Fix connects to an IP field that holds no address:\n%s", fix)
	}
}
