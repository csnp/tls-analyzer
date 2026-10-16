package scanner

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHowItWorksConfirmsEachUnprobedHybridGroupOnItsOwn keeps the manual check
// for the two P-curve hybrid groups able to answer for both of them.
//
// The scan does not probe SecP256r1MLKEM768 or SecP384r1MLKEM1024, so
// docs/how-it-works.md tells the reader to confirm them with openssl s_client,
// and the README sends readers there for it. The page once gave a single
// command, -groups SecP384r1MLKEM1024, as the check for both. s_client offers
// only the groups named after -groups, so against a server whose only group is
// SecP256r1MLKEM768 that command ends in a handshake failure, which reads as the
// group not being offered. Naming both groups in one command does not fix it
// either: measured with OpenSSL 3.6.3 against a server offering both, the
// combined command negotiates SecP256r1MLKEM768 and says nothing about
// SecP384r1MLKEM1024.
//
// So once the page gives a command for either group, it must give each group a
// command that offers that group alone.
func TestHowItWorksConfirmsEachUnprobedHybridGroupOnItsOwn(t *testing.T) {
	path := filepath.Join(repoRoot(t), "docs", "how-it-works.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	unprobed := []tls.CurveID{groupSecP256r1MLKEM768, groupSecP384r1MLKEM1024}
	names := make(map[string]bool, len(unprobed))
	for _, id := range unprobed {
		names[tlsGroups[id].name] = true
	}

	cmds := sClientCommands(string(body))
	confirmsAny := false
	alone := make(map[string]bool)
	for _, cmd := range cmds {
		offered := offeredGroups(cmd)
		for _, g := range offered {
			if names[g] {
				confirmsAny = true
			}
		}
		if len(offered) == 1 {
			alone[offered[0]] = true
		}
	}
	if !confirmsAny {
		return
	}

	for _, id := range unprobed {
		name := tlsGroups[id].name
		if !alone[name] {
			t.Errorf("docs/how-it-works.md gives no openssl s_client command that offers %s "+
				"on its own. s_client offers only the groups named after -groups, so a "+
				"command naming a different group cannot confirm this one. Add "+
				"'openssl s_client -connect host:443 -groups %s'. Commands found: %q",
				name, name, cmds)
		}
	}
}

// sClientCommands returns each openssl s_client command in a Markdown
// document: whole lines inside fenced code blocks, and inline code spans in the
// prose. An inline span may wrap across lines, so prose lines are joined with a
// space before the spans are split out.
func sClientCommands(doc string) []string {
	var cmds []string
	var prose strings.Builder
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			if strings.Contains(line, "openssl s_client") {
				cmds = append(cmds, line)
			}
			continue
		}
		prose.WriteString(line)
		prose.WriteString(" ")
	}
	spans := strings.Split(prose.String(), "`")
	for i := 1; i < len(spans); i += 2 {
		if strings.Contains(spans[i], "openssl s_client") {
			cmds = append(cmds, spans[i])
		}
	}
	return cmds
}

// offeredGroups returns the colon-separated group list given to -groups (or
// its older spelling -curves), or nil when the command names none.
func offeredGroups(cmd string) []string {
	fields := strings.Fields(cmd)
	for i, f := range fields {
		if (f == "-groups" || f == "-curves") && i+1 < len(fields) {
			return strings.Split(fields[i+1], ":")
		}
	}
	return nil
}

// TestOfferedGroupsReadsTheDocumentedShapes pins the parsing the test above
// relies on, so a parser that stopped finding commands cannot make it pass by
// finding nothing to check.
func TestOfferedGroupsReadsTheDocumentedShapes(t *testing.T) {
	doc := strings.Join([]string{
		"Confirm with",
		"`openssl s_client -connect host:443 -groups SecP384r1MLKEM1024`. Or with",
		"`openssl s_client -connect host:443",
		"-groups SecP256r1MLKEM768:SecP384r1MLKEM1024`.",
		"",
		"```sh",
		"echo | openssl s_client -connect host:443 -groups SecP256r1MLKEM768 | grep 'Negotiated TLS1.3 group'",
		"```",
		"`openssl s_client -connect host:443` alone.",
	}, "\n")

	cmds := sClientCommands(doc)
	got := make([]string, 0, len(cmds))
	for _, c := range cmds {
		got = append(got, strings.Join(offeredGroups(c), ":"))
	}
	want := []string{
		"SecP256r1MLKEM768",
		"SecP384r1MLKEM1024",
		"SecP256r1MLKEM768:SecP384r1MLKEM1024",
		"",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("offered groups per command = %q, want %q (commands %q)", got, want, cmds)
	}
}
