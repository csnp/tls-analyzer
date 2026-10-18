package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheCommandsDocShowsTheHelpThisBuildPrints holds the CLI Reference in
// docs/commands.md to the text --help prints. That block was written by hand
// and drifted from it: it described --port as "Target port, 1-65535, overrides
// a port in the target" where --help said "Target port (overrides port in
// target)", gave -h as "Help for tlsanalyzer" where --help prints "help for
// tlsanalyzer", and left out the completion and help commands.
func TestTheCommandsDocShowsTheHelpThisBuildPrints(t *testing.T) {
	help := executeCLI(t, "--help")
	if help.err != nil {
		t.Fatalf("--help failed: %v", help.err)
	}

	var usage string
	for i, block := range cliReferenceBlocks(t) {
		if !strings.Contains(help.stdout, block) {
			t.Errorf("block %d of the CLI Reference in docs/commands.md is not text --help prints:\n%s",
				i+1, block)
		}
		if strings.HasPrefix(block, "Usage:") {
			usage = block
		}
	}
	if usage == "" {
		t.Fatal("the CLI Reference in docs/commands.md has no block that starts at Usage:")
	}
	// From Usage: to the last line of --help is every command and every flag.
	if !strings.HasSuffix(strings.TrimRight(help.stdout, "\n"), usage) {
		t.Errorf("the Usage: block in docs/commands.md stops before the end of --help, "+
			"so it leaves out a command or a flag:\n%s", usage)
	}
}

// cliReferenceBlocks returns the fenced blocks of the "## CLI Reference"
// section of docs/commands.md, without their fences.
func cliReferenceBlocks(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "commands.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var blocks, block []string
	inSection, inFence := false, false
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case !inFence && strings.HasPrefix(line, "## "):
			inSection = line == "## CLI Reference"
		case inSection && strings.HasPrefix(line, "```"):
			if inFence {
				blocks = append(blocks, strings.Join(block, "\n"))
				block = nil
			}
			inFence = !inFence
		case inSection && inFence:
			block = append(block, line)
		}
	}
	if len(blocks) == 0 {
		t.Fatalf("%s has no fenced block under ## CLI Reference", path)
	}
	return blocks
}
