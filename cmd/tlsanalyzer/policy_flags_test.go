package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyFlagConflictIsRefused pins that naming two policies is an error.
//
// --policy-file used to win silently, so a run could be evaluated against a
// different policy than the one the command line most visibly asked for, and
// nothing in the report said which had been applied.
func TestPolicyFlagConflictIsRefused(t *testing.T) {
	previousName, previousFile := policyName, policyFile
	defer func() { policyName, policyFile = previousName, previousFile }()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path,
		[]byte("name: mine\nrules:\n  cipher:\n    minKeySize: 256\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		file        string
		wantRefused bool
	}{
		{"neither given", "", "", false},
		{"only --policy", "strict", "", false},
		{"only --policy-file", "", path, false},
		{"both given", "strict", path, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyName, policyFile = tt.policy, tt.file

			// runScan reaches flag validation before any network work, so an
			// empty target list is enough: a refused combination must fail on
			// its own message rather than on "no targets specified".
			err := runScan(rootCmd, nil)
			if err == nil {
				t.Fatal("runScan returned no error at all")
			}
			named := strings.Contains(err.Error(), "both name a policy")

			if tt.wantRefused && !named {
				t.Errorf("--policy %q with --policy-file %q was accepted; got: %v",
					tt.policy, tt.file, err)
			}
			if !tt.wantRefused && named {
				t.Errorf("--policy %q with --policy-file %q was refused as a conflict: %v",
					tt.policy, tt.file, err)
			}
		})
	}
}

// TestPrintPolicyRefusesAnUnknownName keeps the starting-point command from
// being a dead end of its own.
func TestPrintPolicyRefusesAnUnknownName(t *testing.T) {
	err := printPolicyCmd.RunE(printPolicyCmd, []string{"modren"})
	if err == nil {
		t.Fatal("print-policy accepted a policy name that does not exist")
	}
	if !strings.Contains(err.Error(), "Available:") {
		t.Fatalf("error = %q, want it to list the policies that do exist", err.Error())
	}
	if !strings.Contains(err.Error(), "modern") {
		t.Fatalf("error = %q, want the listing to include modern", err.Error())
	}
}
