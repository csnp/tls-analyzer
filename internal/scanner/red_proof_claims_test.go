package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTestFileClaimsAnUnrepeatableRedProof stops one specific false claim
// coming back.
//
// Test files in the 0.4.0 release tree asserted, in a comment, that the file
// builds against the sources before the fix and fails there on behaviour. Almost
// all of those claims are false, measured by copying each subject file alone into
// a pristine tree at a869357, the commit before that release; the table is in
// docs/testing/red-proof.md with the command that reproduces it. The cause is
// structural: 0.4.0 landed as a single squashed commit, so the production change,
// the new types, the helpers and the tests all arrived at once, and no test in it
// has an earlier tree to be built against. A proof that needs objects only one
// machine ever had is not a proof anyone can repeat.
//
// Nothing in a code review reliably catches a comment, which is why so many were
// wrong and why the review that looked found three of them. So the phrase is
// banned mechanically. Red proofs name their mutation instead.
//
// It lives in a test package rather than in CI because a check that only runs in
// CI is one a contributor meets after pushing.
func TestNoTestFileClaimsAnUnrepeatableRedProof(t *testing.T) {
	root := repoRoot(t)

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, phrase := range bannedRedProofPhrases() {
			if strings.Contains(string(body), phrase) {
				offenders = append(offenders, rel+": "+phrase)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository failed: %v", err)
	}

	for _, o := range offenders {
		t.Errorf("%s\n\tThere is no earlier tree in this repository for a test of this "+
			"release to be built against: it landed as one squashed commit, so the "+
			"production change, the new types and the helpers all arrived together. Name "+
			"the mutation that kills the test instead, and see docs/testing/red-proof.md.", o)
	}
}

// bannedRedProofPhrases assembles the phrases at runtime so this file does not
// contain them as literals and does not have to exempt itself.
//
// A self-exemption is the wrong shape for a guard: it makes the one file nobody
// checks the one file where the claim can be written. The doc that explains the
// history quotes the phrases freely and is not walked, because the walk only
// visits _test.go files.
//
// This bans an idiom, not an idea. Someone determined to assert an unrepeatable
// red proof can phrase it differently and this will not see it. It is worth
// having anyway: the false claims were copies of one sentence, and the review
// that looked found three of them.
func bannedRedProofPhrases() []string {
	const against = "against the " + "pre-" + "fix"
	return []string{
		"compiles " + against,
		"compile " + against + " sources and fail",
		"compiles against " + "pre-" + "fix",
	}
}

// TestTheClaimGuardActuallyReadsTestFiles proves the walk is not vacuous.
//
// A guard that walks the wrong directory, or matches nothing because the phrase
// list is empty, passes on every input and says nothing. This checks that the
// walk reaches a known file and that the matcher fires on the banned phrase.
func TestTheClaimGuardActuallyReadsTestFiles(t *testing.T) {
	root := repoRoot(t)

	var seen int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(path, "_test.go") {
			seen++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository failed: %v", err)
	}

	// Measured at 68 test files when this was written, against 60 in the previous
	// release. The floor is well under that so ordinary churn does not trip it,
	// and well over zero so a walk that starts in the wrong directory does.
	if seen < 30 {
		t.Errorf("the walk found %d test files, which is too few to be reaching the "+
			"repository; the guard above would pass without reading anything", seen)
	}

	// And the matcher fires on the sentence it exists to ban, assembled the same
	// way so this file still carries no literal copy of it.
	example := "This file names nothing new, so it " + bannedRedProofPhrases()[0] + " sources."
	var matched bool
	for _, phrase := range bannedRedProofPhrases() {
		if strings.Contains(example, phrase) {
			matched = true
		}
	}
	if !matched {
		t.Error("the banned phrases no longer match the sentence they were written for, " +
			"so the guard above would pass over a file that carries it")
	}

	// The other direction: an ordinary red-proof comment must NOT match, or the
	// guard fails every file and says nothing about any of them.
	clean := "Red-proved by setting NotYetValid to false rather than deriving it."
	for _, phrase := range bannedRedProofPhrases() {
		if strings.Contains(clean, phrase) {
			t.Errorf("phrase %q matches an ordinary red-proof comment", phrase)
		}
	}
}

// repoRoot walks up from the test's working directory to the module root, so
// the guard does not depend on which package it is compiled into.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("no go.mod found above the test's working directory, so the guard has no " +
		"repository to walk")
	return ""
}
