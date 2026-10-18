package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// These tests run the command line through rootCmd.Execute, the call main
// makes, because each defect they cover lives in a step that calling a
// command's Run or RunE directly skips: flag parsing, the argument check and
// the --version handling cobra does before any command runs. Measured with a
// binary built from the tree before these fixes:
//
//	tlsanalyzer --version             Error: unknown flag: --version
//	tlsanalyzer policies | cat        5 policy names, each wrapped in \x1b[1m and \x1b[0m
//	tlsanalyzer policies --no-color   Error: unknown flag: --no-color
//	tlsanalyzer policies extra        printed the listing and exited 0
//	tlsanalyzer version extra         printed the version and exited 0
//	tlsanalyzer --timeout abc         Error: invalid argument "abc" for "-t, --timeout" flag:
//	                                  strconv.ParseInt: parsing "abc": invalid syntax

// cliResult is what one run of the command line printed and returned.
type cliResult struct {
	stdout, stderr string
	err            error
}

// executeCLI runs args through rootCmd.Execute. stdout and stderr are files for
// the length of the run, the way runCLI does it, so text printed with fmt.Print
// and text printed through cobra are both captured.
//
// Execute leaves every flag it parsed set and marked Changed, and runScan reads
// Changed("port"), so each flag is put back afterwards. That includes the help
// and version flags cobra adds during a run, which go back to their defaults.
func executeCLI(t *testing.T, args ...string) cliResult {
	t.Helper()

	type flagState struct {
		value   string
		changed bool
	}
	saved := map[*pflag.Flag]flagState{}
	visitCommandFlags(func(f *pflag.Flag) { saved[f] = flagState{f.Value.String(), f.Changed} })
	defer visitCommandFlags(func(f *pflag.Flag) {
		state, ok := saved[f]
		if !ok {
			state = flagState{f.DefValue, false}
		}
		if err := f.Value.Set(state.value); err != nil {
			t.Errorf("restoring --%s to %q: %v", f.Name, state.value, err)
		}
		f.Changed = state.changed
	})

	dir := t.TempDir()
	stdoutFile, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	stderrFile, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}

	prevStdout, prevStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutFile, stderrFile
	rootCmd.SetArgs(args)
	func() {
		defer func() {
			os.Stdout, os.Stderr = prevStdout, prevStderr
			rootCmd.SetArgs(nil)
		}()
		err = rootCmd.Execute()
	}()
	_ = stdoutFile.Close()
	_ = stderrFile.Close()

	stdout, _ := os.ReadFile(stdoutFile.Name())
	stderr, _ := os.ReadFile(stderrFile.Name())
	return cliResult{stdout: string(stdout), stderr: string(stderr), err: err}
}

// visitCommandFlags calls fn once for each flag of rootCmd and of its commands.
func visitCommandFlags(fn func(*pflag.Flag)) {
	seen := map[*pflag.Flag]bool{}
	for _, cmd := range append([]*cobra.Command{rootCmd}, rootCmd.Commands()...) {
		for _, set := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
			set.VisitAll(func(f *pflag.Flag) {
				if !seen[f] {
					seen[f] = true
					fn(f)
				}
			})
		}
	}
}

// stubTerminal makes stdout look like a terminal, or not, for one test.
// executeCLI points stdout at a file, which is not a terminal, so without the
// stub the colour control below could not be a control.
func stubTerminal(t *testing.T, isTerminal bool) {
	t.Helper()
	prev := stdoutIsTTY
	t.Cleanup(func() { stdoutIsTTY = prev })
	stdoutIsTTY = func() bool { return isTerminal }
}

// TestTheVersionFlagPrintsWhatTheVersionCommandPrints covers `tlsanalyzer
// --version`, which answered "Error: unknown flag: --version".
func TestTheVersionFlagPrintsWhatTheVersionCommandPrints(t *testing.T) {
	command := executeCLI(t, "version")
	if command.err != nil {
		t.Fatalf("the version command failed: %v", command.err)
	}
	if !strings.Contains(command.stdout, version) {
		t.Fatalf("the version command does not print the version %s:\n%s", version, command.stdout)
	}

	for _, flag := range []string{"--version", "-v"} {
		run := executeCLI(t, flag)
		if run.err != nil {
			t.Errorf("%s was refused: %v", flag, run.err)
			continue
		}
		if run.stdout != command.stdout {
			t.Errorf("%s and the version command print different text.\n%s:\n%s\nversion:\n%s",
				flag, flag, run.stdout, command.stdout)
		}
	}
}

// assertListsEveryPolicy keeps the escape checks below from passing on a
// listing that printed nothing.
func assertListsEveryPolicy(t *testing.T, stdout string) {
	t.Helper()
	names := analyzer.NewPolicyEvaluator().ListPolicies()
	if len(names) == 0 {
		t.Fatal("there are no built-in policies to list")
	}
	for _, name := range names {
		if !strings.Contains(stdout, name) {
			t.Errorf("the listing does not name the policy %s:\n%s", name, stdout)
		}
	}
}

// TestThePolicyListingWrittenToAPipeCarriesNoEscapes covers `tlsanalyzer
// policies | cat`, which wrapped each policy name in ANSI bold. The listing
// read --no-color and nothing else, so it coloured a pipe or a file the way the
// scan report, which asks whether stdout is a terminal, does not.
func TestThePolicyListingWrittenToAPipeCarriesNoEscapes(t *testing.T) {
	stubTerminal(t, false)

	run := executeCLI(t, "policies")
	if run.err != nil {
		t.Fatalf("policies failed: %v", run.err)
	}
	assertListsEveryPolicy(t, run.stdout)
	if n := strings.Count(run.stdout, "\x1b"); n > 0 {
		t.Errorf("the listing written to a pipe carries %d escape bytes:\n%q", n, run.stdout)
	}
}

// TestThePolicyListingAcceptsNoColor covers `tlsanalyzer policies --no-color`,
// which answered "Error: unknown flag: --no-color" because the flag was defined
// for a scan only. On a terminal it is the one way to turn the bold off.
func TestThePolicyListingAcceptsNoColor(t *testing.T) {
	stubTerminal(t, true)

	run := executeCLI(t, "policies", "--no-color")
	if run.err != nil {
		t.Fatalf("policies --no-color was refused: %v", run.err)
	}
	assertListsEveryPolicy(t, run.stdout)
	if n := strings.Count(run.stdout, "\x1b"); n > 0 {
		t.Errorf("policies --no-color on a terminal carries %d escape bytes:\n%q", n, run.stdout)
	}
}

// TestThePolicyListingOnATerminalKeepsItsBold is the control for the two tests
// above: with a terminal on stdout and no --no-color the names are still bold,
// so the escapes are gone from a pipe because of where the listing is going,
// not because the bold was removed.
func TestThePolicyListingOnATerminalKeepsItsBold(t *testing.T) {
	stubTerminal(t, true)

	run := executeCLI(t, "policies")
	if run.err != nil {
		t.Fatalf("policies failed: %v", run.err)
	}
	assertListsEveryPolicy(t, run.stdout)
	if !strings.Contains(run.stdout, "\x1b[1m") {
		t.Errorf("the listing on a terminal lost its bold policy names:\n%q", run.stdout)
	}
}

// TestCommandsThatTakeNoArgumentsRefuseOne covers `tlsanalyzer policies extra`,
// which printed the listing and exited 0 while `print-policy strict extra`
// refused its extra argument. `version extra` did the same as `policies extra`.
func TestCommandsThatTakeNoArgumentsRefuseOne(t *testing.T) {
	for _, command := range []string{"policies", "version"} {
		t.Run(command, func(t *testing.T) {
			run := executeCLI(t, command, "extra")
			if run.err == nil {
				t.Fatalf("%s extra was accepted, and printed:\n%s", command, run.stdout)
			}
			if run.stdout != "" {
				t.Errorf("%s extra printed to stdout before it was refused:\n%s", command, run.stdout)
			}
		})
	}
}

// TestARefusedArgumentIsNotRepeated keeps the refusal above off the forgery
// surface. The argument is invocation text, the third source of untrusted text
// in the sanitize package comment, so the refusal counts the arguments and
// does not quote them.
func TestARefusedArgumentIsNotRepeated(t *testing.T) {
	run := executeCLI(t, "policies", forgery)
	if run.err == nil {
		t.Fatalf("policies was given an argument and accepted it, printing:\n%s", run.stdout)
	}
	for site, text := range map[string]string{"the error": run.err.Error(), "stderr": run.stderr} {
		assertNoSteering(t, site, text)
		if strings.Contains(text, "FORGED") {
			t.Errorf("%s repeats the refused argument: %q", site, text)
		}
	}
}

// TestAFlagValueThatIsNotANumberIsAnsweredLikeOneOutOfRange covers `--timeout
// abc`, whose error quoted the Go function that failed: "strconv.ParseInt:
// parsing \"abc\": invalid syntax". `--timeout 0` is answered
// "--timeout: invalid value 0: must be at least 1 second", and the two now
// open the same way.
func TestAFlagValueThatIsNotANumberIsAnsweredLikeOneOutOfRange(t *testing.T) {
	zero := executeCLI(t, "--timeout", "0")
	if zero.err == nil || !strings.HasPrefix(zero.err.Error(), "--timeout: invalid value 0: ") {
		t.Fatalf("--timeout 0 is no longer answered the way this test mirrors: %v", zero.err)
	}

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--timeout", "abc"}, `--timeout: invalid value "abc": must be a whole number of seconds`},
		{[]string{"-t", "30s"}, `--timeout: invalid value "30s": must be a whole number of seconds`},
		{[]string{"--timeout=1.5"}, `--timeout: invalid value "1.5": must be a whole number of seconds`},
		{[]string{"--timeout", "99999999999999999999"}, `--timeout: invalid value "99999999999999999999": out of range`},
		{[]string{"--port", "https"}, `--port: invalid value "https": must be a whole number`},
		{[]string{"-c", "many"}, `--concurrency: invalid value "many": must be a whole number`},
		{[]string{"--no-color=maybe"}, `--no-color: invalid value "maybe": must be true or false`},
		{[]string{"--compact=yes"}, `--compact: invalid value "yes": must be true or false`},
	}
	for _, c := range cases {
		run := executeCLI(t, c.args...)
		if run.err == nil {
			t.Errorf("%s was accepted", strings.Join(c.args, " "))
			continue
		}
		if got := run.err.Error(); got != c.want {
			t.Errorf("%s\n\tgot:  %q\n\twant: %q", strings.Join(c.args, " "), got, c.want)
		}
		if strings.Contains(run.stderr, "strconv") {
			t.Errorf("%s names a Go function on stderr: %q", strings.Join(c.args, " "), run.stderr)
		}
	}
}

// TestARefusedFlagValueCannotSteerTheTerminal keeps the rewritten message above
// off the forgery surface: the value is invocation text, and it is repeated, so
// it is quoted with its control characters escaped.
func TestARefusedFlagValueCannotSteerTheTerminal(t *testing.T) {
	run := executeCLI(t, "--timeout", forgery)
	if run.err == nil {
		t.Fatal("a --timeout value that is not a number was accepted")
	}
	assertNoSteering(t, "the error", run.err.Error())
	assertNoSteering(t, "stderr", run.stderr)
	if !strings.HasPrefix(run.err.Error(), "--timeout: invalid value ") {
		t.Errorf("the value was refused some other way: %q", run.err.Error())
	}
}
