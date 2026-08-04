// Package main provides the CLI entry point for qramm-tls-analyzer.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
	"github.com/csnp/qramm-tls-analyzer/internal/reporter"
	"github.com/csnp/qramm-tls-analyzer/internal/sanitize"
	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	version = "0.4.0"
	commit  = "dev"
	date    = "unknown"
)

// CLI flags
var (
	outputFormat string
	outputFile   string
	timeout      int
	noColor      bool
	jsonCompact  bool
	port         int
	sni          string
	skipVulns    bool
	skipQuantum  bool
	skipCNSA2    bool
	policyName   string
	policyFile   string
	targetsFile  string
	concurrency  int
)

// Exit codes. A compliance check that cannot fail a build is not a gate, and
// policy non-compliance exited 0, so --policy could report 35 HIGH violations
// and still let a pipeline through. The codes are separate so a job can tell a
// failed policy from a scan that could not run at all, and they are documented
// in --help and the README rather than only here.
const (
	exitScanFailed   = 1
	exitPolicyFailed = 2
)

// policyGateError reports that a policy was applied and the target either did
// not satisfy it or could not be fully evaluated against it. Both are failures
// of the gate: a verdict that skipped rules has not established compliance, and
// the policy score only rises when a rule is not evaluated.
type policyGateError struct{ message string }

func (e *policyGateError) Error() string { return e.message }

func main() {
	if err := rootCmd.Execute(); err != nil {
		var gate *policyGateError
		if errors.As(err, &gate) {
			os.Exit(exitPolicyFailed)
		}
		os.Exit(exitScanFailed)
	}
}

// policyOutcome turns policy results into the process outcome.
//
// Scan failures are the caller's to report first: a target that was never
// reached has no policy verdict, and reporting it as non-compliant would be a
// verdict about nothing.
func policyOutcome(results []*types.ScanResult) error {
	var failed, incomplete []string

	for _, result := range results {
		if result == nil || result.PolicyResult == nil {
			continue
		}
		if !result.PolicyResult.Compliant {
			failed = append(failed, result.Target)
		} else if !result.PolicyResult.Complete {
			// A compliant verdict that skipped rules has not established
			// compliance with the policy, only with the part of it that ran.
			incomplete = append(incomplete, result.Target)
		}
	}

	switch {
	case len(failed) > 0 && len(incomplete) > 0:
		return &policyGateError{fmt.Sprintf(
			"policy not satisfied by %s; and not fully evaluated against %s",
			strings.Join(failed, ", "), strings.Join(incomplete, ", "))}
	case len(failed) > 0:
		return &policyGateError{fmt.Sprintf(
			"policy not satisfied by %s", strings.Join(failed, ", "))}
	case len(incomplete) > 0:
		return &policyGateError{fmt.Sprintf(
			"policy could not be fully evaluated against %s, so compliance is not "+
				"established. See the rules listed as not evaluated",
			strings.Join(incomplete, ", "))}
	}

	return nil
}

var rootCmd = &cobra.Command{
	Use:   "tlsanalyzer [target]",
	Short: "QRAMM TLS Analyzer - Quantum-ready TLS security assessment",
	Long: `QRAMM TLS Analyzer performs comprehensive TLS security analysis
with a focus on post-quantum cryptography readiness.

It analyzes:
  • TLS protocol versions supported
  • Cipher suites and key exchanges
  • Certificate validity and strength
  • Quantum vulnerability assessment
  • CNSA 2.0 compliance timeline
  • Security vulnerabilities and misconfigurations

Quantum Ready grades, from the quantum readiness score:
  Q+ 80-100   Q 50-79   Q- 20-49   QV below 20

  The score weights the key exchange at 80 and the certificate at 20, so a
  server offering hybrid key exchange with a classical certificate scores 64
  and grades Q, not Q+. Q+ needs either a full post-quantum key exchange, which
  is yours to deploy, or hybrid key exchange plus a post-quantum certificate,
  which is not: no publicly trusted CA issues one yet. So a host running hybrid
  key exchange is at the best posture most operators can reach today. The
  QUANTUM RISK ASSESSMENT section of the report says that in full, and the
  recommendations say to track CA readiness rather than asking for work that
  cannot be done.

TLS Security grades:
  A+ 95-100   A 85-94   B 75-84   C 60-74   D 40-59   F below 40

Exit codes:
  0  scanned, and any policy applied was fully evaluated and satisfied
  1  the scan could not be completed
  2  a policy was applied and the target did not satisfy it, or the policy
     could not be fully evaluated, which does not establish compliance

Examples:
  tlsanalyzer example.com
  tlsanalyzer example.com:8443
  tlsanalyzer example.com --format json
  tlsanalyzer example.com --format html -o report.html
  tlsanalyzer example.com --format cbom -o inventory.json
  tlsanalyzer example.com --policy cnsa-2.0-2027
  tlsanalyzer --targets hosts.txt --format json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,

	// A runtime failure is not a usage mistake. Every error, including an
	// unreachable host, printed the error and then the whole ~30 line usage
	// block after it, which buried the one line that mattered. Cobra still
	// prints "Error: ..." itself; --help remains the way to see usage.
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("qramm-tls-analyzer %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		fmt.Println()
		fmt.Println("Part of the QRAMM Toolkit by CSNP (https://csnp.org)")
	},
}

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "List available security policies",
	Run: func(cmd *cobra.Command, args []string) {
		evaluator := analyzer.NewPolicyEvaluator()
		policies := evaluator.ListPolicies()

		fmt.Println("\nAvailable Security Policies:")
		fmt.Println("─────────────────────────────────────────────────────────")
		for _, name := range policies {
			policy, _ := evaluator.GetPolicy(name)
			fmt.Printf("\n  %s\n", colorBold(name))
			fmt.Printf("    %s\n", policy.Description)
			if policy.Rules.Quantum.CNSA2TargetYear > 0 {
				fmt.Printf("    CNSA 2.0 Target: %d\n", policy.Rules.Quantum.CNSA2TargetYear)
			}
		}
		fmt.Println()
	},
}

// printPolicyCmd emits a built-in policy in the exact shape --policy-file
// accepts.
//
// The policy schema was documented nowhere, and unknown keys were silently
// ignored, so a hand-written policy could be accepted, applied to nothing and
// reported as compliant. Unknown keys are refused now, which makes having a
// correct starting point part of the fix rather than a convenience.
var printPolicyCmd = &cobra.Command{
	Use:   "print-policy [name]",
	Short: "Print a built-in policy as YAML, to copy as a starting point",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		evaluator := analyzer.NewPolicyEvaluator()
		policy, ok := evaluator.GetPolicy(args[0])
		if !ok {
			names := evaluator.ListPolicies()
			sort.Strings(names)
			return fmt.Errorf("unknown policy: %s. Available: %s",
				sanitize.ForReport(args[0], sanitize.MaxReportDetail), strings.Join(names, ", "))
		}

		out, err := yaml.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to render policy as YAML: %w", err)
		}

		fmt.Printf("# Built-in policy %q, in the shape --policy-file accepts.\n", policy.Name)
		fmt.Print(printPolicyHeader())
		fmt.Print(string(out))
		return nil
	},
}

// printPolicyHeader describes the schema shown by print-policy.
//
// It is a function so a test can hold it to what the loader actually accepts.
// It read "Every key below is part of the schema. Any other key is refused.",
// which was false: `extends` is accepted and is not printed here, because a
// built-in policy inherits from nothing. This is the only surface that shows a
// user the schema, so the header left `extends` undiscoverable while the
// policy-refusal messages tell the reader to reach for it.
func printPolicyHeader() string {
	return "# Every key below is part of the schema. The one key not shown here is\n" +
		"# 'extends: <built-in policy name>', which inherits that policy's rules and\n" +
		"# lets this file override individual ones. Any other key is refused.\n"
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(policiesCmd)
	rootCmd.AddCommand(printPolicyCmd)

	// Suppressing the usage block leaves a flag mistake with no next step, so
	// point at --help explicitly rather than printing every flag.
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return fmt.Errorf("%w\nRun 'tlsanalyzer --help' to see the available flags", err)
	})

	// Output options
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "text",
		"Output format: text, json, sarif, cbom, html")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "",
		"Output file (default: stdout)")
	rootCmd.Flags().BoolVar(&noColor, "no-color", false,
		"Disable colored output")
	rootCmd.Flags().BoolVar(&jsonCompact, "compact", false,
		"Compact JSON output (no indentation)")

	// Connection options
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 30,
		"Connection timeout in seconds")
	rootCmd.Flags().IntVarP(&port, "port", "p", 443,
		"Target port (overrides port in target)")
	rootCmd.Flags().StringVar(&sni, "sni", "",
		"Server Name Indication (SNI) to use")

	// Scan options
	rootCmd.Flags().BoolVar(&skipVulns, "skip-vulns", false,
		"Skip vulnerability checks")
	rootCmd.Flags().BoolVar(&skipQuantum, "skip-quantum", false,
		"Skip quantum risk assessment")
	rootCmd.Flags().BoolVar(&skipCNSA2, "skip-cnsa2", false,
		"Skip CNSA 2.0 compliance analysis")

	// Policy options
	rootCmd.Flags().StringVar(&policyName, "policy", "",
		"Apply a security policy (use 'policies' command to list)")
	rootCmd.Flags().StringVar(&policyFile, "policy-file", "",
		"Path to custom policy YAML file")

	// Batch scanning options
	rootCmd.Flags().StringVar(&targetsFile, "targets", "",
		"File containing list of targets (one per line)")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10,
		"Number of concurrent scans for batch mode")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Collect targets
	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	// Validate the flag values before anything else, so that an unusable value is
	// reported as such whether or not a target was supplied. Checking targets
	// first meant "tlsanalyzer --concurrency 0" answered "no targets specified"
	// and said nothing about the concurrency.
	if err := validateFlags(cmd); err != nil {
		return err
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets specified. Use 'tlsanalyzer example.com' or '--targets file.txt'")
	}

	// Apply --port only when the user actually passed it, so that targets
	// written as host:port keep working and the default never silently
	// rewrites them. A port written into the target itself is checked by the
	// scanner when it parses the target, which is the one place both routes meet.
	if cmd.Flags().Changed("port") {
		for i, target := range targets {
			targets[i] = applyPortOverride(target, port)
		}
	}

	// Handle signals for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nInterrupted, shutting down...")
		cancel()
	}()

	// Configure scanner
	cfg := scanner.DefaultConfig()
	cfg.Timeout = time.Duration(timeout) * time.Second
	cfg.ConnectTimeout = time.Duration(timeout/2) * time.Second
	cfg.SNI = sni
	cfg.CheckVulns = !skipVulns
	cfg.CheckQuantum = !skipQuantum
	cfg.Concurrency = concurrency

	// Setup output
	output := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	// Load policy if specified
	var policy *types.Policy
	if policyName != "" || policyFile != "" {
		evaluator := analyzer.NewPolicyEvaluator()
		if policyFile != "" {
			policy, err = evaluator.LoadPolicy(policyFile)
			if err != nil {
				return fmt.Errorf("failed to load policy: %w", err)
			}
		} else {
			var ok bool
			policy, ok = evaluator.GetPolicy(policyName)
			if !ok {
				return fmt.Errorf("unknown policy: %s (use 'policies' command to list available policies)",
					sanitize.ForReport(policyName, sanitize.MaxReportDetail))
			}
		}
	}

	// Create scanner and analyzers
	s := scanner.New(cfg)
	cnsa2Analyzer := analyzer.NewCNSA2Analyzer()
	policyEvaluator := analyzer.NewPolicyEvaluator()

	// Determine if batch mode
	if len(targets) == 1 {
		// Single target mode
		return scanSingleTarget(ctx, s.Scan, cnsa2Analyzer, policyEvaluator, targets[0], policy, output)
	}

	// Batch mode
	return scanBatchTargets(ctx, s.Scan, cnsa2Analyzer, policyEvaluator, targets, policy, output)
}

// scanFunc performs one scan.
//
// The batch and single paths take the scan as a function rather than a
// *scanner.Scanner so that output ordering can be tested against a completion
// order that is deliberately the reverse of the input order. Nothing else can
// prove the ordering fix, because a real scan finishes in whatever order the
// network allows.
type scanFunc func(ctx context.Context, target string) (*types.ScanResult, error)

// scrubbedError renders an error's message with control characters collapsed,
// while still unwrapping to the original.
//
// Errors reaching stderr carry the target back to the user, and the target may
// come from a --targets file somebody else wrote, so stderr is a forgery surface
// too: it shares the terminal with the report and a sweep prints it after every
// report it produced. The message cannot simply be rebuilt with %s, because
// main unwraps with errors.As to tell a policy-gate failure (exit 2) from a scan
// failure (exit 1), and flattening the chain would silently change the exit code
// this tool's own CI guidance depends on. So scrub the text and keep the chain.
type scrubbedError struct{ err error }

func (e scrubbedError) Error() string {
	return sanitize.ForReport(e.err.Error(), sanitize.MaxReportDetail)
}

func (e scrubbedError) Unwrap() error { return e.err }

func scanSingleTarget(ctx context.Context, scan scanFunc, cnsa2 *analyzer.CNSA2Analyzer, policyEval *analyzer.PolicyEvaluator, target string, policy *types.Policy, output io.Writer) error {
	result, err := scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scan failed: %w", scrubbedError{err})
	}

	// Add CNSA 2.0 analysis
	if !skipCNSA2 {
		result.CNSA2Timeline = cnsa2.Analyze(result)
	}

	// Evaluate policy if specified
	if policy != nil {
		result.PolicyResult = policyEval.Evaluate(result, policy)
	}

	// Stamp the released binary's version so generated reports carry real
	// provenance rather than the scanner package default.
	result.ScannerVersion = version

	// Create reporter and output. The report is written before any gate result
	// is returned, so a failing policy still prints the findings that explain it.
	rep := createReporter()
	if err := rep.Report(output, result); err != nil {
		return err
	}

	return policyOutcome([]*types.ScanResult{result})
}

func scanBatchTargets(ctx context.Context, scan scanFunc, cnsa2 *analyzer.CNSA2Analyzer, policyEval *analyzer.PolicyEvaluator, targets []string, policy *types.Policy, output io.Writer) error {
	// Results are written to a fixed slot per target, so batch output follows the
	// order of the targets file. Appending as each scan finished produced an order
	// that varied between identical runs, and did so even at --concurrency 1,
	// because the semaphore does not hand out slots in the order goroutines
	// queued for them. That made a --targets sweep undiffable in CI.
	results := make([]*types.ScanResult, len(targets))
	var wg sync.WaitGroup

	// Semaphore for concurrency control
	sem := make(chan struct{}, concurrency)

	// Progress tracking
	total := len(targets)
	completed := 0
	var progressMu sync.Mutex

	for i, target := range targets {
		wg.Add(1)
		go func(slot int, t string) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			result, err := scan(ctx, t)
			if err != nil {
				result = &types.ScanResult{
					Target:         t,
					Error:          err.Error(),
					Timestamp:      time.Now(),
					ScannerVersion: version,
				}
			} else {
				// Add CNSA 2.0 analysis
				if !skipCNSA2 {
					result.CNSA2Timeline = cnsa2.Analyze(result)
				}

				// Evaluate policy if specified
				if policy != nil {
					result.PolicyResult = policyEval.Evaluate(result, policy)
				}

				// Stamp the released binary's version so generated reports
				// carry real provenance. The scanner package default would
				// otherwise leave every SARIF, CBOM and HTML report claiming a
				// version the user never installed.
				result.ScannerVersion = version
			}

			results[slot] = result

			// Update progress
			progressMu.Lock()
			completed++
			if !noColor && outputFile != "" {
				fmt.Fprintf(os.Stderr, "\rScanning: %d/%d targets completed", completed, total)
			}
			progressMu.Unlock()
		}(i, target)
	}

	wg.Wait()

	if !noColor && outputFile != "" {
		fmt.Fprintln(os.Stderr) // New line after progress
	}

	// Output results.
	//
	// Machine-readable formats are emitted as one document covering the whole
	// batch. Concatenating one JSON object per target produced a stream that
	// only lenient parsers such as jq accept; json.load and every strict parser
	// reject it, which broke the documented
	// "tlsanalyzer --targets hosts.txt --format json" workflow.
	if outputFormat == "json" {
		encoder := json.NewEncoder(output)
		if !jsonCompact {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(results); err != nil {
			return err
		}
		return batchOutcome(results)
	}

	rep := createReporter()
	for _, result := range results {
		if err := rep.Report(output, result); err != nil {
			return err
		}
		if outputFormat == "text" {
			fmt.Fprintln(output) // Separator between results
		}
	}

	return batchOutcome(results)
}

// batchOutcome fails the run when any target could not be scanned.
//
// Batch mode exited 0 with nothing on stderr even when every target failed, so
// "tlsanalyzer --targets hosts.txt && deploy" proceeded on a sweep that measured
// nothing. The single-target path has always exited non-zero for the same
// failure; this makes the two agree.
func batchOutcome(results []*types.ScanResult) error {
	failed := make([]string, 0, len(results))
	for _, result := range results {
		if result != nil && result.Error != "" {
			failed = append(failed, result.Target)
		}
	}

	// These names came from the targets file, so they are untrusted text on their
	// way to a terminal. stderr is not the report, but it shares the terminal with
	// it, and a sweep prints this line after every report it produced.
	for i := range failed {
		failed[i] = sanitize.ForReport(failed[i], sanitize.MaxReportDetail)
	}

	switch len(failed) {
	case 0:
		// Nothing failed to scan, so any remaining failure is the policy gate's.
		return policyOutcome(results)
	case len(results):
		return fmt.Errorf("no targets could be scanned (%d of %d failed): %s",
			len(failed), len(results), strings.Join(failed, ", "))
	default:
		return fmt.Errorf("%d of %d targets could not be scanned: %s",
			len(failed), len(results), strings.Join(failed, ", "))
	}
}

// applyPortOverride attaches the --port value to a target.
//
// The flag was previously declared and documented but never read, so
// "tlsanalyzer host -p 8443" silently scanned port 443 and reported a confident
// grade for a port the user never asked about. Only an explicitly provided flag
// overrides, so a target written as host:port keeps working on its own.
func applyPortOverride(target string, portOverride int) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		// No port present. Strip any brackets so JoinHostPort can re-add them
		// for an IPv6 literal rather than double-bracketing it.
		host = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	return net.JoinHostPort(host, strconv.Itoa(portOverride))
}

func collectTargets(args []string) ([]string, error) {
	var targets []string

	// From command line
	if len(args) > 0 {
		targets = append(targets, args[0])
	}

	// From file
	if targetsFile != "" {
		file, err := os.Open(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open targets file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read targets file: %w", err)
		}
	}

	return targets, nil
}

// validateFlags rejects every flag value the tool cannot act on, before any
// target is resolved or any connection is attempted.
//
// --port was the only numeric flag that was checked. --concurrency 0 hung
// forever on an unbuffered semaphore with nothing on either stream,
// --concurrency -1 panicked out of make() with a Go stack trace that also printed
// absolute source paths, and --timeout 0 or a negative value meant no timeout at
// all, so a single unresponsive host wedged an entire sweep.
func validateFlags(cmd *cobra.Command) error {
	// Reject an unrecognized format rather than falling back to text. A pipeline
	// asking for "--format JSON" previously received a text report and a success
	// exit code, so the mistake was invisible until something downstream failed
	// to parse it.
	if err := validateFormat(outputFormat); err != nil {
		return err
	}

	if cmd.Flags().Changed("port") {
		if err := scanner.ValidatePort(port); err != nil {
			return fmt.Errorf("--port: %w", err)
		}
	}

	if concurrency < 1 {
		return fmt.Errorf("--concurrency: invalid value %d: must be at least 1", concurrency)
	}

	if timeout < 1 {
		return fmt.Errorf("--timeout: invalid value %d: must be at least 1 second", timeout)
	}

	// Both flags name a policy and only one can be applied. --policy-file won
	// silently, so a run could be evaluated against a different policy than the
	// one the command line most visibly asked for, with nothing in the output
	// saying which had been used.
	if policyName != "" && policyFile != "" {
		// Both values come from the invocation, which this tool treats as
		// untrusted text, and policyName is already scrubbed where it is printed
		// as an unknown policy. Printing the same variable raw here was the split
		// that makes "fixing one print site is not fixing the class" concrete.
		return fmt.Errorf(
			"--policy %s and --policy-file %s both name a policy, and only one can be applied. "+
				"Pass one of them",
			sanitize.ForReport(policyName, sanitize.MaxReportDetail),
			sanitize.ForReport(policyFile, sanitize.MaxReportDetail))
	}

	return nil
}

// supportedFormats lists the accepted --format values, in help-text order.
var supportedFormats = []string{"text", "json", "sarif", "cbom", "html"}

// validateFormat rejects an unknown output format. Matching is case-sensitive
// so that "--format JSON" fails loudly rather than silently producing text.
func validateFormat(format string) error {
	for _, supported := range supportedFormats {
		if format == supported {
			return nil
		}
	}
	return fmt.Errorf("unknown format: %s (supported: %s)",
		format, strings.Join(supportedFormats, ", "))
}

func createReporter() reporter.Reporter {
	switch reporter.Format(outputFormat) {
	case reporter.FormatJSON:
		return &reporter.JSONReporter{Compact: jsonCompact}
	case reporter.FormatSARIF:
		return &reporter.SARIFReporter{}
	case reporter.FormatCBOM:
		return &reporter.CBOMReporter{}
	case reporter.FormatHTML:
		return &reporter.HTMLReporter{IncludeCSS: true}
	default:
		return &reporter.TextReporter{NoColor: !useColorForTextReport(noColor, outputFile, stdoutIsTTY())}
	}
}

// useColorForTextReport decides whether the text report may carry ANSI escapes.
//
// Colour is decided by the DESTINATION, not by stdout. Before 0.4.0 this read
// only stdout's TTY-ness, so `tlsanalyzer host -o report.txt` run from a
// terminal wrote 363 escape bytes into the saved file: the report went to the
// file while the colour decision still consulted the terminal. A saved report is
// read later by a pager, an editor, a diff or an auditor, so it has to be plain.
func useColorForTextReport(noColorFlag bool, outputPath string, stdoutIsTerminal bool) bool {
	if noColorFlag {
		return false
	}
	if outputPath != "" {
		return false
	}
	return stdoutIsTerminal
}

// stdoutIsTTY is a variable so tests can drive the decision in both directions.
// Under `go test` stdout is never a terminal, so a test that read the real one
// would pass before the fix and prove nothing.
var stdoutIsTTY = isTTY

// isTTY checks if stdout is a terminal
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func colorBold(s string) string {
	if noColor {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}
