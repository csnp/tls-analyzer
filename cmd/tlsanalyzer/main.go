// Package main provides the CLI entry point for qramm-tls-analyzer.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/csnp/qramm-tls-analyzer/internal/analyzer"
	"github.com/csnp/qramm-tls-analyzer/internal/reporter"
	"github.com/csnp/qramm-tls-analyzer/internal/scanner"
	"github.com/csnp/qramm-tls-analyzer/pkg/types"
	"github.com/spf13/cobra"
)

var (
	version = "0.3.0"
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(policiesCmd)

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

	if len(targets) == 0 {
		return fmt.Errorf("no targets specified. Use 'tlsanalyzer example.com' or '--targets file.txt'")
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
				return fmt.Errorf("unknown policy: %s (use 'policies' command to list available policies)", policyName)
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
		return scanSingleTarget(ctx, s, cnsa2Analyzer, policyEvaluator, targets[0], policy, output)
	}

	// Batch mode
	return scanBatchTargets(ctx, s, cnsa2Analyzer, policyEvaluator, targets, policy, output)
}

func scanSingleTarget(ctx context.Context, s *scanner.Scanner, cnsa2 *analyzer.CNSA2Analyzer, policyEval *analyzer.PolicyEvaluator, target string, policy *types.Policy, output *os.File) error {
	result, err := s.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
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

	// Create reporter and output
	rep := createReporter()
	return rep.Report(output, result)
}

func scanBatchTargets(ctx context.Context, s *scanner.Scanner, cnsa2 *analyzer.CNSA2Analyzer, policyEval *analyzer.PolicyEvaluator, targets []string, policy *types.Policy, output *os.File) error {
	results := make([]*types.ScanResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for concurrency control
	sem := make(chan struct{}, concurrency)

	// Progress tracking
	total := len(targets)
	completed := 0
	var progressMu sync.Mutex

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			result, err := s.Scan(ctx, t)
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

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			// Update progress
			progressMu.Lock()
			completed++
			if !noColor && outputFile != "" {
				fmt.Fprintf(os.Stderr, "\rScanning: %d/%d targets completed", completed, total)
			}
			progressMu.Unlock()
		}(target)
	}

	wg.Wait()

	if !noColor && outputFile != "" {
		fmt.Fprintln(os.Stderr) // New line after progress
	}

	// Output results
	rep := createReporter()
	for _, result := range results {
		if err := rep.Report(output, result); err != nil {
			return err
		}
		if outputFormat == "text" {
			fmt.Fprintln(output) // Separator between results
		}
	}

	return nil
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
		return &reporter.TextReporter{NoColor: noColor || !isTTY()}
	}
}

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
