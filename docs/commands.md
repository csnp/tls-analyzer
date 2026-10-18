# Commands and flags

The flags for a scan, the `policies`, `print-policy` and `version` commands,
and the exit codes. Run `tlsanalyzer --help` for the list your own build
prints.

## CLI Reference

The commands and flags, as `tlsanalyzer --help` lists them:

```
Usage:
  tlsanalyzer [target] [flags]
  tlsanalyzer [command]

Available Commands:
  completion   Generate the autocompletion script for the specified shell
  help         Help about any command
  policies     List available security policies
  print-policy Print a built-in policy as YAML, to copy as a starting point
  version      Print version information

Flags:
      --compact              Compact JSON output (no indentation)
  -c, --concurrency int      Number of concurrent scans for batch mode (default 10)
  -f, --format string        Output format: text, json, sarif, cbom, html (default "text")
  -h, --help                 help for tlsanalyzer
      --no-color             Disable colored output
  -o, --output string        Output file (default: stdout)
      --policy string        Apply a security policy (use 'policies' command to list)
      --policy-file string   Path to custom policy YAML file
  -p, --port int             Target port, 1-65535, overrides a port in the target (default 443)
      --skip-cnsa2           Skip CNSA 2.0 compliance analysis
      --skip-quantum         Skip quantum risk assessment
      --skip-vulns           Skip vulnerability checks
      --sni string           Server Name Indication (SNI) to use
      --targets string       File with one host name, IP address or host:port per
                             line. Lines starting with # are skipped. Every line is
                             checked before anything is looked up, and a file with
                             any other line is refused
  -t, --timeout int          Connection timeout in seconds (default 30)
  -v, --version              version for tlsanalyzer

Use "tlsanalyzer [command] --help" for more information about a command.
```

`tlsanalyzer --version` prints the same text as `tlsanalyzer version`.
`tlsanalyzer policies` also takes `--no-color`. Without it, the policy names
are bold on a terminal and plain when the listing goes to a pipe or a file.

The exit codes, as `tlsanalyzer --help` gives them:

```
Exit codes:
  0  scanned, and any policy applied was fully evaluated and satisfied
  1  the scan could not be completed
  2  a policy was applied and the target did not satisfy it, or the policy
     could not be fully evaluated, which does not establish compliance
```

`--policy` and `--policy-file` both name a policy, so passing both is an error
rather than one silently winning.

## Output formats

Other formats: `--format json` for automation, `--format cbom` for [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), `--format html` for shareable reports, `--format sarif` for GitHub Security.
