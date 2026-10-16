# Commands and flags

The flags for a scan, the `policies`, `print-policy` and `version` commands,
and the exit codes. Run `tlsanalyzer --help` for the list your own build
prints.

## CLI Reference

```
USAGE:
  tlsanalyzer [target] [flags]
  tlsanalyzer [command]

COMMANDS:
  policies      List available security policies
  print-policy  Print a built-in policy as YAML, to copy as a starting point
  version       Print version information

FLAGS:
  -f, --format string      Output format: text, json, sarif, cbom, html (default "text")
  -o, --output string      Output file (default: stdout)
  -t, --timeout int        Connection timeout in seconds (default 30)
  -p, --port int           Target port, 1-65535, overrides a port in the
                           target (default 443)
      --sni string         Server Name Indication (SNI)
      --no-color           Disable colored output
      --compact            Compact JSON output
      --skip-vulns         Skip vulnerability checks
      --skip-quantum       Skip quantum risk assessment
      --skip-cnsa2         Skip CNSA 2.0 compliance analysis
      --policy string      Apply a security policy
      --policy-file string Path to custom policy YAML file
      --targets string     File containing list of targets
  -c, --concurrency int    Concurrent scans for batch mode (default 10)
  -h, --help              Help for tlsanalyzer

EXIT CODES:
  0  scanned, and any policy applied was fully evaluated and satisfied
  1  the scan could not be completed
  2  a policy was applied and the target did not satisfy it, or the policy
     could not be fully evaluated
```

`--policy` and `--policy-file` both name a policy, so passing both is an error
rather than one silently winning.

## Output formats

Other formats: `--format json` for automation, `--format cbom` for [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), `--format html` for shareable reports, `--format sarif` for GitHub Security.
