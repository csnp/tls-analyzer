# Contributing to QRAMM TLS Analyzer

Thank you for your interest in contributing to QRAMM TLS Analyzer! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Issues

1. Check if the issue already exists in [GitHub Issues](https://github.com/csnp/qramm-tls-analyzer/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Environment details (OS, Go version, etc.)

### Suggesting Features

1. Open a [GitHub Issue](https://github.com/csnp/qramm-tls-analyzer/issues) with the "enhancement" label
2. Describe the feature and its use case
3. Explain why it would benefit users

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test ./... -v`
5. Run linter: `go vet ./...`
6. Format code: `gofmt -s -w .`
7. Commit with a clear message
8. Push and create a Pull Request

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git

### Getting Started

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/qramm-tls-analyzer.git
cd qramm-tls-analyzer

# Add upstream remote
git remote add upstream https://github.com/csnp/qramm-tls-analyzer.git

# Install dependencies
go mod download

# Build
go build -o tlsanalyzer ./cmd/tlsanalyzer

# Run tests
go test ./... -v
```

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Specific package
go test ./internal/analyzer/... -v

# Short tests (skip integration tests)
go test ./... -short
```

### Code Style

- Follow standard Go conventions
- Run `gofmt -s -w .` before committing
- Run `go vet ./...` to check for issues
- Add comments for exported functions and types
- Keep functions focused and testable

## Project Structure

```
qramm-tls-analyzer/
├── cmd/
│   └── tlsanalyzer/
│       └── main.go           # CLI entry point
├── internal/
│   ├── analyzer/             # Analysis logic
│   │   ├── cnsa2.go          # CNSA 2.0 compliance
│   │   └── policy.go         # Policy evaluation
│   ├── reporter/             # Output formatters
│   │   ├── cbom.go           # CycloneDX CBOM
│   │   ├── html.go           # HTML reports
│   │   ├── json.go           # JSON output
│   │   ├── sarif.go          # SARIF format
│   │   └── text.go           # Terminal output
│   └── scanner/              # TLS scanning
│       ├── scanner.go        # Core scanning
│       ├── quantum.go        # PQC assessment
│       ├── grade.go          # Grading system
│       └── vulnerabilities.go # Vuln detection
├── pkg/
│   └── types/                # Shared types
│       ├── result.go         # Scan results
│       ├── policy.go         # Policy definitions
│       ├── cbom.go           # CBOM types
│       └── compliance.go     # Compliance types
├── docs/                     # Documentation
└── policies/                 # Built-in policies
```

## Guidelines

### Adding New Features

1. Discuss major changes in an issue first
2. Write tests for new functionality
3. Update documentation as needed
4. Keep backward compatibility

### Adding Output Formats

1. Create a new file in `internal/reporter/`
2. Implement the format logic
3. Add CLI flag support in `cmd/tlsanalyzer/main.go`
4. Add tests and documentation

### Adding Policies

1. Create YAML policy in `policies/` directory
2. Add policy to the built-in policy list
3. Document the policy purpose and requirements
4. Add tests for policy evaluation

### Adding Vulnerability Checks

1. Add detection logic in `internal/scanner/vulnerabilities.go`
2. Include references to CVE or security advisories
3. Add remediation guidance
4. Write tests with known-vulnerable configurations

## Testing Guidelines

- Write unit tests for all new functions
- Use table-driven tests where appropriate
- Mock external dependencies (network calls)
- Test edge cases and error conditions
- Aim for >80% coverage on new code

## Documentation

- Update README.md for user-facing changes
- Add/update docs/ for detailed guides
- Include code comments for complex logic
- Add examples for new features

## Release Process

Releases are managed by maintainers:

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create annotated tag: `git tag -a v0.x.0 -m "Release v0.x.0"`
4. Push tag: `git push origin v0.x.0`
5. GitHub Actions builds and publishes release
6. Render the Homebrew formula from the release's published `checksums.txt`, and
   commit the output to [csnp/homebrew-tap](https://github.com/csnp/homebrew-tap)
   as `Formula/tlsanalyzer.rb`:

   ```bash
   dir=$(mktemp -d)
   curl -fsSL -o "$dir/checksums.txt" https://github.com/csnp/tls-analyzer/releases/download/v0.x.0/checksums.txt
   go run ./packaging/brewformula -version 0.x.0 -checksums "$dir/checksums.txt" > "$dir/tlsanalyzer.rb"
   ```

## Getting Help

- Open an issue for questions
- Join discussions in existing issues
- Check existing documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Acknowledgments

Thank you to all contributors who help make this project better!
