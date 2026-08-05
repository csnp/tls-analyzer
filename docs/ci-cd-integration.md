# CI/CD Integration Guide

This guide covers integrating QRAMM TLS Analyzer into your continuous integration and deployment pipelines.

## GitHub Actions

### Basic TLS Scan

```yaml
name: TLS Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  tls-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install TLS Analyzer
        run: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

      - name: Scan Production Endpoint
        run: tlsanalyzer api.example.com --format json -o tls-report.json

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: tls-report
          path: tls-report.json
```

### With SARIF Upload to GitHub Security

```yaml
name: TLS Security Scan with SARIF

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday

jobs:
  tls-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install TLS Analyzer
        run: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

      - name: Scan Endpoint
        run: tlsanalyzer api.example.com --format sarif -o tls-results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tls-results.sarif
          category: tls-security
```

### Policy Compliance Gate

```yaml
name: TLS Policy Compliance

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install TLS Analyzer
        run: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

      - name: Check Compliance
        run: |
          RESULT=$(tlsanalyzer api.example.com --policy cnsa-2.0-2027 --format json)
          COMPLIANT=$(echo $RESULT | jq -r '.policyResult.compliant')
          SCORE=$(echo $RESULT | jq -r '.policyResult.score')

          echo "Compliance: $COMPLIANT"
          echo "Score: $SCORE/100"

          if [ "$COMPLIANT" != "true" ]; then
            echo "::error::Policy compliance check failed"
            echo $RESULT | jq '.policyResult.violations[]'
            exit 1
          fi
```

### Batch Scanning Multiple Endpoints

```yaml
name: Batch TLS Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  batch-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install TLS Analyzer
        run: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

      - name: Create Targets List
        run: |
          cat > targets.txt << EOF
          api.example.com
          web.example.com
          auth.example.com
          EOF

      - name: Run Batch Scan
        run: |
          tlsanalyzer --targets targets.txt --format html -o batch-report.html
          tlsanalyzer --targets targets.txt --format json -o batch-report.json

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: tls-reports
          path: |
            batch-report.html
            batch-report.json

      - name: Check for Critical Issues
        run: |
          CRITICAL=$(cat batch-report.json | jq '[.[] | select(.grade.letter == "F")] | length')
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Found $CRITICAL endpoints with failing grades"
            exit 1
          fi
```

## GitLab CI

### Basic Scan

```yaml
stages:
  - security

tls_security_scan:
  stage: security
  image: golang:1.25
  variables:
    TARGET: api.example.com
  script:
    - go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
    - tlsanalyzer $TARGET --format json -o tls-report.json
    - tlsanalyzer $TARGET --format html -o tls-report.html
  artifacts:
    paths:
      - tls-report.json
      - tls-report.html
    expire_in: 30 days
  only:
    - main
    - schedules
```

### With Policy Check

```yaml
tls_compliance_check:
  stage: security
  image: golang:1.25
  variables:
    TARGET: api.example.com
    POLICY: cnsa-2.0-2027
  script:
    - go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
    - |
      RESULT=$(tlsanalyzer $TARGET --policy $POLICY --format json)
      echo $RESULT > compliance-report.json
      COMPLIANT=$(echo $RESULT | jq -r '.policyResult.compliant')
      if [ "$COMPLIANT" != "true" ]; then
        echo "Policy compliance check failed"
        echo $RESULT | jq '.policyResult.violations[]'
        exit 1
      fi
  artifacts:
    paths:
      - compliance-report.json
    when: always
```

## Jenkins

### Jenkinsfile

```groovy
pipeline {
    agent any

    environment {
        TARGET = 'api.example.com'
    }

    stages {
        stage('Setup') {
            steps {
                sh 'go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest'
            }
        }

        stage('TLS Scan') {
            steps {
                sh 'tlsanalyzer ${TARGET} --format json -o tls-report.json'
                sh 'tlsanalyzer ${TARGET} --format html -o tls-report.html'
            }
        }

        stage('Policy Check') {
            steps {
                script {
                    def result = sh(
                        script: 'tlsanalyzer ${TARGET} --policy cnsa-2.0-2027 --format json',
                        returnStdout: true
                    )
                    def json = readJSON text: result
                    if (!json.policyResult.compliant) {
                        error "TLS Policy compliance check failed"
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'tls-report.*'
        }
    }
}
```

## Azure DevOps

### azure-pipelines.yml

```yaml
trigger:
  - main

schedules:
  - cron: '0 0 * * *'
    displayName: Daily TLS Scan
    branches:
      include:
        - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  TARGET: 'api.example.com'

steps:
  - task: GoTool@0
    inputs:
      version: '1.25'

  - script: |
      go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
    displayName: 'Install TLS Analyzer'

  - script: |
      tlsanalyzer $(TARGET) --format json -o $(Build.ArtifactStagingDirectory)/tls-report.json
      tlsanalyzer $(TARGET) --format sarif -o $(Build.ArtifactStagingDirectory)/tls-results.sarif
    displayName: 'Run TLS Scan'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'tls-reports'
```

## CircleCI

### .circleci/config.yml

```yaml
version: 2.1

jobs:
  tls-scan:
    docker:
      - image: cimg/go:1.25
    steps:
      - checkout
      - run:
          name: Install TLS Analyzer
          command: go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest
      - run:
          name: Run TLS Scan
          command: |
            tlsanalyzer api.example.com --format json -o tls-report.json
            tlsanalyzer api.example.com --format html -o tls-report.html
      - store_artifacts:
          path: tls-report.json
      - store_artifacts:
          path: tls-report.html

workflows:
  security-scan:
    jobs:
      - tls-scan
```

## Docker Integration

### Dockerfile for CI

```dockerfile
FROM golang:1.25-alpine

RUN go install github.com/csnp/qramm-tls-analyzer/cmd/tlsanalyzer@latest

ENTRYPOINT ["tlsanalyzer"]
```

### Usage in CI

```bash
# Build scanner image
docker build -t tls-analyzer .

# Run scan
docker run --rm tls-analyzer api.example.com --format json
```

## Best Practices

1. **Run on schedule** - Daily or weekly scans catch certificate expiry and configuration drift
2. **Use policy gates** - Block deployments that don't meet security requirements
3. **Store reports** - Archive scan results for compliance auditing
4. **Alert on failures** - Integrate with Slack/Teams for immediate notification
5. **Track trends** - Compare scores over time to measure security posture
6. **Scan staging first** - Validate TLS configuration before production deployment
