# KubeShield

[![CI](https://github.com/y0s3ph/kubeshield/actions/workflows/ci.yml/badge.svg)](https://github.com/y0s3ph/kubeshield/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**AI-powered Kubernetes manifest security scanner.**

KubeShield performs static analysis of Kubernetes YAML manifests to detect security misconfigurations, reliability risks, and best practice violations — before they reach your cluster. Optionally, it uses AI to generate actionable remediation plans.

```
╭─────────────────────────────────────────────╮
│   KUBESHIELD    Kubernetes Security Scanner │
╰─────────────────────────────────────────────╯
╭──────────────────── Scan Summary ─────────────────────╮
│ Files scanned:      1                                 │
│ Resources scanned:  2                                 │
│ Total findings:     29                                │
│ Breakdown:          3 critical | 6 high | 13 medium   │
╰───────────────────────────────────────────────────────╯
╭──────────────────────────────────────────╮
│ Security Score: 0/100  |  Status: FAILED │
╰──────────────────────────────────────────╯
```

## Features

- **16 built-in security rules** aligned with [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- **Severity levels** — CRITICAL, HIGH, MEDIUM, LOW with color-coded output
- **Security scoring** — 0-100 score for quick assessment
- **AI remediation** — optional LLM-powered fix suggestions with YAML snippets (OpenAI)
- **CI/CD ready** — configurable exit codes, JSON output, file reports
- **Multi-document support** — handles multi-doc YAML and directory scanning
- **Zero dependencies on a cluster** — pure static analysis of manifest files

## Rules

| ID | Severity | Category | Description |
|---|---|---|---|
| KS-SEC-001 | HIGH | Security | Container runs as root |
| KS-SEC-002 | CRITICAL | Security | Privileged container |
| KS-SEC-003 | MEDIUM | Security | Writable root filesystem |
| KS-SEC-004 | MEDIUM | Security | Linux capabilities not dropped |
| KS-SEC-005 | HIGH | Security | Privilege escalation allowed |
| KS-SEC-006 | CRITICAL | Security | Host namespace sharing (PID/Net/IPC) |
| KS-SEC-007 | MEDIUM | Security | Image uses `latest` or untagged |
| KS-SEC-008 | LOW | Security | Missing Seccomp profile |
| KS-SEC-009 | LOW | Security | Auto-mounted service account token |
| KS-REL-001 | MEDIUM | Reliability | Missing liveness probe |
| KS-REL-002 | MEDIUM | Reliability | Missing readiness probe |
| KS-REL-003 | LOW | Reliability | Single replica deployment |
| KS-RES-001 | HIGH | Resources | Missing resource limits |
| KS-RES-002 | MEDIUM | Resources | Missing resource requests |
| KS-NET-001 | MEDIUM | Networking | Container uses hostPort |
| KS-NET-002 | LOW | Best Practice | Resource in default namespace |

## Installation

```bash
pip install git+https://github.com/y0s3ph/kubeshield.git
```

Or for development:

```bash
git clone https://github.com/y0s3ph/kubeshield.git
cd kubeshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

### Scan manifests

```bash
# Scan a single file
kubeshield scan deployment.yaml

# Scan a directory recursively
kubeshield scan ./k8s/

# Scan multiple paths
kubeshield scan deployment.yaml service.yaml ./manifests/
```

### Filter by severity or rule

```bash
# Only show critical and high findings
kubeshield scan -s CRITICAL -s HIGH ./manifests/

# Run specific rules only
kubeshield scan -r KS-SEC-002 -r KS-SEC-006 deployment.yaml
```

### Output formats

```bash
# JSON to stdout (for piping)
kubeshield scan --json deployment.yaml

# Save JSON report to file
kubeshield scan -o report.json deployment.yaml
```

### AI-powered remediation

```bash
# Set your API key
export OPENAI_API_KEY=sk-...

# Get AI remediation suggestions
kubeshield scan --ai deployment.yaml
```

### CI/CD integration

```bash
# Fail only on critical findings (default: high)
kubeshield scan --fail-on critical ./manifests/

# Fail on any finding
kubeshield scan --fail-on any ./manifests/
```

### List available rules

```bash
kubeshield rules
```

## CI/CD Pipeline Example

### GitHub Actions

```yaml
- name: Install KubeShield
  run: pip install git+https://github.com/y0s3ph/kubeshield.git

- name: Scan manifests
  run: kubeshield scan --fail-on high -o report.json ./k8s/

- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: kubeshield-report
    path: report.json
```

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=kubeshield --cov-report=term-missing

# Lint
ruff check .

# Format
ruff format .
```

## Architecture

```
kubeshield/
├── cli.py          # Click CLI entrypoint
├── scanner.py      # Core engine: loads manifests, applies rules
├── models.py       # Data models: Severity, Finding, ScanResult
├── rules/          # Pluggable rule engine
│   ├── base.py     # Abstract Rule class with auto-registration
│   ├── security.py # CIS-aligned security rules
│   ├── reliability.py
│   ├── resources.py
│   └── networking.py
├── report/         # Output formatters
│   ├── console.py  # Rich terminal output
│   └── json_report.py
└── ai/
    └── advisor.py  # LLM-powered remediation suggestions
```

## License

MIT
