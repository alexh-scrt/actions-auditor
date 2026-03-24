# actions-auditor

> Audit your GitHub Actions before attackers do.

`actions-auditor` is a CLI security tool that scans GitHub Actions workflow YAML files for common misconfigurations and vulnerabilities. It produces a prioritized, color-coded risk report with concrete remediation guidance and exits with a non-zero status code so you can gate your CI pipelines on security findings.

---

## Quick Start

```bash
# Install from PyPI
pip install actions-auditor

# Scan the default .github/workflows/ directory
actions-auditor scan

# Scan a specific directory or file
actions-auditor scan path/to/workflows/

# Fail only on HIGH severity and above
actions-auditor scan --min-severity HIGH
```

That's it. A color-coded report prints to your terminal, and the process exits with code `1` if any findings are detected.

---

## What It Does

`actions-auditor` parses your GitHub Actions workflow YAML files and runs a suite of security rules against them — catching issues like overly broad token permissions, exposed secrets, unpinned third-party actions, and dangerous trigger patterns. Each finding is tagged with a severity level, a file and line reference, and a concrete remediation step so you know exactly what to fix and why.

---

## Features

- **Token permission auditing** — Detects `permissions: write-all` and missing least-privilege scope declarations (AA001, AA002)
- **Secret exposure detection** — Finds secrets leaked via `env` blocks, `run` scripts, or `workflow_dispatch` inputs that could appear in logs (AA003, AA004, AA008)
- **Supply-chain attack prevention** — Flags third-party Actions not pinned to a full 40-character commit SHA (AA005)
- **Dangerous trigger detection** — Identifies `pull_request_target` combined with a PR head checkout — the exact vector behind major CI/CD breaches (AA006)
- **Script injection detection** — Catches untrusted GitHub context values interpolated directly into `run` scripts (AA007)
- **CI/CD gating** — Exits with a non-zero status on findings; integrates as a pre-commit hook or standalone pipeline step

---

## Usage Examples

### Standalone CLI

```bash
# Scan default workflow directory
actions-auditor scan

# Scan a custom path
actions-auditor scan .github/workflows/deploy.yml

# Filter to CRITICAL and HIGH only
actions-auditor scan --min-severity HIGH

# Output in JSON format (for downstream processing)
actions-auditor scan --format json

# Suppress color output (e.g. in CI logs)
actions-auditor scan --no-color
```

### Example Report Output

```
╔══════════════════════════════════════════════════════╗
║         actions-auditor  v0.1.0  Security Report     ║
╚══════════════════════════════════════════════════════╝

🔴 CRITICAL  AA006  deploy.yml:14
  pull_request_target trigger with head-ref checkout detected.
  → Use pull_request instead, or never check out untrusted code
    in a pull_request_target workflow.
    Ref: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/

🟠 HIGH      AA001  ci.yml:3
  permissions: write-all grants excessive GITHUB_TOKEN scope.
  → Declare explicit, minimal scopes (e.g. contents: read).
    Ref: https://docs.github.com/en/actions/security-guides/automatic-token-authentication

🟡 MEDIUM    AA005  ci.yml:22
  Third-party action 'actions/checkout@v3' is not pinned to a commit SHA.
  → Pin to a full SHA: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    Ref: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions

──────────────────────────────────────────────────────
Summary: 3 findings  [CRITICAL: 1 | HIGH: 1 | MEDIUM: 1]
```

### As a Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/example/actions-auditor
    rev: v0.1.0
    hooks:
      - id: actions-auditor
```

The hook automatically scans staged workflow files and blocks the commit if any security issues are found.

---

## Security Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| AA001 | HIGH | `permissions: write-all` or overly broad GITHUB_TOKEN scope |
| AA002 | MEDIUM | Missing top-level `permissions` declaration |
| AA003 | HIGH | Secret exposed in `env` block |
| AA004 | HIGH | Secret interpolated directly in `run` script |
| AA005 | MEDIUM | Third-party action not pinned to a full commit SHA |
| AA006 | CRITICAL | `pull_request_target` trigger with PR head checkout |
| AA007 | HIGH | Script injection from untrusted GitHub context values |
| AA008 | HIGH | `workflow_dispatch` input interpolated in `run` script |

---

## Project Structure

```
actions-auditor/
├── actions_auditor/
│   ├── __init__.py        # Package init, version, public API
│   ├── cli.py             # CLI entry point and argument parsing
│   ├── scanner.py         # Workflow file discovery and YAML loading
│   ├── rules.py           # Security rule checker functions
│   ├── models.py          # Finding, Severity, ScanResult dataclasses
│   ├── reporter.py        # Color-coded terminal report rendering
│   └── remediation.py     # Rule ID → remediation advice registry
├── tests/
│   ├── __init__.py
│   ├── test_rules.py      # Unit tests for each security rule
│   ├── test_scanner.py    # Tests for file discovery and YAML parsing
│   ├── test_models.py     # Tests for core data models
│   ├── test_reporter.py   # Tests for report rendering
│   ├── test_remediation.py
│   └── fixtures/
│       ├── good_workflow.yml  # Negative test case (zero findings)
│       └── bad_workflow.yml   # Positive test case (all violations)
├── .pre-commit-hooks.yaml
├── pyproject.toml
└── README.md
```

---

## Configuration

`actions-auditor` is configured via CLI flags. No config file is required.

| Flag | Default | Description |
|------|---------|-------------|
| `PATH` | `.github/workflows/` | Directory or file to scan |
| `--min-severity` | `INFO` | Minimum severity to report (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `--format` | `terminal` | Output format: `terminal` or `json` |
| `--no-color` | `False` | Disable color output |
| `--no-remediation` | `False` | Omit remediation advice from output |
| `--exit-zero` | `False` | Always exit 0, even when findings are detected |

### CI Pipeline Integration

```yaml
# .github/workflows/audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: pip install actions-auditor
      - run: actions-auditor scan --min-severity MEDIUM
```

---

## Installation

**Requirements:** Python 3.9+

```bash
# From PyPI
pip install actions-auditor

# From source
git clone https://github.com/example/actions-auditor
cd actions-auditor
pip install -e .
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
