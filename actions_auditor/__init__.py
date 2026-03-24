"""actions_auditor: A CLI security tool for scanning GitHub Actions workflow files.

This package scans GitHub Actions workflow YAML files for common
misconfigurations and vulnerabilities, including:

- Overly permissive GITHUB_TOKEN scopes
- Exposed secrets in environment variables or run scripts
- Third-party actions not pinned to a full commit SHA
- Dangerous pull_request_target triggers with head checkouts
- Script injection risks from untrusted inputs

The tool produces a prioritized, color-coded risk report with concrete
remediation guidance and exits with a non-zero status when findings are
detected, enabling CI/CD pipeline gating.

Typical usage::

    from actions_auditor import __version__
    print(__version__)

Or via the CLI::

    actions-auditor scan .github/workflows/
"""

__version__ = "0.1.0"
__author__ = "actions-auditor contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
