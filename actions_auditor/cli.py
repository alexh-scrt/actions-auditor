"""CLI entry point for actions_auditor.

This module wires up the command-line interface using ``argparse`` and
orchestrates the full scan pipeline:

1. Parse command-line arguments.
2. Discover and load workflow YAML files via :class:`~actions_auditor.scanner.Scanner`.
3. Apply all security rules via :func:`~actions_auditor.rules.run_all_rules`.
4. Render the report via :class:`~actions_auditor.reporter.Reporter`.
5. Exit with a non-zero status code when findings are detected (for CI gating).

The tool exposes a single ``scan`` sub-command::

    actions-auditor scan [PATH] [OPTIONS]

Example invocations::

    # Scan the default .github/workflows/ directory
    actions-auditor scan

    # Scan a specific directory
    actions-auditor scan /path/to/repo

    # Scan with verbose output and a minimum severity filter
    actions-auditor scan --verbose --min-severity HIGH

    # Scan specific files (pre-commit integration)
    actions-auditor scan --files ci.yml deploy.yml

    # Output summary only
    actions-auditor scan --summary-only

The module also exposes a :func:`main` function that serves as the
installed ``actions-auditor`` console script entry point.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from rich.console import Console

from actions_auditor import __version__
from actions_auditor.models import Severity, ScanResult
from actions_auditor.reporter import Reporter, render_report
from actions_auditor.rules import run_all_rules
from actions_auditor.scanner import Scanner, ScannerError, WorkflowFile


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity argument type
# ---------------------------------------------------------------------------


def _parse_severity(value: str) -> Severity:
    """Convert a CLI severity string to a :class:`~actions_auditor.models.Severity` enum.

    Args:
        value: A case-insensitive severity name, e.g. ``'HIGH'``, ``'medium'``.

    Returns:
        The corresponding :class:`~actions_auditor.models.Severity` member.

    Raises:
        :class:`argparse.ArgumentTypeError`: If *value* is not a valid severity name.
    """
    normalised = value.strip().upper()
    try:
        return Severity[normalised]
    except KeyError:
        valid = ", ".join(s.name for s in Severity)
        raise argparse.ArgumentTypeError(
            f"Invalid severity '{value}'. Valid choices are: {valid}"
        )


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser.

    Returns:
        A configured :class:`argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        prog="actions-auditor",
        description=(
            "Scan GitHub Actions workflow YAML files for common "
            "misconfigurations and security vulnerabilities."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  actions-auditor scan                         # scan .github/workflows/\n"
            "  actions-auditor scan /path/to/repo           # scan specific root dir\n"
            "  actions-auditor scan --verbose               # verbose output\n"
            "  actions-auditor scan --min-severity HIGH     # filter by severity\n"
            "  actions-auditor scan --files ci.yml          # scan specific files\n"
            "  actions-auditor scan --summary-only          # print summary only\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"actions-auditor {__version__}",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug logging output.",
    )

    # Sub-commands
    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    # ------------------------------------------------------------------
    # 'scan' sub-command
    # ------------------------------------------------------------------
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan GitHub Actions workflow files for security issues.",
        description=(
            "Scan GitHub Actions workflow YAML files in a target directory "
            "or a specified list of files for security misconfigurations."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scan_parser.add_argument(
        "path",
        nargs="?",
        default=None,
        metavar="PATH",
        help=(
            "Root directory to scan. The tool will look for workflow files in "
            "<PATH>/.github/workflows/. Defaults to the current working directory."
        ),
    )

    scan_parser.add_argument(
        "--files",
        nargs="+",
        metavar="FILE",
        default=None,
        help=(
            "Explicit list of workflow YAML files to scan. When provided, "
            "PATH and --workflows-dir are ignored. Useful for pre-commit integration."
        ),
    )

    scan_parser.add_argument(
        "--workflows-dir",
        metavar="DIR",
        default=None,
        help=(
            "Override the workflows sub-directory to search. "
            "Defaults to .github/workflows/ relative to PATH."
        ),
    )

    scan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help=(
            "Emit detailed per-finding panels including descriptions and "
            "remediation guidance."
        ),
    )

    scan_parser.add_argument(
        "--no-remediation",
        action="store_true",
        default=False,
        help="Suppress remediation advice panels (only effective with --verbose).",
    )

    scan_parser.add_argument(
        "--summary-only",
        action="store_true",
        default=False,
        help="Print only the summary panel; suppress the per-severity finding tables.",
    )

    scan_parser.add_argument(
        "--show-files",
        action="store_true",
        default=False,
        help="Include the list of scanned files in the summary panel.",
    )

    scan_parser.add_argument(
        "--min-severity",
        metavar="LEVEL",
        type=_parse_severity,
        default=Severity.INFO,
        help=(
            "Minimum severity level to report. Findings below this level are "
            "suppressed. Choices: CRITICAL, HIGH, MEDIUM, LOW, INFO (default: INFO)."
        ),
    )

    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color output (useful for CI log capture).",
    )

    scan_parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help=(
            "Always exit with status 0, even when findings are detected. "
            "Useful when integrating as a warning-only step in CI."
        ),
    )

    scan_parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        default=False,
        help="Follow symbolic links when traversing the workflows directory.",
    )

    return parser


# ---------------------------------------------------------------------------
# Scan command implementation
# ---------------------------------------------------------------------------


def _run_scan(args: argparse.Namespace, console: Optional[Console] = None) -> int:
    """Execute the ``scan`` sub-command and return the process exit code.

    Args:
        args: Parsed :class:`argparse.Namespace` from the ``scan`` sub-command.
        console: Optional :class:`~rich.console.Console` to use for output.
            When ``None``, a new console is created respecting ``--no-color``.

    Returns:
        An integer exit code: ``0`` for success / no findings (or
        ``--exit-zero`` was passed), ``1`` when findings are detected,
        ``2`` for operational errors (e.g., directory not found).
    """
    # ------------------------------------------------------------------
    # Set up console
    # ------------------------------------------------------------------
    if console is None:
        console = Console(no_color=getattr(args, "no_color", False))

    # ------------------------------------------------------------------
    # Determine target path
    # ------------------------------------------------------------------
    if args.path is not None:
        root = Path(args.path).resolve()
    else:
        root = Path.cwd()

    # ------------------------------------------------------------------
    # Build explicit paths list (if --files was provided)
    # ------------------------------------------------------------------
    explicit_paths: Optional[List[Path]] = None
    if args.files:
        explicit_paths = [Path(f) for f in args.files]

    # ------------------------------------------------------------------
    # Build workflows directory override (if --workflows-dir was provided)
    # ------------------------------------------------------------------
    workflows_dir: Optional[Path] = None
    if args.workflows_dir:
        workflows_dir = Path(args.workflows_dir)

    # ------------------------------------------------------------------
    # Discover and load workflow files
    # ------------------------------------------------------------------
    scanner = Scanner(
        root=root,
        workflows_dir=workflows_dir,
        explicit_paths=explicit_paths,
        follow_symlinks=getattr(args, "follow_symlinks", False),
    )

    try:
        workflow_files: List[WorkflowFile] = scanner.scan()
    except ScannerError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    if not workflow_files:
        console.print(
            "[yellow]Warning:[/yellow] No workflow YAML files found. "
            "Ensure the target directory contains .github/workflows/*.yml files "
            "or pass explicit files with --files."
        )
        return 0

    # ------------------------------------------------------------------
    # Apply security rules to each workflow file
    # ------------------------------------------------------------------
    result = ScanResult()

    for wf in workflow_files:
        result.add_scanned_file(wf.path)

        if not wf.is_valid:
            console.print(
                f"[yellow]Warning:[/yellow] Skipping unparseable file "
                f"[cyan]{wf.path}[/cyan]: {wf.parse_error}"
            )
            continue

        findings = run_all_rules(wf)
        result.add_findings(findings)

        logger.debug(
            "Scanned %s: %d finding(s)",
            wf.path,
            len(findings),
        )

    # ------------------------------------------------------------------
    # Render the report
    # ------------------------------------------------------------------
    min_severity: Severity = getattr(args, "min_severity", Severity.INFO)
    verbose: bool = getattr(args, "verbose", False)
    show_remediation: bool = not getattr(args, "no_remediation", False)
    show_files: bool = getattr(args, "show_files", False)
    summary_only: bool = getattr(args, "summary_only", False)

    if summary_only:
        # Only print the summary panel
        reporter = Reporter(
            console=console,
            show_file_list=show_files,
            min_severity=min_severity,
        )
        reporter.render_summary(result)
    else:
        reporter = Reporter(
            console=console,
            verbose=verbose,
            show_remediation=show_remediation,
            show_file_list=show_files,
            min_severity=min_severity,
        )
        reporter.render(result)

    # ------------------------------------------------------------------
    # Determine exit code
    # ------------------------------------------------------------------
    if getattr(args, "exit_zero", False):
        return 0

    return result.exit_code


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments, execute the requested command, and return an exit code.

    This function is registered as the ``actions-auditor`` console script
    entry point in ``pyproject.toml``.  It is also callable directly for
    programmatic use and testing.

    Args:
        argv: Optional sequence of command-line argument strings.  When
            ``None`` (the default), ``sys.argv[1:]`` is used.

    Returns:
        An integer exit code suitable for passing to :func:`sys.exit`.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------
    # Configure logging
    # ------------------------------------------------------------------
    log_level = logging.DEBUG if getattr(args, "debug", False) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,
    )

    # ------------------------------------------------------------------
    # Dispatch sub-commands
    # ------------------------------------------------------------------
    command = getattr(args, "command", None)

    if command == "scan":
        return _run_scan(args)

    # No sub-command given — if the user ran `actions-auditor` with no args,
    # treat it as `actions-auditor scan` with defaults (convenient for
    # pre-commit hooks that call `actions-auditor` without a sub-command).
    if command is None:
        # Insert a synthetic 'scan' command and re-parse so all scan
        # defaults are applied correctly.
        effective_argv = list(argv) if argv is not None else list(sys.argv[1:])
        effective_argv.insert(0, "scan")
        args = parser.parse_args(effective_argv)
        return _run_scan(args)

    # Unknown command — this should not be reachable because argparse handles
    # unknown sub-commands, but guard defensively.
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
