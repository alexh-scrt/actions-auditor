"""Rich terminal reporter for actions_auditor.

This module renders a prioritized, color-coded security risk report to the
terminal using the ``rich`` library. It groups findings by severity level,
attaches remediation guidance from :mod:`actions_auditor.remediation`, and
provides a summary panel with severity counts.

Key public API:

- :func:`render_report`: Render a complete scan report to the terminal.
- :func:`render_summary`: Render only the summary panel.
- :func:`render_findings_table`: Render a table of findings for one severity.
- :class:`Reporter`: Stateful reporter class for full control over output.

Typical usage::

    from actions_auditor.reporter import Reporter
    from actions_auditor.models import ScanResult

    result: ScanResult = ...  # populated by scanner + rules
    reporter = Reporter()
    reporter.render(result)

Or using the convenience function::

    from actions_auditor.reporter import render_report
    render_report(result)
"""

from __future__ import annotations

import io
from typing import Dict, List, Optional, Sequence

from rich.columns import Columns
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from actions_auditor.models import Finding, Severity, ScanResult
from actions_auditor.remediation import get_remediation_or_default, RemediationAdvice


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Severity levels in display order (most severe first).
_SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Maximum characters to show for evidence snippets in the table.
_MAX_EVIDENCE_LEN: int = 80

# Maximum characters for description in the table.
_MAX_DESCRIPTION_LEN: int = 120

# Maximum characters for remediation recommendation in the detail panel.
_MAX_RECOMMENDATION_LEN: int = 300


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_len: int, suffix: str = "…") -> str:
    """Truncate *text* to at most *max_len* characters.

    Args:
        text: The string to truncate.
        max_len: Maximum allowed character count (including *suffix*).
        suffix: The suffix appended when truncation occurs.  Defaults to ``'…'``.

    Returns:
        The original string if it fits, otherwise a truncated version with
        *suffix* appended.
    """
    if len(text) <= max_len:
        return text
    return text[: max_len - len(suffix)] + suffix


def _severity_badge(severity: Severity) -> Text:
    """Return a Rich :class:`~rich.text.Text` badge for *severity*.

    Args:
        severity: The severity level to render.

    Returns:
        A styled :class:`~rich.text.Text` instance.
    """
    badge = Text(f" {severity.label.upper()} ", style=f"bold {severity.rich_style} on default")
    return badge


def _severity_label_text(severity: Severity) -> Text:
    """Return a styled severity label for use in table cells.

    Args:
        severity: The severity level.

    Returns:
        A :class:`~rich.text.Text` instance with the appropriate color.
    """
    return Text(severity.label, style=f"bold {severity.rich_style}")


def _format_location(finding: Finding) -> str:
    """Return an escaped location string for Rich markup.

    Args:
        finding: The finding whose location should be formatted.

    Returns:
        A plain string (safe for Rich markup escape).
    """
    return finding.location


def _build_findings_table(findings: List[Finding], severity: Severity) -> Table:
    """Build a Rich :class:`~rich.table.Table` for findings at one severity level.

    The table contains columns for: Rule ID, Location, Title, and Evidence.

    Args:
        findings: The list of findings to display (all at the same severity).
        severity: The severity level — used for header styling.

    Returns:
        A configured :class:`~rich.table.Table` instance.
    """
    style = severity.rich_style
    header_style = f"bold {style}"

    table = Table(
        box=box.ROUNDED,
        border_style=style,
        header_style=header_style,
        show_lines=True,
        expand=True,
    )

    table.add_column("Rule", style="bold", no_wrap=True, min_width=5, max_width=7)
    table.add_column("Location", no_wrap=False, min_width=20, max_width=45)
    table.add_column("Title", no_wrap=False, min_width=20)
    table.add_column("Evidence", no_wrap=False, style="dim", min_width=15)

    for finding in findings:
        location_text = Text(escape(_format_location(finding)), style="cyan")
        title_text = Text(escape(finding.title))
        evidence_str = _truncate(
            finding.evidence or "", _MAX_EVIDENCE_LEN
        )
        evidence_text = Text(escape(evidence_str), style="dim yellow")

        table.add_row(
            Text(finding.rule_id, style=f"bold {style}"),
            location_text,
            title_text,
            evidence_text,
        )

    return table


def _build_remediation_panel(finding: Finding) -> Panel:
    """Build a Rich :class:`~rich.panel.Panel` with remediation advice.

    Args:
        finding: The finding for which to display remediation.

    Returns:
        A :class:`~rich.panel.Panel` containing formatted remediation text.
    """
    advice = get_remediation_or_default(finding.effective_remediation_id)
    severity = finding.severity
    style = severity.rich_style

    content_lines: List[str] = []

    # Recommendation
    rec = _truncate(advice.recommendation, _MAX_RECOMMENDATION_LEN)
    content_lines.append(f"[bold]Recommendation:[/bold] {escape(rec)}")

    # References (up to 3 to keep output concise)
    if advice.references:
        content_lines.append("")
        content_lines.append("[bold]References:[/bold]")
        for ref in advice.references[:3]:
            content_lines.append(f"  [link={ref}]{escape(ref)}[/link]")
        if len(advice.references) > 3:
            extra = len(advice.references) - 3
            content_lines.append(f"  [dim]… and {extra} more[/dim]")

    content = "\n".join(content_lines)

    return Panel(
        content,
        title=f"[bold {style}]Remediation: {escape(finding.rule_id)}[/bold {style}]",
        border_style=style,
        padding=(0, 1),
        expand=True,
    )


def _build_summary_panel(
    result: ScanResult,
    show_file_list: bool = False,
) -> Panel:
    """Build a Rich :class:`~rich.panel.Panel` summarising the scan.

    Args:
        result: The completed :class:`~actions_auditor.models.ScanResult`.
        show_file_list: When ``True``, the panel also lists all scanned files.

    Returns:
        A :class:`~rich.panel.Panel` containing the scan summary.
    """
    counts = result.severity_counts()
    total = result.total_findings
    file_count = len(result.scanned_files)

    lines: List[str] = [
        f"[bold]Files scanned:[/bold] {file_count}",
        f"[bold]Total findings:[/bold] {total}",
        "",
        "[bold]Findings by severity:[/bold]",
    ]

    for sev in _SEVERITY_ORDER:
        count = counts[sev]
        style = sev.rich_style
        emoji = sev.rich_emoji
        count_str = str(count) if count > 0 else "[dim]0[/dim]"
        lines.append(
            f"  {emoji}  [{style}]{sev.label:<10}[/{style}]  {count_str}"
        )

    if show_file_list and result.scanned_files:
        lines.append("")
        lines.append("[bold]Scanned files:[/bold]")
        for p in result.scanned_files:
            lines.append(f"  [dim]{escape(str(p))}[/dim]")

    if total == 0:
        status_line = "\n[bold green]:white_check_mark:  No security findings detected.[/bold green]"
    else:
        status_line = (
            f"\n[bold red]:cross_mark:  {total} finding(s) detected. "
            "Review and remediate before merging.[/bold red]"
        )
    lines.append(status_line)

    border_color = "red" if total > 0 else "green"
    return Panel(
        "\n".join(lines),
        title="[bold]Scan Summary[/bold]",
        border_style=border_color,
        padding=(0, 1),
        expand=True,
    )


def _build_detail_panel(finding: Finding) -> Panel:
    """Build a Rich :class:`~rich.panel.Panel` with full finding detail.

    Includes the description and any contextual metadata.

    Args:
        finding: The finding to detail.

    Returns:
        A :class:`~rich.panel.Panel` with finding details.
    """
    severity = finding.severity
    style = severity.rich_style

    lines: List[str] = []

    # Description
    lines.append(f"[bold]Description:[/bold] {escape(finding.description)}")

    # Metadata
    if finding.job_name:
        lines.append(f"[bold]Job:[/bold] {escape(finding.job_name)}")
    if finding.step_name:
        lines.append(f"[bold]Step:[/bold] {escape(finding.step_name)}")
    if finding.line_number is not None:
        lines.append(f"[bold]Line:[/bold] {finding.line_number}")
    if finding.evidence:
        lines.append(
            f"[bold]Evidence:[/bold] [yellow]{escape(finding.evidence)}[/yellow]"
        )

    title_text = (
        f"[bold {style}]{severity.rich_emoji}  "
        f"{escape(finding.rule_id)}: {escape(finding.title)}[/bold {style}]"
    )

    return Panel(
        "\n".join(lines),
        title=title_text,
        border_style=style,
        padding=(0, 1),
        expand=True,
    )


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------


class Reporter:
    """Renders a prioritized, color-coded security report using ``rich``.

    The reporter is configurable via constructor parameters to support
    different output modes (e.g., verbose detail, compact summary-only,
    CI-friendly no-colour output).

    Args:
        console: A :class:`~rich.console.Console` instance to write to.
            When ``None`` (the default), a new console is created that
            writes to ``stdout``.
        verbose: When ``True``, emit detailed per-finding panels with
            descriptions and remediation advice below each severity group.
            When ``False`` (the default), only the summary table is shown.
        show_remediation: When ``True``, attach a remediation advice panel
            below each finding's detail panel.  Only effective when
            *verbose* is also ``True``.
        show_file_list: When ``True``, include the list of scanned files in
            the summary panel.
        min_severity: Only report findings at or above this severity level.
            Defaults to :attr:`~actions_auditor.models.Severity.INFO` (all
            findings).
    """

    def __init__(
        self,
        console: Optional[Console] = None,
        verbose: bool = False,
        show_remediation: bool = True,
        show_file_list: bool = False,
        min_severity: Severity = Severity.INFO,
    ) -> None:
        """Initialise the reporter."""
        self._console = console if console is not None else Console()
        self._verbose = verbose
        self._show_remediation = show_remediation
        self._show_file_list = show_file_list
        self._min_severity = min_severity

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def render(self, result: ScanResult) -> None:
        """Render the complete scan report for *result* to the console.

        Findings are grouped by severity (most severe first).  When
        *verbose* is ``True``, detailed panels are shown for each finding.
        A summary panel is always printed at the end.

        Args:
            result: The :class:`~actions_auditor.models.ScanResult` to report.
        """
        self._print_header(result)

        filtered = self._filter_findings(result.sorted_findings())

        if not filtered:
            self._console.print()
            self._console.print(
                Panel(
                    "[bold green]:white_check_mark:  No findings to display at the current severity threshold.[/bold green]",
                    border_style="green",
                    padding=(0, 1),
                )
            )
        else:
            # Group findings by severity and render each group.
            for severity in _SEVERITY_ORDER:
                if severity < self._min_severity:
                    continue
                group = [f for f in filtered if f.severity is severity]
                if not group:
                    continue
                self._render_severity_group(severity, group)

        self._console.print()
        self._console.print(_build_summary_panel(result, show_file_list=self._show_file_list))

    def render_summary(self, result: ScanResult) -> None:
        """Render only the summary panel for *result*.

        Useful for compact output when detailed findings have already been
        displayed through another mechanism.

        Args:
            result: The :class:`~actions_auditor.models.ScanResult` to summarise.
        """
        self._console.print(
            _build_summary_panel(result, show_file_list=self._show_file_list)
        )

    def render_finding(self, finding: Finding) -> None:
        """Render a single finding as a detail panel.

        Args:
            finding: The :class:`~actions_auditor.models.Finding` to render.
        """
        self._console.print(_build_detail_panel(finding))
        if self._show_remediation:
            self._console.print(_build_remediation_panel(finding))

    # ------------------------------------------------------------------
    # Internal rendering helpers
    # ------------------------------------------------------------------

    def _print_header(self, result: ScanResult) -> None:
        """Print the report header rule and title.

        Args:
            result: The scan result (used for context in the header).
        """
        self._console.print()
        self._console.print(
            Rule(
                "[bold cyan] :shield: GitHub Actions Security Audit Report :shield: [/bold cyan]",
                style="cyan",
            )
        )
        self._console.print()

    def _render_severity_group(
        self, severity: Severity, findings: List[Finding]
    ) -> None:
        """Render all findings for a single severity level.

        Outputs a section heading and a summary table.  When *verbose* is
        ``True``, individual detail panels are also printed for each finding.

        Args:
            severity: The severity level being rendered.
            findings: The findings at this severity level.
        """
        style = severity.rich_style
        emoji = severity.rich_emoji
        count = len(findings)

        # Section divider
        self._console.print()
        self._console.print(
            Rule(
                f"[{style}]{emoji}  {severity.label} ({count} finding{'s' if count != 1 else ''})[/{style}]",
                style=style,
            )
        )
        self._console.print()

        # Summary table for this severity group
        table = _build_findings_table(findings, severity)
        self._console.print(table)

        # Verbose detail panels
        if self._verbose:
            for finding in findings:
                self._console.print()
                self._console.print(_build_detail_panel(finding))
                if self._show_remediation:
                    self._console.print(_build_remediation_panel(finding))

    def _filter_findings(
        self, findings: List[Finding]
    ) -> List[Finding]:
        """Filter *findings* to only those at or above :attr:`_min_severity`.

        Args:
            findings: The full list of findings to filter.

        Returns:
            A filtered (and still sorted) list of findings.
        """
        return [
            f for f in findings
            if f.severity >= self._min_severity
        ]


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def render_report(
    result: ScanResult,
    console: Optional[Console] = None,
    verbose: bool = False,
    show_remediation: bool = True,
    show_file_list: bool = False,
    min_severity: Severity = Severity.INFO,
) -> None:
    """Render a complete scan report to the terminal.

    This is a convenience wrapper around :class:`Reporter` for callers that
    do not need the full class interface.

    Args:
        result: The :class:`~actions_auditor.models.ScanResult` to report.
        console: Optional :class:`~rich.console.Console` to write to.
            Defaults to a new console writing to ``stdout``.
        verbose: When ``True``, emit detailed per-finding panels in addition
            to the summary table.
        show_remediation: When ``True`` and *verbose* is ``True``, attach
            remediation panels below each finding.
        show_file_list: When ``True``, include the scanned file list in the
            summary panel.
        min_severity: Minimum severity threshold; findings below this level
            are suppressed.  Defaults to :attr:`~Severity.INFO`.
    """
    reporter = Reporter(
        console=console,
        verbose=verbose,
        show_remediation=show_remediation,
        show_file_list=show_file_list,
        min_severity=min_severity,
    )
    reporter.render(result)


def render_summary(
    result: ScanResult,
    console: Optional[Console] = None,
    show_file_list: bool = False,
) -> None:
    """Render only the scan summary panel.

    Args:
        result: The :class:`~actions_auditor.models.ScanResult` to summarise.
        console: Optional :class:`~rich.console.Console` to write to.
        show_file_list: When ``True``, include scanned files in the panel.
    """
    reporter = Reporter(
        console=console,
        show_file_list=show_file_list,
    )
    reporter.render_summary(result)


def render_findings_table(
    findings: List[Finding],
    severity: Severity,
    console: Optional[Console] = None,
) -> None:
    """Render a findings table for the given *severity* group to the console.

    Args:
        findings: The list of findings to render (typically pre-filtered to
            a single severity level).
        severity: The severity level — determines the table border colour and
            header style.
        console: Optional :class:`~rich.console.Console` to write to.
    """
    _console = console if console is not None else Console()
    table = _build_findings_table(findings, severity)
    _console.print(table)


def report_to_string(
    result: ScanResult,
    verbose: bool = False,
    show_remediation: bool = True,
    show_file_list: bool = False,
    min_severity: Severity = Severity.INFO,
) -> str:
    """Render the report to a string rather than the terminal.

    Useful for testing or capturing output programmatically.  Rich markup
    and ANSI colour codes are stripped from the output.

    Args:
        result: The :class:`~actions_auditor.models.ScanResult` to report.
        verbose: Passed through to :class:`Reporter`.
        show_remediation: Passed through to :class:`Reporter`.
        show_file_list: Passed through to :class:`Reporter`.
        min_severity: Passed through to :class:`Reporter`.

    Returns:
        The rendered report as a plain string (no ANSI escape sequences).
    """
    string_io = io.StringIO()
    console = Console(
        file=string_io,
        no_color=True,
        highlight=False,
        markup=True,
        width=120,
    )
    reporter = Reporter(
        console=console,
        verbose=verbose,
        show_remediation=show_remediation,
        show_file_list=show_file_list,
        min_severity=min_severity,
    )
    reporter.render(result)
    return string_io.getvalue()
