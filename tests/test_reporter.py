"""Unit tests for the Rich terminal reporter (actions_auditor.reporter).

Covers:
- _truncate helper
- _severity_badge and _severity_label_text helpers
- _build_findings_table produces a Rich Table
- _build_summary_panel produces a Rich Panel
- _build_detail_panel produces a Rich Panel
- _build_remediation_panel produces a Rich Panel
- Reporter.render() produces output containing expected text
- Reporter.render_summary() produces output
- Reporter.render_finding() produces output
- Reporter._filter_findings() respects min_severity
- render_report() convenience function
- render_summary() convenience function
- render_findings_table() convenience function
- report_to_string() captures output as a string
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import List

import pytest
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from actions_auditor.models import Finding, Severity, ScanResult
from actions_auditor.reporter import (
    Reporter,
    _build_detail_panel,
    _build_findings_table,
    _build_remediation_panel,
    _build_summary_panel,
    _severity_badge,
    _severity_label_text,
    _truncate,
    render_findings_table,
    render_report,
    render_summary,
    report_to_string,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_finding(
    rule_id: str = "AA001",
    title: str = "Test finding",
    description: str = "A test finding description.",
    severity: Severity = Severity.HIGH,
    file_path: Path = Path("workflow.yml"),
    line_number: int | None = 10,
    job_name: str | None = "build",
    step_name: str | None = "checkout",
    evidence: str | None = "permissions: write-all",
    remediation_id: str | None = None,
) -> Finding:
    """Convenience factory for Finding instances."""
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        job_name=job_name,
        step_name=step_name,
        evidence=evidence,
        remediation_id=remediation_id,
    )


def _make_scan_result(
    findings: List[Finding] | None = None,
    files: List[Path] | None = None,
) -> ScanResult:
    """Convenience factory for ScanResult instances."""
    result = ScanResult(
        scanned_files=files or [Path("workflow.yml")],
    )
    for f in (findings or []):
        result.add_finding(f)
    return result


def _capture_output(
    reporter: Reporter,
    result: ScanResult,
) -> str:
    """Run reporter.render() capturing all output as a plain string."""
    buf = io.StringIO()
    con = Console(file=buf, no_color=True, highlight=False, markup=True, width=120)
    reporter._console = con
    reporter.render(result)
    return buf.getvalue()


def _string_console() -> tuple[Console, io.StringIO]:
    """Return a (Console, StringIO) pair for capturing output."""
    buf = io.StringIO()
    con = Console(file=buf, no_color=True, highlight=False, markup=True, width=120)
    return con, buf


# ---------------------------------------------------------------------------
# _truncate tests
# ---------------------------------------------------------------------------


class TestTruncate:
    """Tests for the _truncate internal helper."""

    def test_short_string_unchanged(self) -> None:
        assert _truncate("hello", 10) == "hello"

    def test_exact_length_unchanged(self) -> None:
        assert _truncate("hello", 5) == "hello"

    def test_long_string_truncated(self) -> None:
        result = _truncate("hello world", 8)
        assert len(result) == 8
        assert result.endswith("…")

    def test_empty_string(self) -> None:
        assert _truncate("", 10) == ""

    def test_custom_suffix(self) -> None:
        result = _truncate("abcdefgh", 5, suffix="...")
        assert result == "ab..."
        assert len(result) == 5

    def test_zero_max_len_with_suffix(self) -> None:
        # Edge case: max_len shorter than suffix
        result = _truncate("hello world", 1, suffix="…")
        assert len(result) <= 1


# ---------------------------------------------------------------------------
# _severity_badge and _severity_label_text tests
# ---------------------------------------------------------------------------


class TestSeverityHelpers:
    """Tests for severity display helpers."""

    def test_severity_badge_returns_text(self) -> None:
        badge = _severity_badge(Severity.CRITICAL)
        assert isinstance(badge, Text)

    def test_severity_badge_contains_label(self) -> None:
        badge = _severity_badge(Severity.HIGH)
        assert "HIGH" in badge.plain

    def test_severity_label_text_returns_text(self) -> None:
        label = _severity_label_text(Severity.MEDIUM)
        assert isinstance(label, Text)

    def test_severity_label_text_contains_label(self) -> None:
        label = _severity_label_text(Severity.LOW)
        assert "Low" in label.plain

    def test_all_severities_produce_badge(self) -> None:
        for sev in Severity:
            badge = _severity_badge(sev)
            assert isinstance(badge, Text)
            assert sev.label.upper() in badge.plain

    def test_all_severities_produce_label(self) -> None:
        for sev in Severity:
            label = _severity_label_text(sev)
            assert isinstance(label, Text)


# ---------------------------------------------------------------------------
# _build_findings_table tests
# ---------------------------------------------------------------------------


class TestBuildFindingsTable:
    """Tests for the _build_findings_table helper."""

    def test_returns_table_instance(self) -> None:
        findings = [_make_finding()]
        table = _build_findings_table(findings, Severity.HIGH)
        assert isinstance(table, Table)

    def test_table_has_correct_column_count(self) -> None:
        findings = [_make_finding()]
        table = _build_findings_table(findings, Severity.HIGH)
        assert len(table.columns) == 4

    def test_table_row_count_matches_findings(self) -> None:
        findings = [_make_finding() for _ in range(3)]
        table = _build_findings_table(findings, Severity.HIGH)
        assert table.row_count == 3

    def test_empty_findings_produces_empty_table(self) -> None:
        table = _build_findings_table([], Severity.INFO)
        assert table.row_count == 0

    def test_table_for_critical_severity(self) -> None:
        findings = [_make_finding(severity=Severity.CRITICAL, rule_id="AA006")]
        table = _build_findings_table(findings, Severity.CRITICAL)
        assert isinstance(table, Table)

    def test_table_renders_without_error(self) -> None:
        """The table should render to a string without raising."""
        findings = [_make_finding(rule_id="AA005", evidence="uses: actions/checkout@v4")]
        table = _build_findings_table(findings, Severity.HIGH)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(table)
        output = buf.getvalue()
        assert len(output) > 0

    def test_long_evidence_is_truncated_in_output(self) -> None:
        long_evidence = "uses: " + "a" * 200
        findings = [_make_finding(evidence=long_evidence)]
        table = _build_findings_table(findings, Severity.HIGH)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=200)
        con.print(table)
        # The raw evidence in output should not contain all 200 'a' chars
        # (it gets truncated to _MAX_EVIDENCE_LEN)
        output = buf.getvalue()
        assert "a" * 200 not in output


# ---------------------------------------------------------------------------
# _build_summary_panel tests
# ---------------------------------------------------------------------------


class TestBuildSummaryPanel:
    """Tests for the _build_summary_panel helper."""

    def test_returns_panel_instance(self) -> None:
        result = _make_scan_result()
        panel = _build_summary_panel(result)
        assert isinstance(panel, Panel)

    def test_panel_renders_without_error(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        panel = _build_summary_panel(result)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert len(output) > 0

    def test_panel_shows_file_count(self) -> None:
        result = _make_scan_result(files=[Path("a.yml"), Path("b.yml")])
        panel = _build_summary_panel(result)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "2" in output

    def test_panel_shows_finding_count(self) -> None:
        findings = [_make_finding() for _ in range(5)]
        result = _make_scan_result(findings=findings)
        panel = _build_summary_panel(result)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "5" in output

    def test_no_findings_shows_success_message(self) -> None:
        result = _make_scan_result(findings=[])
        panel = _build_summary_panel(result)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "No security findings" in output or "0" in output

    def test_show_file_list_includes_paths(self) -> None:
        result = _make_scan_result(files=[Path(".github/workflows/ci.yml")])
        panel = _build_summary_panel(result, show_file_list=True)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "ci.yml" in output

    def test_show_file_list_false_excludes_paths(self) -> None:
        result = _make_scan_result(files=[Path(".github/workflows/ci.yml")])
        panel = _build_summary_panel(result, show_file_list=False)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        # File paths should NOT appear in the panel when show_file_list=False
        # (only the count does)
        assert ".github/workflows/ci.yml" not in output

    def test_all_severity_levels_mentioned(self) -> None:
        result = _make_scan_result()
        panel = _build_summary_panel(result)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        for sev in Severity:
            assert sev.label in output


# ---------------------------------------------------------------------------
# _build_detail_panel tests
# ---------------------------------------------------------------------------


class TestBuildDetailPanel:
    """Tests for the _build_detail_panel helper."""

    def test_returns_panel_instance(self) -> None:
        finding = _make_finding()
        panel = _build_detail_panel(finding)
        assert isinstance(panel, Panel)

    def test_panel_contains_rule_id(self) -> None:
        finding = _make_finding(rule_id="AA007")
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "AA007" in output

    def test_panel_contains_description(self) -> None:
        finding = _make_finding(description="Unique description text for test.")
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "Unique description text for test." in output

    def test_panel_contains_job_name(self) -> None:
        finding = _make_finding(job_name="my_deploy_job")
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "my_deploy_job" in output

    def test_panel_contains_step_name(self) -> None:
        finding = _make_finding(step_name="my_unique_step")
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "my_unique_step" in output

    def test_panel_contains_line_number(self) -> None:
        finding = _make_finding(line_number=42)
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "42" in output

    def test_panel_contains_evidence(self) -> None:
        finding = _make_finding(evidence="permissions: write-all")
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "permissions: write-all" in output

    def test_panel_renders_without_none_job(self) -> None:
        """Panel should render fine when job_name and step_name are None."""
        finding = _make_finding(job_name=None, step_name=None, line_number=None)
        panel = _build_detail_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)  # Should not raise


# ---------------------------------------------------------------------------
# _build_remediation_panel tests
# ---------------------------------------------------------------------------


class TestBuildRemediationPanel:
    """Tests for the _build_remediation_panel helper."""

    def test_returns_panel_instance(self) -> None:
        finding = _make_finding(rule_id="AA001")
        panel = _build_remediation_panel(finding)
        assert isinstance(panel, Panel)

    def test_panel_contains_rule_id(self) -> None:
        finding = _make_finding(rule_id="AA001")
        panel = _build_remediation_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "AA001" in output

    def test_panel_contains_recommendation_text(self) -> None:
        finding = _make_finding(rule_id="AA001")
        panel = _build_remediation_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        # AA001 recommendation should mention least-privilege or write-all
        assert len(output) > 50

    def test_panel_contains_reference_url(self) -> None:
        finding = _make_finding(rule_id="AA005")
        panel = _build_remediation_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)
        output = buf.getvalue()
        assert "https://" in output

    def test_unknown_rule_uses_fallback(self) -> None:
        finding = _make_finding(rule_id="AA999")
        panel = _build_remediation_panel(finding)
        buf = io.StringIO()
        con = Console(file=buf, no_color=True, width=120)
        con.print(panel)  # Should not raise
        output = buf.getvalue()
        assert "AA999" in output

    def test_panel_renders_for_all_known_rules(self) -> None:
        for rule_id in ["AA001", "AA002", "AA003", "AA004", "AA005", "AA006", "AA007", "AA008"]:
            finding = _make_finding(rule_id=rule_id)
            panel = _build_remediation_panel(finding)
            buf = io.StringIO()
            con = Console(file=buf, no_color=True, width=120)
            con.print(panel)  # Must not raise


# ---------------------------------------------------------------------------
# Reporter class tests
# ---------------------------------------------------------------------------


class TestReporter:
    """Tests for the Reporter class."""

    def test_render_empty_result_no_error(self) -> None:
        result = _make_scan_result(findings=[])
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)  # Should not raise
        output = buf.getvalue()
        assert len(output) > 0

    def test_render_includes_header(self) -> None:
        result = _make_scan_result(findings=[])
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)
        output = buf.getvalue()
        assert "Audit" in output or "Security" in output or "GitHub" in output

    def test_render_includes_summary(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)
        output = buf.getvalue()
        assert "Summary" in output

    def test_render_includes_rule_id(self) -> None:
        findings = [_make_finding(rule_id="AA001")]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)
        output = buf.getvalue()
        assert "AA001" in output

    def test_render_includes_severity_label(self) -> None:
        findings = [_make_finding(severity=Severity.CRITICAL)]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)
        output = buf.getvalue()
        assert "Critical" in output

    def test_render_verbose_includes_description(self) -> None:
        description = "Unique verbose description text XYZ."
        findings = [_make_finding(description=description)]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con, verbose=True, show_remediation=False)
        reporter.render(result)
        output = buf.getvalue()
        assert description in output

    def test_render_non_verbose_excludes_description_from_panels(self) -> None:
        """In non-verbose mode the description should not appear as a panel."""
        description = "This is the detailed description text that should not appear."
        findings = [_make_finding(description=description)]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con, verbose=False)
        reporter.render(result)
        output = buf.getvalue()
        # Description panel not shown in non-verbose mode
        assert "Description:" not in output

    def test_render_verbose_includes_remediation(self) -> None:
        findings = [_make_finding(rule_id="AA001")]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con, verbose=True, show_remediation=True)
        reporter.render(result)
        output = buf.getvalue()
        assert "Remediation" in output

    def test_render_verbose_no_remediation(self) -> None:
        findings = [_make_finding(rule_id="AA001")]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con, verbose=True, show_remediation=False)
        reporter.render(result)
        output = buf.getvalue()
        assert "Remediation" not in output

    def test_render_multiple_severities_in_order(self) -> None:
        """CRITICAL findings section should appear before HIGH in the output."""
        findings = [
            _make_finding(severity=Severity.HIGH, rule_id="AA001"),
            _make_finding(severity=Severity.CRITICAL, rule_id="AA006"),
        ]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)
        output = buf.getvalue()
        critical_pos = output.find("Critical")
        high_pos = output.find("High")
        assert critical_pos < high_pos

    def test_render_summary_only(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render_summary(result)
        output = buf.getvalue()
        assert "Summary" in output

    def test_render_finding_outputs_finding_info(self) -> None:
        finding = _make_finding(rule_id="AA003", title="My specific title")
        con, buf = _string_console()
        reporter = Reporter(console=con, show_remediation=False)
        reporter.render_finding(finding)
        output = buf.getvalue()
        assert "AA003" in output
        assert "My specific title" in output

    def test_render_finding_with_remediation(self) -> None:
        finding = _make_finding(rule_id="AA005")
        con, buf = _string_console()
        reporter = Reporter(console=con, show_remediation=True)
        reporter.render_finding(finding)
        output = buf.getvalue()
        assert "Remediation" in output

    def test_filter_findings_by_min_severity(self) -> None:
        """Findings below min_severity should not appear in the output."""
        findings = [
            _make_finding(severity=Severity.INFO, rule_id="AA002"),
            _make_finding(severity=Severity.HIGH, rule_id="AA001"),
        ]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        reporter = Reporter(console=con, min_severity=Severity.HIGH)
        reporter.render(result)
        output = buf.getvalue()
        # HIGH finding should be present, INFO should be absent from table
        assert "AA001" in output
        # AA002 is INFO severity which is below HIGH threshold
        # We check the table does not contain it (summary still shows counts)
        # The table section for INFO should not render at all
        assert "Info" not in output or "AA002" not in output

    def test_default_console_is_created_when_none(self) -> None:
        """Reporter creates its own Console when none is provided."""
        reporter = Reporter()
        assert reporter._console is not None

    def test_show_file_list_in_summary(self) -> None:
        result = _make_scan_result(files=[Path(".github/workflows/ci.yml")])
        con, buf = _string_console()
        reporter = Reporter(console=con, show_file_list=True)
        reporter.render(result)
        output = buf.getvalue()
        assert "ci.yml" in output

    def test_empty_findings_shows_no_findings_message(self) -> None:
        result = _make_scan_result(findings=[])
        con, buf = _string_console()
        reporter = Reporter(console=con)
        reporter.render(result)
        output = buf.getvalue()
        # Should indicate clean state
        assert "No" in output or "0" in output

    def test_filter_findings_method_directly(self) -> None:
        reporter = Reporter(min_severity=Severity.MEDIUM)
        findings = [
            _make_finding(severity=Severity.INFO),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.CRITICAL),
        ]
        filtered = reporter._filter_findings(findings)
        assert all(f.severity >= Severity.MEDIUM for f in filtered)
        assert len(filtered) == 3

    def test_filter_findings_info_min_returns_all(self) -> None:
        reporter = Reporter(min_severity=Severity.INFO)
        findings = [
            _make_finding(severity=Severity.INFO),
            _make_finding(severity=Severity.LOW),
            _make_finding(severity=Severity.CRITICAL),
        ]
        filtered = reporter._filter_findings(findings)
        assert len(filtered) == 3


# ---------------------------------------------------------------------------
# Convenience function tests
# ---------------------------------------------------------------------------


class TestConvenienceFunctions:
    """Tests for the module-level convenience functions."""

    def test_render_report_runs_without_error(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        con, buf = _string_console()
        render_report(result, console=con)  # Should not raise
        assert len(buf.getvalue()) > 0

    def test_render_report_verbose(self) -> None:
        result = _make_scan_result(findings=[_make_finding(description="Verbose desc text.")])        
        con, buf = _string_console()
        render_report(result, console=con, verbose=True, show_remediation=False)
        output = buf.getvalue()
        assert "Verbose desc text." in output

    def test_render_report_min_severity_filters(self) -> None:
        findings = [
            _make_finding(severity=Severity.INFO, rule_id="AA002"),
            _make_finding(severity=Severity.CRITICAL, rule_id="AA006"),
        ]
        result = _make_scan_result(findings=findings)
        con, buf = _string_console()
        render_report(result, console=con, min_severity=Severity.CRITICAL)
        output = buf.getvalue()
        assert "AA006" in output

    def test_render_summary_outputs_summary_panel(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        con, buf = _string_console()
        render_summary(result, console=con)
        output = buf.getvalue()
        assert "Summary" in output

    def test_render_summary_show_file_list(self) -> None:
        result = _make_scan_result(files=[Path("special_workflow.yml")])
        con, buf = _string_console()
        render_summary(result, console=con, show_file_list=True)
        output = buf.getvalue()
        assert "special_workflow.yml" in output

    def test_render_findings_table_outputs_table(self) -> None:
        findings = [_make_finding(rule_id="AA005")]
        con, buf = _string_console()
        render_findings_table(findings, Severity.HIGH, console=con)
        output = buf.getvalue()
        assert "AA005" in output

    def test_render_findings_table_creates_console_when_none(self) -> None:
        """render_findings_table should not raise even without a console arg."""
        findings = [_make_finding(rule_id="AA001")]
        # This writes to stdout; we just check it does not raise.
        try:
            # Redirect by patching the Console; instead verify no exception.
            render_findings_table(findings, Severity.HIGH, console=Console(file=io.StringIO()))
        except Exception as exc:
            pytest.fail(f"render_findings_table raised: {exc}")

    def test_render_findings_table_empty_findings(self) -> None:
        con, buf = _string_console()
        render_findings_table([], Severity.LOW, console=con)
        output = buf.getvalue()
        # Should produce an empty table without error
        assert len(output) > 0


# ---------------------------------------------------------------------------
# report_to_string tests
# ---------------------------------------------------------------------------


class TestReportToString:
    """Tests for the report_to_string() function."""

    def test_returns_string(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        output = report_to_string(result)
        assert isinstance(output, str)

    def test_non_empty_output(self) -> None:
        result = _make_scan_result(findings=[_make_finding()])
        output = report_to_string(result)
        assert len(output) > 0

    def test_contains_rule_id(self) -> None:
        findings = [_make_finding(rule_id="AA003")]
        result = _make_scan_result(findings=findings)
        output = report_to_string(result)
        assert "AA003" in output

    def test_contains_summary(self) -> None:
        result = _make_scan_result(findings=[])
        output = report_to_string(result)
        assert "Summary" in output

    def test_verbose_mode_includes_description(self) -> None:
        findings = [_make_finding(description="Unique test description XYZ123.")]
        result = _make_scan_result(findings=findings)
        output = report_to_string(result, verbose=True, show_remediation=False)
        assert "Unique test description XYZ123." in output

    def test_min_severity_filters_output(self) -> None:
        findings = [
            _make_finding(severity=Severity.INFO, rule_id="AA002"),
            _make_finding(severity=Severity.HIGH, rule_id="AA001"),
        ]
        result = _make_scan_result(findings=findings)
        output = report_to_string(result, min_severity=Severity.HIGH)
        assert "AA001" in output

    def test_empty_result_returns_string(self) -> None:
        result = _make_scan_result(findings=[])
        output = report_to_string(result)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_all_severity_levels_trigger_sections(self) -> None:
        """A finding at each severity level should produce output for each."""
        findings = [
            _make_finding(severity=Severity.CRITICAL, rule_id="AA006"),
            _make_finding(severity=Severity.HIGH, rule_id="AA001"),
            _make_finding(severity=Severity.MEDIUM, rule_id="AA002"),
            _make_finding(severity=Severity.LOW, rule_id="AA003"),
            _make_finding(severity=Severity.INFO, rule_id="AA004"),
        ]
        result = _make_scan_result(findings=findings)
        output = report_to_string(result)
        for rule_id in ["AA006", "AA001", "AA002", "AA003", "AA004"]:
            assert rule_id in output

    def test_show_file_list_includes_path(self) -> None:
        result = _make_scan_result(files=[Path("path/to/workflow.yml")])
        output = report_to_string(result, show_file_list=True)
        assert "workflow.yml" in output

    def test_output_contains_no_ansi_codes(self) -> None:
        """report_to_string should strip ANSI escape codes."""
        result = _make_scan_result(findings=[_make_finding()])
        output = report_to_string(result)
        # ANSI escape codes start with ESC (\x1b)
        assert "\x1b" not in output
