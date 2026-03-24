"""Unit tests for the core data models defined in actions_auditor.models.

Covers:
- Severity enum ordering, labels, styles, and emojis
- Finding dataclass construction, validation, and derived properties
- ScanResult dataclass mutation helpers, query helpers, and exit code logic
"""

from __future__ import annotations

from pathlib import Path

import pytest

from actions_auditor.models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_finding(
    rule_id: str = "AA001",
    title: str = "Test finding",
    description: str = "A test finding.",
    severity: Severity = Severity.HIGH,
    file_path: Path = Path("workflow.yml"),
    line_number: int | None = None,
    job_name: str | None = None,
    step_name: str | None = None,
    evidence: str | None = None,
    remediation_id: str | None = None,
) -> Finding:
    """Convenience factory for Creating Finding instances in tests."""
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


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------


class TestSeverity:
    """Tests for the Severity enum."""

    def test_all_members_exist(self) -> None:
        """All expected severity levels are present."""
        names = {s.name for s in Severity}
        assert names == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_values_are_ordered(self) -> None:
        """Severity values increase with risk level."""
        assert Severity.INFO.value < Severity.LOW.value
        assert Severity.LOW.value < Severity.MEDIUM.value
        assert Severity.MEDIUM.value < Severity.HIGH.value
        assert Severity.HIGH.value < Severity.CRITICAL.value

    def test_comparison_operators(self) -> None:
        """Severity instances support rich comparison."""
        assert Severity.INFO < Severity.CRITICAL
        assert Severity.CRITICAL > Severity.LOW
        assert Severity.MEDIUM <= Severity.HIGH
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.HIGH >= Severity.HIGH

    def test_label_property(self) -> None:
        """label returns a title-cased string."""
        assert Severity.CRITICAL.label == "Critical"
        assert Severity.HIGH.label == "High"
        assert Severity.MEDIUM.label == "Medium"
        assert Severity.LOW.label == "Low"
        assert Severity.INFO.label == "Info"

    def test_rich_style_property_returns_string(self) -> None:
        """rich_style returns a non-empty string for every severity."""
        for sev in Severity:
            assert isinstance(sev.rich_style, str)
            assert len(sev.rich_style) > 0

    def test_rich_style_critical_is_bold_red(self) -> None:
        assert Severity.CRITICAL.rich_style == "bold red"

    def test_rich_emoji_property_returns_string(self) -> None:
        """rich_emoji returns a non-empty string for every severity."""
        for sev in Severity:
            assert isinstance(sev.rich_emoji, str)
            assert len(sev.rich_emoji) > 0

    def test_sorting(self) -> None:
        """Severity instances can be sorted correctly."""
        unordered = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH]
        result = sorted(unordered)
        assert result == [Severity.INFO, Severity.LOW, Severity.HIGH, Severity.CRITICAL]

    def test_comparison_with_non_severity_returns_not_implemented(self) -> None:
        """Comparing a Severity with a non-Severity returns NotImplemented."""
        # Python will raise TypeError when NotImplemented is returned from both sides
        with pytest.raises(TypeError):
            _ = Severity.HIGH < 42  # type: ignore[operator]


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_basic_construction(self) -> None:
        """A Finding can be created with required fields only."""
        f = _make_finding()
        assert f.rule_id == "AA001"
        assert f.title == "Test finding"
        assert f.severity is Severity.HIGH
        assert f.file_path == Path("workflow.yml")
        assert f.line_number is None
        assert f.job_name is None
        assert f.step_name is None
        assert f.evidence is None
        assert f.remediation_id is None

    def test_full_construction(self) -> None:
        """A Finding can be created with all optional fields."""
        f = _make_finding(
            line_number=42,
            job_name="build",
            step_name="checkout",
            evidence="uses: actions/checkout@v3",
            remediation_id="REMED-001",
        )
        assert f.line_number == 42
        assert f.job_name == "build"
        assert f.step_name == "checkout"
        assert f.evidence == "uses: actions/checkout@v3"
        assert f.remediation_id == "REMED-001"

    def test_frozen_immutability(self) -> None:
        """Finding instances are immutable."""
        f = _make_finding()
        with pytest.raises((AttributeError, TypeError)):
            f.rule_id = "CHANGED"  # type: ignore[misc]

    def test_invalid_severity_type_raises_type_error(self) -> None:
        """Passing a non-Severity severity raises TypeError."""
        with pytest.raises(TypeError, match="severity must be a Severity instance"):
            Finding(
                rule_id="AA001",
                title="x",
                description="y",
                severity="HIGH",  # type: ignore[arg-type]
                file_path=Path("f.yml"),
            )

    def test_invalid_file_path_type_raises_type_error(self) -> None:
        """Passing a string instead of Path for file_path raises TypeError."""
        with pytest.raises(TypeError, match="file_path must be a pathlib.Path instance"):
            Finding(
                rule_id="AA001",
                title="x",
                description="y",
                severity=Severity.HIGH,
                file_path="workflow.yml",  # type: ignore[arg-type]
            )

    def test_empty_rule_id_raises_value_error(self) -> None:
        """An empty rule_id raises ValueError."""
        with pytest.raises(ValueError, match="rule_id must not be empty"):
            Finding(
                rule_id="",
                title="x",
                description="y",
                severity=Severity.HIGH,
                file_path=Path("f.yml"),
            )

    def test_whitespace_only_rule_id_raises_value_error(self) -> None:
        """A whitespace-only rule_id raises ValueError."""
        with pytest.raises(ValueError, match="rule_id must not be empty"):
            Finding(
                rule_id="   ",
                title="x",
                description="y",
                severity=Severity.HIGH,
                file_path=Path("f.yml"),
            )

    def test_empty_title_raises_value_error(self) -> None:
        """An empty title raises ValueError."""
        with pytest.raises(ValueError, match="title must not be empty"):
            Finding(
                rule_id="AA001",
                title="",
                description="y",
                severity=Severity.HIGH,
                file_path=Path("f.yml"),
            )

    def test_zero_line_number_raises_value_error(self) -> None:
        """A line_number of 0 raises ValueError."""
        with pytest.raises(ValueError, match="line_number must be a positive integer"):
            _make_finding(line_number=0)

    def test_negative_line_number_raises_value_error(self) -> None:
        """A negative line_number raises ValueError."""
        with pytest.raises(ValueError, match="line_number must be a positive integer"):
            _make_finding(line_number=-5)

    def test_valid_line_number_does_not_raise(self) -> None:
        """A positive line_number is accepted."""
        f = _make_finding(line_number=1)
        assert f.line_number == 1

    def test_effective_remediation_id_falls_back_to_rule_id(self) -> None:
        """effective_remediation_id returns rule_id when remediation_id is None."""
        f = _make_finding(rule_id="AA001", remediation_id=None)
        assert f.effective_remediation_id == "AA001"

    def test_effective_remediation_id_uses_remediation_id_when_set(self) -> None:
        """effective_remediation_id returns remediation_id when it is set."""
        f = _make_finding(rule_id="AA001", remediation_id="REMED-XYZ")
        assert f.effective_remediation_id == "REMED-XYZ"

    def test_location_with_no_optional_fields(self) -> None:
        """location returns just the filename when no optional fields are set."""
        f = _make_finding(file_path=Path("my_workflow.yml"))
        assert f.location == "my_workflow.yml"

    def test_location_with_line_number(self) -> None:
        """location includes line number when set."""
        f = _make_finding(file_path=Path("ci.yml"), line_number=15)
        assert f.location == "ci.yml:15"

    def test_location_with_job_only(self) -> None:
        """location includes job context when only job_name is set."""
        f = _make_finding(file_path=Path("ci.yml"), job_name="build")
        assert f.location == "ci.yml (job: build)"

    def test_location_with_job_and_step(self) -> None:
        """location includes both job and step context."""
        f = _make_finding(
            file_path=Path("ci.yml"),
            line_number=42,
            job_name="build",
            step_name="checkout",
        )
        assert f.location == "ci.yml:42 (job: build, step: checkout)"

    def test_location_with_step_only(self) -> None:
        """location includes step context when only step_name is set."""
        f = _make_finding(file_path=Path("ci.yml"), step_name="run tests")
        assert f.location == "ci.yml (step: run tests)"

    def test_str_representation(self) -> None:
        """__str__ contains rule_id, severity label, and title."""
        f = _make_finding(rule_id="AA002", title="Unpinned action", severity=Severity.HIGH)
        s = str(f)
        assert "AA002" in s
        assert "High" in s
        assert "Unpinned action" in s

    def test_hashable_can_be_used_in_set(self) -> None:
        """Finding is frozen/hashable and can be added to a set."""
        f1 = _make_finding()
        f2 = _make_finding()
        s = {f1, f2}
        assert len(s) == 1  # identical instances are equal

    def test_equality(self) -> None:
        """Two Findings with identical field values are equal."""
        f1 = _make_finding(line_number=5)
        f2 = _make_finding(line_number=5)
        assert f1 == f2

    def test_inequality(self) -> None:
        """Two Findings with different field values are not equal."""
        f1 = _make_finding(line_number=5)
        f2 = _make_finding(line_number=10)
        assert f1 != f2


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------


class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_default_construction(self) -> None:
        """A ScanResult starts with empty lists."""
        result = ScanResult()
        assert result.scanned_files == []
        assert result.findings == []

    def test_add_finding(self) -> None:
        """add_finding appends a single finding."""
        result = ScanResult()
        f = _make_finding()
        result.add_finding(f)
        assert len(result.findings) == 1
        assert result.findings[0] is f

    def test_add_finding_invalid_type_raises_type_error(self) -> None:
        """add_finding raises TypeError for non-Finding objects."""
        result = ScanResult()
        with pytest.raises(TypeError, match="Expected a Finding instance"):
            result.add_finding("not a finding")  # type: ignore[arg-type]

    def test_add_findings_multiple(self) -> None:
        """add_findings appends multiple findings."""
        result = ScanResult()
        findings = [_make_finding(rule_id=f"AA00{i}") for i in range(3)]
        result.add_findings(findings)
        assert len(result.findings) == 3

    def test_add_findings_with_invalid_element_raises_type_error(self) -> None:
        """add_findings raises TypeError if any element is not a Finding."""
        result = ScanResult()
        with pytest.raises(TypeError):
            result.add_findings([_make_finding(), "bad"])  # type: ignore[list-item]

    def test_add_scanned_file(self) -> None:
        """add_scanned_file appends a Path to scanned_files."""
        result = ScanResult()
        p = Path(".github/workflows/ci.yml")
        result.add_scanned_file(p)
        assert p in result.scanned_files

    def test_add_scanned_file_invalid_type_raises_type_error(self) -> None:
        """add_scanned_file raises TypeError for non-Path objects."""
        result = ScanResult()
        with pytest.raises(TypeError, match="Expected a pathlib.Path instance"):
            result.add_scanned_file("not/a/path")  # type: ignore[arg-type]

    def test_total_findings_empty(self) -> None:
        """total_findings is 0 for a fresh ScanResult."""
        assert ScanResult().total_findings == 0

    def test_total_findings_after_adding(self) -> None:
        """total_findings reflects the number of added findings."""
        result = ScanResult()
        result.add_findings([_make_finding() for _ in range(5)])
        assert result.total_findings == 5

    def test_has_findings_false_when_empty(self) -> None:
        """has_findings is False when there are no findings."""
        assert ScanResult().has_findings is False

    def test_has_findings_true_when_populated(self) -> None:
        """has_findings is True after adding at least one finding."""
        result = ScanResult()
        result.add_finding(_make_finding())
        assert result.has_findings is True

    def test_exit_code_zero_when_no_findings(self) -> None:
        """exit_code is 0 when there are no findings."""
        assert ScanResult().exit_code == 0

    def test_exit_code_one_when_findings_present(self) -> None:
        """exit_code is 1 when there are findings."""
        result = ScanResult()
        result.add_finding(_make_finding())
        assert result.exit_code == 1

    def test_findings_by_severity_filters_correctly(self) -> None:
        """findings_by_severity returns only findings at that level."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.HIGH))
        result.add_finding(_make_finding(severity=Severity.LOW))
        result.add_finding(_make_finding(severity=Severity.CRITICAL))

        high_findings = result.findings_by_severity(Severity.HIGH)
        assert len(high_findings) == 1
        assert all(f.severity is Severity.HIGH for f in high_findings)

    def test_findings_by_severity_empty_result(self) -> None:
        """findings_by_severity returns an empty list when no match."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.HIGH))
        assert result.findings_by_severity(Severity.CRITICAL) == []

    def test_findings_for_file_filters_correctly(self) -> None:
        """findings_for_file returns only findings for the given file."""
        p1 = Path("a.yml")
        p2 = Path("b.yml")
        result = ScanResult()
        result.add_finding(_make_finding(file_path=p1))
        result.add_finding(_make_finding(file_path=p2))
        result.add_finding(_make_finding(file_path=p1))

        assert len(result.findings_for_file(p1)) == 2
        assert len(result.findings_for_file(p2)) == 1

    def test_sorted_findings_descending(self) -> None:
        """sorted_findings returns findings from CRITICAL to INFO by default."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.LOW))
        result.add_finding(_make_finding(severity=Severity.CRITICAL))
        result.add_finding(_make_finding(severity=Severity.MEDIUM))

        sorted_f = result.sorted_findings()
        assert sorted_f[0].severity is Severity.CRITICAL
        assert sorted_f[-1].severity is Severity.LOW

    def test_sorted_findings_ascending(self) -> None:
        """sorted_findings(descending=False) returns findings from INFO to CRITICAL."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.HIGH))
        result.add_finding(_make_finding(severity=Severity.INFO))

        sorted_f = result.sorted_findings(descending=False)
        assert sorted_f[0].severity is Severity.INFO
        assert sorted_f[-1].severity is Severity.HIGH

    def test_severity_counts_all_keys_present(self) -> None:
        """severity_counts always returns a key for every Severity level."""
        result = ScanResult()
        counts = result.severity_counts()
        assert set(counts.keys()) == set(Severity)

    def test_severity_counts_zero_when_empty(self) -> None:
        """All severity counts are 0 for an empty ScanResult."""
        result = ScanResult()
        for count in result.severity_counts().values():
            assert count == 0

    def test_severity_counts_after_adding(self) -> None:
        """severity_counts correctly reflects added findings."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.HIGH))
        result.add_finding(_make_finding(severity=Severity.HIGH))
        result.add_finding(_make_finding(severity=Severity.CRITICAL))

        counts = result.severity_counts()
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.MEDIUM] == 0

    def test_iter_findings_by_severity_order(self) -> None:
        """iter_findings_by_severity yields findings in descending severity order."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.INFO))
        result.add_finding(_make_finding(severity=Severity.CRITICAL))
        result.add_finding(_make_finding(severity=Severity.MEDIUM))

        severities = [f.severity for f in result.iter_findings_by_severity()]
        assert severities == sorted(severities, reverse=True)

    def test_str_representation(self) -> None:
        """__str__ contains file count and finding count."""
        result = ScanResult(
            scanned_files=[Path("a.yml"), Path("b.yml")],
        )
        result.add_finding(_make_finding())
        s = str(result)
        assert "2" in s
        assert "1" in s

    def test_repr_representation(self) -> None:
        """__repr__ contains severity counts."""
        result = ScanResult()
        result.add_finding(_make_finding(severity=Severity.CRITICAL))
        r = repr(result)
        assert "Critical=1" in r
        assert "ScanResult" in r

    def test_independent_default_lists(self) -> None:
        """Two ScanResult instances do not share default list objects."""
        r1 = ScanResult()
        r2 = ScanResult()
        r1.add_finding(_make_finding())
        assert len(r2.findings) == 0
