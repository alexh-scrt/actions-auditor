"""Core data models for actions_auditor.

This module defines the foundational types used throughout the tool:

- :class:`Severity`: An enumeration of risk levels (CRITICAL, HIGH, MEDIUM, LOW, INFO).
- :class:`Finding`: A dataclass representing a single detected security issue.
- :class:`ScanResult`: A dataclass aggregating all findings from a scan run.

All other modules (rules, reporter, cli) depend on these types.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence


class Severity(enum.Enum):
    """Enumeration of finding severity levels, ordered from most to least severe.

    Attributes:
        CRITICAL: Immediately exploitable, direct path to credential/secret exfiltration
            or full repository compromise.
        HIGH: Significant misconfiguration that substantially raises the attack surface
            or can lead to supply-chain compromise.
        MEDIUM: Noteworthy issue that violates security best practices and may be
            exploitable under specific conditions.
        LOW: Minor deviation from recommended security posture; low direct risk.
        INFO: Informational observation; not a vulnerability, but worth noting.
    """

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def label(self) -> str:
        """Return the human-readable label for this severity level.

        Returns:
            A title-cased string such as ``'Critical'`` or ``'High'``.
        """
        return self.name.capitalize()

    @property
    def rich_style(self) -> str:
        """Return a Rich markup style string suitable for colored terminal output.

        Returns:
            A Rich style string, e.g. ``'bold red'`` for CRITICAL findings.
        """
        styles: Dict["Severity", str] = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim white",
        }
        return styles[self]

    @property
    def rich_emoji(self) -> str:
        """Return a Rich-compatible emoji string representing the severity level.

        Returns:
            A Rich emoji markup string, e.g. ``':rotating_light:'`` for CRITICAL.
        """
        emojis: Dict["Severity", str] = {
            Severity.CRITICAL: ":rotating_light:",
            Severity.HIGH: ":red_circle:",
            Severity.MEDIUM: ":yellow_circle:",
            Severity.LOW: ":blue_circle:",
            Severity.INFO: ":white_circle:",
        }
        return emojis[self]

    def __lt__(self, other: object) -> bool:
        """Support comparison so severities can be sorted from highest to lowest."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: object) -> bool:
        """Support less-than-or-equal comparison."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other: object) -> bool:
        """Support greater-than comparison."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other: object) -> bool:
        """Support greater-than-or-equal comparison."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value >= other.value


@dataclass(frozen=True)
class Finding:
    """Represents a single security finding detected in a workflow file.

    Instances are immutable (``frozen=True``) so they can be stored in sets
    and used as dictionary keys if needed.

    Attributes:
        rule_id: A short, unique identifier for the rule that produced this
            finding, e.g. ``'AA001'``.
        title: A concise, human-readable summary of the issue.
        description: A detailed explanation of why this is a security concern.
        severity: The :class:`Severity` level assigned to this finding.
        file_path: The :class:`~pathlib.Path` to the workflow file where the
            issue was found.
        line_number: The 1-based line number within *file_path* where the
            issue was detected, or ``None`` if a precise line cannot be
            determined.
        job_name: The name of the GitHub Actions job containing the finding,
            or ``None`` if not applicable (e.g., for top-level workflow issues).
        step_name: The name or index of the step within *job_name* where the
            issue was detected, or ``None`` if not applicable.
        evidence: A short snippet of the offending YAML content, or ``None``
            if no specific snippet is available.
        remediation_id: The key used to look up remediation guidance in
            :mod:`actions_auditor.remediation`, or ``None`` if the rule does
            not have dedicated remediation text (defaults to *rule_id*).
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: Path
    line_number: Optional[int] = None
    job_name: Optional[str] = None
    step_name: Optional[str] = None
    evidence: Optional[str] = None
    remediation_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate field values after initialisation.

        Raises:
            TypeError: If *severity* is not a :class:`Severity` instance.
            TypeError: If *file_path* is not a :class:`~pathlib.Path` instance.
            ValueError: If *rule_id* or *title* is empty.
            ValueError: If *line_number* is provided but is not a positive integer.
        """
        if not isinstance(self.severity, Severity):
            raise TypeError(
                f"severity must be a Severity instance, got {type(self.severity).__name__}"
            )
        if not isinstance(self.file_path, Path):
            raise TypeError(
                f"file_path must be a pathlib.Path instance, got {type(self.file_path).__name__}"
            )
        if not self.rule_id or not self.rule_id.strip():
            raise ValueError("rule_id must not be empty")
        if not self.title or not self.title.strip():
            raise ValueError("title must not be empty")
        if self.line_number is not None and self.line_number < 1:
            raise ValueError(
                f"line_number must be a positive integer, got {self.line_number}"
            )

    @property
    def effective_remediation_id(self) -> str:
        """Return the remediation lookup key, falling back to *rule_id*.

        Returns:
            The value of :attr:`remediation_id` if set, otherwise :attr:`rule_id`.
        """
        return self.remediation_id if self.remediation_id is not None else self.rule_id

    @property
    def location(self) -> str:
        """Return a concise human-readable location string for display in reports.

        Examples::

            >>> # With job, step, and line
            'workflow.yml:42 (job: build / step: checkout)'
            >>> # With only line
            'workflow.yml:10'
            >>> # No line info
            'workflow.yml'

        Returns:
            A formatted location string.
        """
        parts: List[str] = [self.file_path.name]

        if self.line_number is not None:
            parts[-1] = f"{self.file_path.name}:{self.line_number}"

        context_parts: List[str] = []
        if self.job_name:
            context_parts.append(f"job: {self.job_name}")
        if self.step_name:
            context_parts.append(f"step: {self.step_name}")

        if context_parts:
            parts.append(f"({', '.join(context_parts)})")

        return " ".join(parts)

    def __str__(self) -> str:
        """Return a compact string representation of this finding."""
        return (
            f"[{self.severity.label}] {self.rule_id}: {self.title} "
            f"@ {self.location}"
        )


@dataclass
class ScanResult:
    """Aggregates all findings produced by a complete scan run.

    Attributes:
        scanned_files: The list of workflow file paths that were examined.
        findings: The list of :class:`Finding` objects detected across all
            scanned files.
    """

    scanned_files: List[Path] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Append a single :class:`Finding` to the result.

        Args:
            finding: The finding to add.

        Raises:
            TypeError: If *finding* is not a :class:`Finding` instance.
        """
        if not isinstance(finding, Finding):
            raise TypeError(
                f"Expected a Finding instance, got {type(finding).__name__}"
            )
        self.findings.append(finding)

    def add_findings(self, findings: Sequence[Finding]) -> None:
        """Append multiple :class:`Finding` objects to the result.

        Args:
            findings: An iterable of :class:`Finding` objects to add.

        Raises:
            TypeError: If any element in *findings* is not a :class:`Finding`.
        """
        for finding in findings:
            self.add_finding(finding)

    def add_scanned_file(self, path: Path) -> None:
        """Record that *path* was included in the scan.

        Args:
            path: The workflow file path that was scanned.

        Raises:
            TypeError: If *path* is not a :class:`~pathlib.Path` instance.
        """
        if not isinstance(path, Path):
            raise TypeError(
                f"Expected a pathlib.Path instance, got {type(path).__name__}"
            )
        self.scanned_files.append(path)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Return the total number of findings.

        Returns:
            An integer count of all findings in this result.
        """
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        """Return ``True`` if there is at least one finding.

        Returns:
            ``True`` when :attr:`findings` is non-empty, ``False`` otherwise.
        """
        return bool(self.findings)

    def findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Return findings filtered to a specific severity level.

        Args:
            severity: The :class:`Severity` to filter by.

        Returns:
            A list of :class:`Finding` objects whose :attr:`~Finding.severity`
            matches *severity*.
        """
        return [f for f in self.findings if f.severity is severity]

    def findings_for_file(self, path: Path) -> List[Finding]:
        """Return findings associated with a specific workflow file.

        Args:
            path: The workflow file path to filter by.

        Returns:
            A list of :class:`Finding` objects whose
            :attr:`~Finding.file_path` equals *path*.
        """
        return [f for f in self.findings if f.file_path == path]

    def sorted_findings(self, descending: bool = True) -> List[Finding]:
        """Return findings sorted by severity.

        Args:
            descending: When ``True`` (the default), findings are ordered from
                most severe (:attr:`~Severity.CRITICAL`) to least severe
                (:attr:`~Severity.INFO`).  Pass ``False`` to reverse.

        Returns:
            A new sorted list of :class:`Finding` objects.
        """
        return sorted(
            self.findings,
            key=lambda f: f.severity.value,
            reverse=descending,
        )

    def severity_counts(self) -> Dict[Severity, int]:
        """Return a mapping of each :class:`Severity` level to its finding count.

        Every severity level is present in the returned mapping, even if its
        count is zero.

        Returns:
            A dict mapping :class:`Severity` → ``int``.
        """
        counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def iter_findings_by_severity(self) -> Iterator[Finding]:
        """Yield findings ordered from most to least severe.

        Yields:
            :class:`Finding` instances in descending severity order.
        """
        yield from self.sorted_findings(descending=True)

    @property
    def exit_code(self) -> int:
        """Return the appropriate process exit code for this scan result.

        Returns:
            ``1`` if any findings exist (enabling CI/CD pipeline gating),
            ``0`` if no findings were detected.
        """
        return 1 if self.has_findings else 0

    def __str__(self) -> str:
        """Return a brief summary of this scan result."""
        return (
            f"ScanResult: {len(self.scanned_files)} file(s) scanned, "
            f"{self.total_findings} finding(s) detected"
        )

    def __repr__(self) -> str:
        """Return a detailed representation of this scan result."""
        counts = self.severity_counts()
        count_str = ", ".join(
            f"{sev.label}={counts[sev]}"
            for sev in sorted(Severity, reverse=True)
        )
        return (
            f"ScanResult(files={len(self.scanned_files)}, "
            f"findings={self.total_findings}, {count_str})"
        )
