"""Workflow file scanner for actions_auditor.

This module is responsible for discovering GitHub Actions workflow YAML files
within a target directory and loading (parsing) them into Python data structures
ready for rule evaluation.

Key responsibilities:

- Recursively discover ``.yml`` and ``.yaml`` files under a given root directory
  (defaulting to the standard ``.github/workflows/`` path).
- Parse each YAML file safely, capturing and reporting parse errors without
  aborting the entire scan.
- Return structured :class:`WorkflowFile` objects that bundle the file path,
  raw text content, and parsed YAML data together so that rules can reference
  both the structured data and the original source for line-number extraction.

Typical usage::

    from pathlib import Path
    from actions_auditor.scanner import Scanner

    scanner = Scanner(Path("."))
    workflow_files = scanner.scan()
    for wf in workflow_files:
        print(wf.path, wf.data)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import yaml

logger = logging.getLogger(__name__)

# The conventional location for GitHub Actions workflow files.
_DEFAULT_WORKFLOWS_SUBDIR = Path(".github") / "workflows"

# Supported YAML file extensions.
_YAML_EXTENSIONS: Tuple[str, ...] = (".yml", ".yaml")


@dataclass
class WorkflowFile:
    """Represents a loaded and parsed GitHub Actions workflow file.

    Attributes:
        path: Absolute or relative path to the ``.yml``/``.yaml`` file.
        raw_content: The raw text content read from disk.
        data: The parsed YAML as a Python object (typically a ``dict``).
            ``None`` if the file could not be parsed.
        parse_error: A human-readable description of the YAML parse error,
            or ``None`` if parsing succeeded.
    """

    path: Path
    raw_content: str
    data: Optional[Any] = field(default=None)
    parse_error: Optional[str] = field(default=None)

    @property
    def is_valid(self) -> bool:
        """Return ``True`` if the file was parsed successfully.

        Returns:
            ``True`` when :attr:`parse_error` is ``None`` and :attr:`data`
            is not ``None``.
        """
        return self.parse_error is None and self.data is not None

    @property
    def jobs(self) -> Dict[str, Any]:
        """Return the ``jobs`` mapping from the parsed workflow data.

        Returns:
            The ``jobs`` dictionary, or an empty dict if absent or unparseable.
        """
        if not self.is_valid or not isinstance(self.data, dict):
            return {}
        return self.data.get("jobs") or {}

    @property
    def triggers(self) -> Any:
        """Return the ``on`` (trigger) section from the parsed workflow data.

        Returns:
            The value of the ``on`` key, or ``None`` if absent.
        """
        if not self.is_valid or not isinstance(self.data, dict):
            return None
        # PyYAML parses ``on`` as the boolean ``True`` in some edge cases;
        # we normalise this here.
        value = self.data.get("on") or self.data.get(True)
        return value

    @property
    def permissions(self) -> Any:
        """Return the top-level ``permissions`` section, or ``None``.

        Returns:
            The value of the top-level ``permissions`` key, or ``None``.
        """
        if not self.is_valid or not isinstance(self.data, dict):
            return None
        return self.data.get("permissions")

    @property
    def env(self) -> Dict[str, Any]:
        """Return the top-level ``env`` mapping, or an empty dict.

        Returns:
            The top-level ``env`` dictionary, or ``{}``.
        """
        if not self.is_valid or not isinstance(self.data, dict):
            return {}
        return self.data.get("env") or {}

    def line_number_for(self, search_text: str) -> Optional[int]:
        """Search for the first occurrence of *search_text* in the raw source.

        This is a best-effort helper for attaching line numbers to findings.
        It performs a simple substring scan of :attr:`raw_content` and returns
        the 1-based line number of the first matching line.

        Args:
            search_text: The text to search for within each source line.

        Returns:
            A 1-based line number, or ``None`` if the text was not found.
        """
        for lineno, line in enumerate(self.raw_content.splitlines(), start=1):
            if search_text in line:
                return lineno
        return None

    def __str__(self) -> str:
        """Return a brief string representation."""
        status = "valid" if self.is_valid else f"invalid: {self.parse_error}"
        return f"WorkflowFile({self.path}, {status})"


class ScannerError(Exception):
    """Raised when the scanner encounters an unrecoverable error.

    Individual YAML parse errors are *not* raised as :class:`ScannerError`;
    they are captured in :attr:`WorkflowFile.parse_error` instead.
    This exception is reserved for top-level failures such as an invalid
    or inaccessible target directory.
    """


class Scanner:
    """Discovers and loads GitHub Actions workflow YAML files from a directory.

    The scanner searches a root directory for workflow files, defaulting to the
    conventional ``.github/workflows/`` sub-directory.  It can also be
    configured to scan an explicit list of file paths.

    Args:
        root: The root directory to search.  Must be an existing directory.
        workflows_dir: Override the sub-directory (relative to *root*) that
            will be searched.  Defaults to ``.github/workflows``.
        explicit_paths: When provided, the scanner will load exactly these
            paths and skip directory discovery entirely.  Useful for
            pre-commit integration where the hook receives individual file
            paths.
        follow_symlinks: Whether to follow symbolic links during directory
            traversal.  Defaults to ``False``.

    Raises:
        ScannerError: If *root* does not exist or is not a directory (only
            when *explicit_paths* is not provided).
    """

    def __init__(
        self,
        root: Path,
        workflows_dir: Optional[Path] = None,
        explicit_paths: Optional[Sequence[Path]] = None,
        follow_symlinks: bool = False,
    ) -> None:
        """Initialise the scanner."""
        self._root = root
        self._workflows_dir = workflows_dir
        self._explicit_paths = list(explicit_paths) if explicit_paths else None
        self._follow_symlinks = follow_symlinks

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> List[WorkflowFile]:
        """Discover and load all workflow files, returning a list of results.

        Returns:
            A list of :class:`WorkflowFile` instances for every discovered
            YAML file.  Files that could not be parsed still appear in the
            list with :attr:`~WorkflowFile.parse_error` set.

        Raises:
            ScannerError: If the target directory is invalid and no explicit
                paths were provided.
        """
        return list(self._iter_workflow_files())

    def discover_paths(self) -> List[Path]:
        """Return a sorted list of YAML file paths to be scanned.

        When *explicit_paths* were supplied to the constructor, those paths
        are returned (filtered to known YAML extensions and verified to exist).
        Otherwise the conventional workflows directory is searched recursively.

        Returns:
            A sorted list of :class:`~pathlib.Path` objects.

        Raises:
            ScannerError: If the computed workflows directory does not exist
                and no explicit paths were provided.
        """
        if self._explicit_paths is not None:
            return self._resolve_explicit_paths()
        return self._discover_in_directory()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_workflow_files(self) -> Iterator[WorkflowFile]:
        """Yield :class:`WorkflowFile` instances for each discovered path."""
        paths = self.discover_paths()
        for path in paths:
            yield self._load_workflow_file(path)

    def _resolve_explicit_paths(self) -> List[Path]:
        """Filter and sort the caller-supplied explicit path list.

        Only paths that:
        1. Have a recognised YAML extension (``.yml`` or ``.yaml``), and
        2. Refer to an existing regular file

        …are included.

        Returns:
            A sorted list of validated :class:`~pathlib.Path` objects.
        """
        result: List[Path] = []
        for raw_path in self._explicit_paths or []:
            path = Path(raw_path)
            if path.suffix.lower() not in _YAML_EXTENSIONS:
                logger.debug("Skipping non-YAML path: %s", path)
                continue
            if not path.is_file():
                logger.warning("Explicit path does not exist or is not a file: %s", path)
                continue
            result.append(path)
        return sorted(result)

    def _discover_in_directory(self) -> List[Path]:
        """Recursively search the workflows directory for YAML files.

        Returns:
            A sorted list of :class:`~pathlib.Path` objects.

        Raises:
            ScannerError: If the search directory does not exist or is not a
                directory.
        """
        search_dir = self._compute_search_directory()

        if not search_dir.exists():
            raise ScannerError(
                f"Workflows directory does not exist: {search_dir}. "
                "Ensure the target repository contains a .github/workflows/ directory "
                "or specify an explicit path with --path."
            )
        if not search_dir.is_dir():
            raise ScannerError(
                f"Expected a directory but got a file: {search_dir}"
            )

        result: List[Path] = []
        try:
            for entry in search_dir.rglob("*"):
                if not entry.is_file(follow_symlinks=self._follow_symlinks):
                    continue
                if entry.suffix.lower() not in _YAML_EXTENSIONS:
                    continue
                result.append(entry)
        except OSError as exc:
            raise ScannerError(
                f"Error while traversing directory {search_dir}: {exc}"
            ) from exc

        return sorted(result)

    def _compute_search_directory(self) -> Path:
        """Return the directory that will be searched for workflow files.

        If the user supplied an explicit *workflows_dir* at construction time,
        that value is used (resolved relative to *root*).  Otherwise, the
        default ``.github/workflows`` sub-directory of *root* is used.

        Returns:
            A :class:`~pathlib.Path` pointing to the target directory.
        """
        if self._workflows_dir is not None:
            candidate = self._workflows_dir
            if not candidate.is_absolute():
                candidate = self._root / candidate
            return candidate
        return self._root / _DEFAULT_WORKFLOWS_SUBDIR

    @staticmethod
    def _load_workflow_file(path: Path) -> WorkflowFile:
        """Read and parse a single workflow YAML file.

        Args:
            path: Path to the ``.yml``/``.yaml`` file.

        Returns:
            A :class:`WorkflowFile` instance.  If the file cannot be read or
            parsed, the instance will have :attr:`~WorkflowFile.parse_error`
            set and :attr:`~WorkflowFile.data` will be ``None``.
        """
        try:
            raw_content = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Cannot read workflow file %s: %s", path, exc)
            return WorkflowFile(
                path=path,
                raw_content="",
                data=None,
                parse_error=f"Cannot read file: {exc}",
            )

        try:
            data = yaml.safe_load(raw_content)
        except yaml.YAMLError as exc:
            error_msg = _format_yaml_error(exc)
            logger.warning("YAML parse error in %s: %s", path, error_msg)
            return WorkflowFile(
                path=path,
                raw_content=raw_content,
                data=None,
                parse_error=error_msg,
            )

        if data is None:
            return WorkflowFile(
                path=path,
                raw_content=raw_content,
                data=None,
                parse_error="File is empty or contains only comments",
            )

        return WorkflowFile(path=path, raw_content=raw_content, data=data)


def _format_yaml_error(exc: yaml.YAMLError) -> str:
    """Format a :class:`yaml.YAMLError` into a concise human-readable string.

    Args:
        exc: The YAML exception to format.

    Returns:
        A short string describing the error, optionally including line/column
        information when available.
    """
    if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark is not None:
        mark = exc.problem_mark
        return (
            f"YAML parse error at line {mark.line + 1}, "
            f"column {mark.column + 1}: {exc.problem}"
        )
    return f"YAML parse error: {exc}"


def load_workflow_file(path: Path) -> WorkflowFile:
    """Module-level convenience function to load a single workflow file.

    This is a thin wrapper around :meth:`Scanner._load_workflow_file` for
    callers that do not need a full :class:`Scanner` instance.

    Args:
        path: Path to the ``.yml``/``.yaml`` workflow file.

    Returns:
        A :class:`WorkflowFile` instance.
    """
    return Scanner._load_workflow_file(path)
