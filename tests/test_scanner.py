"""Unit tests for the workflow file scanner (actions_auditor.scanner).

Covers:
- WorkflowFile dataclass properties and helpers
- Scanner.discover_paths() with directory traversal and explicit paths
- Scanner.scan() loading valid and invalid YAML files
- ScannerError raised for missing directories
- load_workflow_file() convenience function
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Generator

import pytest
import yaml

from actions_auditor.scanner import (
    Scanner,
    ScannerError,
    WorkflowFile,
    _format_yaml_error,
    load_workflow_file,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


VALID_WORKFLOW_YAML = textwrap.dedent("""\
    name: CI
    on: [push]
    permissions:
      contents: read
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")

INVALID_YAML_CONTENT = textwrap.dedent("""\
    name: broken
    on: [push
    this is: : not valid yaml::
""")

EMPTY_YAML_CONTENT = """

"""  # only whitespace / blank lines


@pytest.fixture()
def workflow_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary .github/workflows directory with sample files."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)

    (wf_dir / "ci.yml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
    (wf_dir / "release.yaml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
    (wf_dir / "bad.yml").write_text(INVALID_YAML_CONTENT, encoding="utf-8")
    (wf_dir / "not_yaml.txt").write_text("just text", encoding="utf-8")
    yield tmp_path


# ---------------------------------------------------------------------------
# WorkflowFile tests
# ---------------------------------------------------------------------------


class TestWorkflowFile:
    """Tests for the WorkflowFile dataclass."""

    def _make_valid(self, path: Path = Path("ci.yml")) -> WorkflowFile:
        data = yaml.safe_load(VALID_WORKFLOW_YAML)
        return WorkflowFile(path=path, raw_content=VALID_WORKFLOW_YAML, data=data)

    def _make_invalid(self, path: Path = Path("bad.yml")) -> WorkflowFile:
        return WorkflowFile(
            path=path,
            raw_content=INVALID_YAML_CONTENT,
            data=None,
            parse_error="YAML parse error at line 2, column 10: mapping values are not allowed here",
        )

    def test_is_valid_true_for_parsed_file(self) -> None:
        wf = self._make_valid()
        assert wf.is_valid is True

    def test_is_valid_false_when_data_is_none(self) -> None:
        wf = self._make_invalid()
        assert wf.is_valid is False

    def test_jobs_returns_dict(self) -> None:
        wf = self._make_valid()
        assert isinstance(wf.jobs, dict)
        assert "build" in wf.jobs

    def test_jobs_returns_empty_dict_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.jobs == {}

    def test_triggers_returns_value(self) -> None:
        wf = self._make_valid()
        # The 'on' key in VALID_WORKFLOW_YAML is [push]
        assert wf.triggers is not None

    def test_triggers_returns_none_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.triggers is None

    def test_permissions_returns_value(self) -> None:
        wf = self._make_valid()
        assert wf.permissions == {"contents": "read"}

    def test_permissions_returns_none_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.permissions is None

    def test_env_returns_empty_dict_when_not_present(self) -> None:
        wf = self._make_valid()
        assert wf.env == {}

    def test_env_returns_dict_when_present(self) -> None:
        content = textwrap.dedent("""\
            name: test
            on: push
            env:
              FOO: bar
              BAZ: qux
            jobs: {}
        """)
        data = yaml.safe_load(content)
        wf = WorkflowFile(path=Path("test.yml"), raw_content=content, data=data)
        assert wf.env == {"FOO": "bar", "BAZ": "qux"}

    def test_line_number_for_found(self) -> None:
        wf = self._make_valid()
        lineno = wf.line_number_for("permissions")
        assert lineno is not None
        assert isinstance(lineno, int)
        assert lineno >= 1

    def test_line_number_for_not_found(self) -> None:
        wf = self._make_valid()
        assert wf.line_number_for("this_string_does_not_exist_xyz") is None

    def test_str_representation_valid(self) -> None:
        wf = self._make_valid(path=Path("ci.yml"))
        s = str(wf)
        assert "ci.yml" in s
        assert "valid" in s

    def test_str_representation_invalid(self) -> None:
        wf = self._make_invalid(path=Path("bad.yml"))
        s = str(wf)
        assert "bad.yml" in s
        assert "invalid" in s


# ---------------------------------------------------------------------------
# Scanner.discover_paths() tests
# ---------------------------------------------------------------------------


class TestScannerDiscoverPaths:
    """Tests for path discovery logic."""

    def test_discovers_yml_files(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        paths = scanner.discover_paths()
        names = {p.name for p in paths}
        assert "ci.yml" in names
        assert "release.yaml" in names

    def test_excludes_non_yaml_files(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        paths = scanner.discover_paths()
        names = {p.name for p in paths}
        assert "not_yaml.txt" not in names

    def test_includes_bad_yaml_files(self, workflow_dir: Path) -> None:
        """Bad YAML files are discovered; parse errors come later."""
        scanner = Scanner(workflow_dir)
        paths = scanner.discover_paths()
        names = {p.name for p in paths}
        assert "bad.yml" in names

    def test_paths_are_sorted(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        paths = scanner.discover_paths()
        assert paths == sorted(paths)

    def test_raises_scanner_error_for_missing_directory(self, tmp_path: Path) -> None:
        scanner = Scanner(tmp_path)  # no .github/workflows subdirectory
        with pytest.raises(ScannerError, match="does not exist"):
            scanner.discover_paths()

    def test_custom_workflows_dir(self, tmp_path: Path) -> None:
        custom_dir = tmp_path / "my_workflows"
        custom_dir.mkdir()
        (custom_dir / "sample.yml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        scanner = Scanner(tmp_path, workflows_dir=custom_dir)
        paths = scanner.discover_paths()
        assert len(paths) == 1
        assert paths[0].name == "sample.yml"

    def test_explicit_paths_used_when_provided(self, tmp_path: Path) -> None:
        yml_file = tmp_path / "explicit.yml"
        yml_file.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        # Providing a non-existent root is fine when explicit_paths are given
        scanner = Scanner(root=tmp_path, explicit_paths=[yml_file])
        paths = scanner.discover_paths()
        assert paths == [yml_file]

    def test_explicit_paths_filters_non_yaml(self, tmp_path: Path) -> None:
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("hello", encoding="utf-8")
        yml_file = tmp_path / "ci.yml"
        yml_file.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        scanner = Scanner(root=tmp_path, explicit_paths=[txt_file, yml_file])
        paths = scanner.discover_paths()
        assert txt_file not in paths
        assert yml_file in paths

    def test_explicit_paths_filters_missing_files(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.yml"
        scanner = Scanner(root=tmp_path, explicit_paths=[missing])
        paths = scanner.discover_paths()
        assert missing not in paths

    def test_explicit_paths_sorted(self, tmp_path: Path) -> None:
        files = []
        for name in ["zzz.yml", "aaa.yml", "mmm.yaml"]:
            p = tmp_path / name
            p.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
            files.append(p)

        scanner = Scanner(root=tmp_path, explicit_paths=files)
        paths = scanner.discover_paths()
        assert paths == sorted(paths)


# ---------------------------------------------------------------------------
# Scanner.scan() tests
# ---------------------------------------------------------------------------


class TestScannerScan:
    """Tests for the full scan() method."""

    def test_scan_returns_list_of_workflow_files(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        assert isinstance(results, list)
        assert all(isinstance(wf, WorkflowFile) for wf in results)

    def test_scan_valid_file_has_data(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        valid = [wf for wf in results if wf.path.name == "ci.yml"]
        assert len(valid) == 1
        assert valid[0].is_valid
        assert valid[0].data is not None

    def test_scan_invalid_yaml_has_parse_error(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        bad = [wf for wf in results if wf.path.name == "bad.yml"]
        assert len(bad) == 1
        assert not bad[0].is_valid
        assert bad[0].parse_error is not None

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        scanner = Scanner(tmp_path)
        results = scanner.scan()
        assert results == []

    def test_scan_with_explicit_paths(self, tmp_path: Path) -> None:
        yml_file = tmp_path / "ci.yml"
        yml_file.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        scanner = Scanner(root=tmp_path, explicit_paths=[yml_file])
        results = scanner.scan()
        assert len(results) == 1
        assert results[0].path == yml_file
        assert results[0].is_valid

    def test_scan_raises_scanner_error_without_workflows_dir(self, tmp_path: Path) -> None:
        scanner = Scanner(tmp_path)
        with pytest.raises(ScannerError):
            scanner.scan()


# ---------------------------------------------------------------------------
# load_workflow_file() convenience function tests
# ---------------------------------------------------------------------------


class TestLoadWorkflowFile:
    """Tests for the module-level load_workflow_file function."""

    def test_loads_valid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "ci.yml"
        p.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
        wf = load_workflow_file(p)
        assert wf.is_valid
        assert isinstance(wf.data, dict)
        assert wf.path == p

    def test_handles_invalid_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yml"
        p.write_text(INVALID_YAML_CONTENT, encoding="utf-8")
        wf = load_workflow_file(p)
        assert not wf.is_valid
        assert wf.parse_error is not None
        assert "YAML" in wf.parse_error or "parse" in wf.parse_error.lower()

    def test_handles_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yml"
        p.write_text(EMPTY_YAML_CONTENT, encoding="utf-8")
        wf = load_workflow_file(p)
        assert not wf.is_valid
        assert wf.parse_error is not None

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        p = tmp_path / "nonexistent.yml"
        wf = load_workflow_file(p)
        assert not wf.is_valid
        assert wf.parse_error is not None
        assert "Cannot read file" in wf.parse_error

    def test_raw_content_preserved(self, tmp_path: Path) -> None:
        p = tmp_path / "ci.yml"
        p.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
        wf = load_workflow_file(p)
        assert wf.raw_content == VALID_WORKFLOW_YAML


# ---------------------------------------------------------------------------
# _format_yaml_error helper tests
# ---------------------------------------------------------------------------


class TestFormatYamlError:
    """Tests for the _format_yaml_error internal helper."""

    def test_returns_string(self) -> None:
        try:
            yaml.safe_load("key: [unclosed")
        except yaml.YAMLError as exc:
            result = _format_yaml_error(exc)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_includes_line_info_for_marked_error(self) -> None:
        try:
            yaml.safe_load("key: : bad")
        except yaml.YAMLError as exc:
            result = _format_yaml_error(exc)
            # Should mention line or column
            assert "line" in result.lower() or "column" in result.lower() or "parse" in result.lower()

    def test_generic_error_fallback(self) -> None:
        """A plain YAMLError without mark still returns a useful string."""
        exc = yaml.YAMLError("something went wrong")
        result = _format_yaml_error(exc)
        assert "YAML" in result or "parse" in result.lower()
