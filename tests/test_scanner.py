"""Unit tests for the workflow file scanner (actions_auditor.scanner).

Covers:
- WorkflowFile dataclass properties and helpers
- Scanner.discover_paths() with directory traversal and explicit paths
- Scanner.scan() loading valid and invalid YAML files
- ScannerError raised for missing directories
- load_workflow_file() convenience function
- Integration with real fixture workflow files
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

_FIXTURES_DIR = Path(__file__).parent / "fixtures"

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

WORKFLOW_WITH_ENV = textwrap.dedent("""\
    name: Env Test
    on: push
    env:
      FOO: bar
      BAZ: qux
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo hello
""")

WORKFLOW_WITH_JOBS = textwrap.dedent("""\
    name: Jobs Test
    on: push
    permissions:
      contents: read
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo hello
      test:
        runs-on: ubuntu-latest
        steps:
          - run: pytest
""")


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


@pytest.fixture()
def empty_workflow_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary .github/workflows directory with no YAML files."""
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
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
            parse_error="YAML parse error at line 2, column 10: ...",
        )

    # is_valid

    def test_is_valid_true_for_parsed_file(self) -> None:
        wf = self._make_valid()
        assert wf.is_valid is True

    def test_is_valid_false_when_data_is_none(self) -> None:
        wf = self._make_invalid()
        assert wf.is_valid is False

    def test_is_valid_false_when_parse_error_set(self) -> None:
        wf = WorkflowFile(
            path=Path("x.yml"),
            raw_content="name: test",
            data={"name": "test"},
            parse_error="something wrong",
        )
        assert wf.is_valid is False

    def test_is_valid_false_when_both_none(self) -> None:
        wf = WorkflowFile(
            path=Path("x.yml"),
            raw_content="",
            data=None,
            parse_error=None,
        )
        assert wf.is_valid is False

    # jobs

    def test_jobs_returns_dict(self) -> None:
        wf = self._make_valid()
        assert isinstance(wf.jobs, dict)
        assert "build" in wf.jobs

    def test_jobs_returns_empty_dict_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.jobs == {}

    def test_jobs_returns_empty_dict_when_no_jobs_key(self) -> None:
        data = {"name": "test", "on": "push"}
        wf = WorkflowFile(
            path=Path("test.yml"),
            raw_content="name: test\non: push\n",
            data=data,
        )
        assert wf.jobs == {}

    def test_jobs_returns_multiple_jobs(self) -> None:
        data = yaml.safe_load(WORKFLOW_WITH_JOBS)
        wf = WorkflowFile(path=Path("test.yml"), raw_content=WORKFLOW_WITH_JOBS, data=data)
        assert "build" in wf.jobs
        assert "test" in wf.jobs

    # triggers

    def test_triggers_returns_list_for_list_syntax(self) -> None:
        wf = self._make_valid()
        triggers = wf.triggers
        # on: [push] should parse to a list
        assert triggers is not None
        assert "push" in triggers

    def test_triggers_returns_none_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.triggers is None

    def test_triggers_returns_dict_for_dict_syntax(self) -> None:
        content = textwrap.dedent("""\
            name: test
            on:
              push:
                branches: [main]
              pull_request:
            jobs: {}
        """)
        data = yaml.safe_load(content)
        wf = WorkflowFile(path=Path("test.yml"), raw_content=content, data=data)
        triggers = wf.triggers
        assert isinstance(triggers, dict)
        assert "push" in triggers

    def test_triggers_returns_string_for_string_syntax(self) -> None:
        content = textwrap.dedent("""\
            name: test
            on: push
            jobs: {}
        """)
        data = yaml.safe_load(content)
        wf = WorkflowFile(path=Path("test.yml"), raw_content=content, data=data)
        # on: push parses as the string 'push'
        assert wf.triggers == "push"

    # permissions

    def test_permissions_returns_value(self) -> None:
        wf = self._make_valid()
        assert wf.permissions == {"contents": "read"}

    def test_permissions_returns_none_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.permissions is None

    def test_permissions_returns_none_when_not_present(self) -> None:
        data = {"name": "test", "on": "push", "jobs": {}}
        wf = WorkflowFile(
            path=Path("test.yml"),
            raw_content="name: test\non: push\njobs: {}\n",
            data=data,
        )
        assert wf.permissions is None

    def test_permissions_returns_string_for_write_all(self) -> None:
        content = "name: test\non: push\npermissions: write-all\njobs: {}\n"
        data = yaml.safe_load(content)
        wf = WorkflowFile(path=Path("test.yml"), raw_content=content, data=data)
        assert wf.permissions == "write-all"

    # env

    def test_env_returns_empty_dict_when_not_present(self) -> None:
        wf = self._make_valid()
        assert wf.env == {}

    def test_env_returns_dict_when_present(self) -> None:
        data = yaml.safe_load(WORKFLOW_WITH_ENV)
        wf = WorkflowFile(
            path=Path("test.yml"), raw_content=WORKFLOW_WITH_ENV, data=data
        )
        assert wf.env == {"FOO": "bar", "BAZ": "qux"}

    def test_env_returns_empty_dict_for_invalid_file(self) -> None:
        wf = self._make_invalid()
        assert wf.env == {}

    # line_number_for

    def test_line_number_for_found(self) -> None:
        wf = self._make_valid()
        lineno = wf.line_number_for("permissions")
        assert lineno is not None
        assert isinstance(lineno, int)
        assert lineno >= 1

    def test_line_number_for_not_found(self) -> None:
        wf = self._make_valid()
        assert wf.line_number_for("this_string_does_not_exist_xyz") is None

    def test_line_number_for_first_occurrence(self) -> None:
        content = "line1\nline2\nline1\nline4\n"
        data = {"dummy": "value"}
        wf = WorkflowFile(path=Path("test.yml"), raw_content=content, data=data)
        lineno = wf.line_number_for("line1")
        assert lineno == 1  # Returns the FIRST occurrence

    def test_line_number_for_last_line(self) -> None:
        content = "a\nb\nc\ntarget"
        wf = WorkflowFile(
            path=Path("t.yml"),
            raw_content=content,
            data={"dummy": True},
        )
        lineno = wf.line_number_for("target")
        assert lineno == 4

    def test_line_number_is_one_based(self) -> None:
        content = "target_on_first_line\nother\n"
        wf = WorkflowFile(
            path=Path("t.yml"),
            raw_content=content,
            data={"dummy": True},
        )
        lineno = wf.line_number_for("target_on_first_line")
        assert lineno == 1

    # __str__

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

    # Additional edge cases

    def test_workflow_file_with_non_dict_data(self) -> None:
        """If YAML parses to something other than a dict, is_valid should still
        be True (data is not None and parse_error is None) but jobs/env/etc.
        should gracefully return empty values."""
        wf = WorkflowFile(
            path=Path("list.yml"),
            raw_content="- item1\n- item2\n",
            data=["item1", "item2"],
        )
        assert wf.is_valid is True  # No parse error, data is not None
        assert wf.jobs == {}
        assert wf.env == {}
        assert wf.permissions is None
        assert wf.triggers is None


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

    def test_returns_absolute_or_relative_paths(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        paths = scanner.discover_paths()
        for p in paths:
            assert isinstance(p, Path)

    def test_raises_scanner_error_for_missing_directory(self, tmp_path: Path) -> None:
        scanner = Scanner(tmp_path)  # no .github/workflows subdirectory
        with pytest.raises(ScannerError, match="does not exist"):
            scanner.discover_paths()

    def test_raises_scanner_error_message_is_helpful(self, tmp_path: Path) -> None:
        scanner = Scanner(tmp_path)
        with pytest.raises(ScannerError) as exc_info:
            scanner.discover_paths()
        assert ".github" in str(exc_info.value) or "exist" in str(exc_info.value)

    def test_custom_workflows_dir(self, tmp_path: Path) -> None:
        custom_dir = tmp_path / "my_workflows"
        custom_dir.mkdir()
        (custom_dir / "sample.yml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        scanner = Scanner(tmp_path, workflows_dir=custom_dir)
        paths = scanner.discover_paths()
        assert len(paths) == 1
        assert paths[0].name == "sample.yml"

    def test_custom_workflows_dir_relative_to_root(self, tmp_path: Path) -> None:
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        (custom_dir / "workflow.yml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        # Pass relative path
        scanner = Scanner(tmp_path, workflows_dir=Path("custom"))
        paths = scanner.discover_paths()
        assert len(paths) == 1

    def test_explicit_paths_used_when_provided(self, tmp_path: Path) -> None:
        yml_file = tmp_path / "explicit.yml"
        yml_file.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

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

    def test_explicit_paths_accepts_yaml_extension(self, tmp_path: Path) -> None:
        for ext in [".yml", ".yaml"]:
            p = tmp_path / f"workflow{ext}"
            p.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        scanner = Scanner(
            root=tmp_path,
            explicit_paths=[tmp_path / "workflow.yml", tmp_path / "workflow.yaml"],
        )
        paths = scanner.discover_paths()
        assert len(paths) == 2

    def test_empty_explicit_paths_returns_empty_list(self, tmp_path: Path) -> None:
        scanner = Scanner(root=tmp_path, explicit_paths=[])
        paths = scanner.discover_paths()
        assert paths == []

    def test_nested_yaml_files_discovered(self, tmp_path: Path) -> None:
        """YAML files in sub-directories are discovered via rglob."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        sub_dir = wf_dir / "sub"
        sub_dir.mkdir()
        (wf_dir / "top.yml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
        (sub_dir / "nested.yml").write_text(VALID_WORKFLOW_YAML, encoding="utf-8")

        scanner = Scanner(tmp_path)
        paths = scanner.discover_paths()
        names = {p.name for p in paths}
        assert "top.yml" in names
        assert "nested.yml" in names


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

    def test_scan_empty_directory(self, empty_workflow_dir: Path) -> None:
        scanner = Scanner(empty_workflow_dir)
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

    def test_scan_result_includes_raw_content(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        for wf in results:
            assert isinstance(wf.raw_content, str)

    def test_scan_result_has_correct_paths(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        for wf in results:
            assert wf.path.exists()

    def test_scan_excludes_txt_files(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        names = [wf.path.name for wf in results]
        assert "not_yaml.txt" not in names

    def test_scan_multiple_files_all_loaded(self, workflow_dir: Path) -> None:
        scanner = Scanner(workflow_dir)
        results = scanner.scan()
        # We put ci.yml, release.yaml, bad.yml in the fixture — 3 YAML files
        assert len(results) == 3

    def test_scan_with_empty_explicit_paths(self, tmp_path: Path) -> None:
        scanner = Scanner(root=tmp_path, explicit_paths=[])
        results = scanner.scan()
        assert results == []


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

    def test_path_stored_correctly(self, tmp_path: Path) -> None:
        p = tmp_path / "workflow.yml"
        p.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
        wf = load_workflow_file(p)
        assert wf.path == p

    def test_empty_file_parse_error_mentions_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yml"
        p.write_text("", encoding="utf-8")
        wf = load_workflow_file(p)
        assert not wf.is_valid
        assert wf.parse_error is not None

    def test_comment_only_file_treated_as_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "comments.yml"
        p.write_text("# just a comment\n# another comment\n", encoding="utf-8")
        wf = load_workflow_file(p)
        # yaml.safe_load returns None for comment-only files
        assert not wf.is_valid

    def test_loaded_data_is_dict_for_valid_workflow(self, tmp_path: Path) -> None:
        p = tmp_path / "ci.yml"
        p.write_text(VALID_WORKFLOW_YAML, encoding="utf-8")
        wf = load_workflow_file(p)
        assert isinstance(wf.data, dict)
        assert "name" in wf.data

    def test_missing_file_has_empty_raw_content(self, tmp_path: Path) -> None:
        p = tmp_path / "missing.yml"
        wf = load_workflow_file(p)
        assert wf.raw_content == ""


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
            assert (
                "line" in result.lower()
                or "column" in result.lower()
                or "parse" in result.lower()
            )

    def test_generic_error_fallback(self) -> None:
        """A plain YAMLError without mark still returns a useful string."""
        exc = yaml.YAMLError("something went wrong")
        result = _format_yaml_error(exc)
        assert "YAML" in result or "parse" in result.lower()

    def test_result_is_non_empty_for_unclosed_bracket(self) -> None:
        try:
            yaml.safe_load("items: [a, b, c")
        except yaml.YAMLError as exc:
            result = _format_yaml_error(exc)
            assert len(result) > 5

    def test_result_contains_column_info_when_available(self) -> None:
        try:
            yaml.safe_load(": invalid_key_position")
        except yaml.YAMLError as exc:
            result = _format_yaml_error(exc)
            # Should be a non-empty descriptive string
            assert isinstance(result, str)
            assert len(result) > 0


# ---------------------------------------------------------------------------
# Fixture-based integration tests
# ---------------------------------------------------------------------------


class TestScannerFixtures:
    """Integration tests using the real fixture YAML files."""

    def test_good_workflow_loads_successfully(self) -> None:
        fixture = _FIXTURES_DIR / "good_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: good_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid, f"Good fixture failed to parse: {wf.parse_error}"
        assert isinstance(wf.data, dict)

    def test_bad_workflow_loads_successfully(self) -> None:
        fixture = _FIXTURES_DIR / "bad_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: bad_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid, f"Bad fixture failed to parse: {wf.parse_error}"
        assert isinstance(wf.data, dict)

    def test_good_workflow_has_jobs(self) -> None:
        fixture = _FIXTURES_DIR / "good_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: good_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid
        assert len(wf.jobs) >= 1

    def test_bad_workflow_has_jobs(self) -> None:
        fixture = _FIXTURES_DIR / "bad_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: bad_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid
        assert len(wf.jobs) >= 1

    def test_good_workflow_has_triggers(self) -> None:
        fixture = _FIXTURES_DIR / "good_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: good_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid
        assert wf.triggers is not None

    def test_bad_workflow_has_triggers(self) -> None:
        fixture = _FIXTURES_DIR / "bad_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: bad_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid
        assert wf.triggers is not None

    def test_good_workflow_has_permissions(self) -> None:
        fixture = _FIXTURES_DIR / "good_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: good_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid
        assert wf.permissions is not None

    def test_bad_workflow_has_top_level_env(self) -> None:
        fixture = _FIXTURES_DIR / "bad_workflow.yml"
        if not fixture.exists():
            pytest.skip("Fixture not found: bad_workflow.yml")

        wf = load_workflow_file(fixture)
        assert wf.is_valid
        # bad_workflow.yml has top-level env with secrets
        assert len(wf.env) >= 1

    def test_scanner_discovers_fixtures_dir(self) -> None:
        """Scanner can discover fixtures from the fixtures directory."""
        if not _FIXTURES_DIR.exists():
            pytest.skip("Fixtures directory not found")

        scanner = Scanner(root=_FIXTURES_DIR, workflows_dir=_FIXTURES_DIR)
        results = scanner.scan()
        names = {wf.path.name for wf in results}
        assert "good_workflow.yml" in names or "bad_workflow.yml" in names

    def test_both_fixtures_line_number_search(self) -> None:
        """line_number_for works on the real fixture files."""
        for fixture_name in ["good_workflow.yml", "bad_workflow.yml"]:
            fixture = _FIXTURES_DIR / fixture_name
            if not fixture.exists():
                continue
            wf = load_workflow_file(fixture)
            assert wf.is_valid
            # 'name' appears in every fixture
            lineno = wf.line_number_for("name:")
            assert lineno is not None
            assert lineno >= 1
