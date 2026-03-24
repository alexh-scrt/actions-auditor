"""Security rule checker functions for actions_auditor.

This module defines all security rules as composable checker functions that
accept a :class:`~actions_auditor.scanner.WorkflowFile` and return a list of
:class:`~actions_auditor.models.Finding` objects.

Rules implemented:

- **AA001** – Overly permissive GITHUB_TOKEN (``permissions: write-all`` or
  ``permissions: write-all`` at workflow/job level).
- **AA002** – Missing top-level ``permissions`` declaration.
- **AA003** – Secret exposed in environment variable (top-level or job-level
  ``env`` blocks containing ``${{ secrets.* }}`` expressions).
- **AA004** – Secret interpolated directly in a ``run`` script.
- **AA005** – Third-party action not pinned to a full 40-character commit SHA.
- **AA006** – ``pull_request_target`` trigger combined with a head-ref checkout.
- **AA007** – Script injection risk from untrusted GitHub context values
  interpolated directly into ``run`` scripts.
- **AA008** – ``workflow_dispatch`` input interpolated directly into a ``run``
  script.

Each public checker function follows the signature::

    def check_<name>(workflow: WorkflowFile) -> List[Finding]: ...

A convenience :func:`run_all_rules` function applies every rule in one call.

Typical usage::

    from actions_auditor.rules import run_all_rules
    from actions_auditor.scanner import load_workflow_file
    from pathlib import Path

    wf = load_workflow_file(Path(".github/workflows/ci.yml"))
    findings = run_all_rules(wf)
    for finding in findings:
        print(finding)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from actions_auditor.models import Finding, Severity
from actions_auditor.scanner import WorkflowFile

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

RuleChecker = Callable[[WorkflowFile], List[Finding]]

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Matches a full 40-character hexadecimal Git commit SHA.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# Matches any ${{ secrets.<name> }} expression.
_SECRET_EXPR_RE = re.compile(r"\${{\s*secrets\.[^}]+}}")

# Matches ${{ github.<anything> }} context expressions that carry user-
# controlled data and are therefore potential script injection sources.
# We include the most commonly dangerous sub-contexts.
_GITHUB_UNTRUSTED_CONTEXTS: Tuple[str, ...] = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo.full_name",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.head_ref",
    "github.ref",
)

# Build a combined regex that matches any of the untrusted context expressions
# inside a ${{ ... }} expression.
_untrusted_patterns = "|".join(
    re.escape(ctx) for ctx in _GITHUB_UNTRUSTED_CONTEXTS
)
_GITHUB_INJECTION_RE = re.compile(
    r"\${{\s*(?:" + _untrusted_patterns + r")\s*}}"
)

# Matches ${{ inputs.<name> }} workflow_dispatch input expressions.
_INPUTS_EXPR_RE = re.compile(r"\${{\s*inputs\.[^}]+}}")

# Matches GitHub Actions 'uses:' references that are NOT pinned to a full SHA.
# Format: <owner>/<repo>@<ref>  (or  <owner>/<repo>/<path>@<ref>)
# We flag references whose @<ref> part is NOT a 40-char hex SHA.
_USES_RE = re.compile(r"^([a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+)@(.+)$")

# Permitted built-in action prefixes that do not require SHA pinning because
# they are maintained by GitHub and versioned atomically with the runner.
_GITHUB_BUILTIN_OWNERS = frozenset(
    [
        "actions",  # actions/checkout, actions/cache, etc. – still flagged per policy
    ]
)

# Head-ref checkout indicators used by AA006.
_HEAD_REF_PATTERNS: Tuple[str, ...] = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
)

# Write-level permission values that are considered overly permissive.
_WRITE_PERMISSION_VALUES = frozenset(["write", "write-all"])

# The literal strings that make an entire permissions block too permissive.
_PERMISSIVE_BLOCK_VALUES = frozenset(["write-all"])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _iter_steps(
    workflow: WorkflowFile,
) -> Iterator[Tuple[str, int, Dict[str, Any]]]:
    """Yield ``(job_name, step_index, step_dict)`` for every step in a workflow.

    Steps whose value is not a dict are silently skipped.

    Args:
        workflow: The parsed workflow file to iterate over.

    Yields:
        A 3-tuple of ``(job_name, step_index, step_dict)``.
    """
    for job_name, job_data in workflow.jobs.items():
        if not isinstance(job_data, dict):
            continue
        steps = job_data.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step_index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            yield job_name, step_index, step


def _step_display_name(step: Dict[str, Any], step_index: int) -> str:
    """Return a human-readable name for a step.

    Args:
        step: The step dictionary.
        step_index: The 0-based index of the step within its job.

    Returns:
        The step's ``name`` field if present, otherwise ``'step <N>'``.
    """
    return step.get("name") or f"step {step_index + 1}"


def _is_sha_pinned(ref: str) -> bool:
    """Return ``True`` if *ref* is a full 40-character hexadecimal commit SHA.

    Args:
        ref: The reference string (the part after ``@`` in a ``uses:`` value).

    Returns:
        ``True`` when *ref* matches the 40-char hex pattern.
    """
    return bool(_SHA_RE.match(ref.strip()))


def _first_line_containing(raw_content: str, text: str) -> Optional[int]:
    """Return the 1-based line number of the first line containing *text*.

    Args:
        raw_content: The raw YAML source text.
        text: The substring to search for.

    Returns:
        A 1-based line number, or ``None`` if not found.
    """
    for lineno, line in enumerate(raw_content.splitlines(), start=1):
        if text in line:
            return lineno
    return None


def _make_finding(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file_path: Path,
    line_number: Optional[int] = None,
    job_name: Optional[str] = None,
    step_name: Optional[str] = None,
    evidence: Optional[str] = None,
) -> Finding:
    """Construct a :class:`Finding` with ``remediation_id`` equal to *rule_id*.

    Args:
        rule_id: The rule identifier.
        title: Short finding title.
        description: Detailed description of the issue.
        severity: The severity level.
        file_path: Path to the offending file.
        line_number: Optional 1-based line number.
        job_name: Optional job context.
        step_name: Optional step context.
        evidence: Optional source snippet.

    Returns:
        A fully populated :class:`Finding` instance.
    """
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
        remediation_id=rule_id,
    )


# ---------------------------------------------------------------------------
# AA001 – Overly permissive GITHUB_TOKEN
# ---------------------------------------------------------------------------


def check_overly_permissive_token(workflow: WorkflowFile) -> List[Finding]:
    """Detect overly permissive ``permissions`` declarations (AA001).

    Flags ``permissions: write-all`` at the top level or at the individual
    job level.  Also flags job-level permissions where *any* scope is set to
    ``write`` when the job has no obvious need (conservative heuristic).

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    findings: List[Finding] = []

    # --- Top-level permissions ---
    top_perms = workflow.permissions
    if top_perms is not None:
        if isinstance(top_perms, str) and top_perms.strip() in _PERMISSIVE_BLOCK_VALUES:
            line = _first_line_containing(workflow.raw_content, "write-all")
            findings.append(
                _make_finding(
                    rule_id="AA001",
                    title="Overly permissive GITHUB_TOKEN (write-all)",
                    description=(
                        "The workflow grants 'write-all' permissions to the GITHUB_TOKEN, "
                        "giving every job unrestricted write access to all repository "
                        "resources. This maximises the blast radius of any supply-chain "
                        "or injection attack."
                    ),
                    severity=Severity.HIGH,
                    file_path=workflow.path,
                    line_number=line,
                    evidence="permissions: write-all",
                )
            )

    # --- Job-level permissions ---
    for job_name, job_data in workflow.jobs.items():
        if not isinstance(job_data, dict):
            continue
        job_perms = job_data.get("permissions")
        if job_perms is None:
            continue
        if isinstance(job_perms, str) and job_perms.strip() in _PERMISSIVE_BLOCK_VALUES:
            line = _first_line_containing(workflow.raw_content, "write-all")
            findings.append(
                _make_finding(
                    rule_id="AA001",
                    title="Overly permissive GITHUB_TOKEN at job level (write-all)",
                    description=(
                        f"Job '{job_name}' grants 'write-all' permissions to the "
                        "GITHUB_TOKEN. Limit permissions to only the scopes this "
                        "specific job requires."
                    ),
                    severity=Severity.HIGH,
                    file_path=workflow.path,
                    line_number=line,
                    job_name=job_name,
                    evidence=f"permissions: write-all (job: {job_name})",
                )
            )
        elif isinstance(job_perms, dict):
            # Flag individual scopes set to 'write' at job level as MEDIUM
            # (write-all at job level is already HIGH above)
            for scope, value in job_perms.items():
                if isinstance(value, str) and value.strip() == "write":
                    evidence_str = f"{scope}: write"
                    line = _first_line_containing(workflow.raw_content, evidence_str)
                    findings.append(
                        _make_finding(
                            rule_id="AA001",
                            title=f"Broad GITHUB_TOKEN write scope: '{scope}'",
                            description=(
                                f"Job '{job_name}' grants write access to the '{scope}' "
                                "scope. Verify that this level of access is strictly "
                                "necessary and that the scope cannot be narrowed."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=workflow.path,
                            line_number=line,
                            job_name=job_name,
                            evidence=evidence_str,
                        )
                    )

    return findings


# ---------------------------------------------------------------------------
# AA002 – Missing top-level permissions declaration
# ---------------------------------------------------------------------------


def check_missing_permissions(workflow: WorkflowFile) -> List[Finding]:
    """Detect workflows that omit a top-level ``permissions`` block (AA002).

    When no ``permissions`` key is present, GitHub uses the repository's default
    permissions which may grant broad write access to the token.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    if not isinstance(workflow.data, dict):
        return []

    # Check whether any 'permissions' key is present at the top level.
    # PyYAML may interpret the bare 'on' keyword as True; we use .get() safely.
    if "permissions" not in workflow.data:
        return [
            _make_finding(
                rule_id="AA002",
                title="Missing top-level permissions declaration",
                description=(
                    "No top-level 'permissions' block was found. Without an explicit "
                    "declaration the GITHUB_TOKEN inherits the repository's default "
                    "permissions, which may include broad write access. Add a "
                    "'permissions' block with the minimum required scopes."
                ),
                severity=Severity.MEDIUM,
                file_path=workflow.path,
                evidence="permissions: <not declared>",
            )
        ]

    return []


# ---------------------------------------------------------------------------
# AA003 – Secret exposed in environment variable
# ---------------------------------------------------------------------------


def check_secrets_in_env(workflow: WorkflowFile) -> List[Finding]:
    """Detect ``${{ secrets.* }}`` expressions in ``env`` blocks (AA003).

    Checks the top-level ``env`` block and every job-level ``env`` block.
    Secrets in step-level ``env`` are acceptable (narrowly scoped) and are
    not flagged by this rule.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    findings: List[Finding] = []

    # --- Top-level env ---
    for var_name, var_value in workflow.env.items():
        if not isinstance(var_value, str):
            continue
        if _SECRET_EXPR_RE.search(var_value):
            evidence = f"{var_name}: {var_value}"
            line = _first_line_containing(workflow.raw_content, var_name)
            findings.append(
                _make_finding(
                    rule_id="AA003",
                    title=f"Secret exposed in top-level env variable '{var_name}'",
                    description=(
                        f"The top-level environment variable '{var_name}' contains a "
                        "'${{ secrets.* }}' expression. Secrets exposed at the "
                        "workflow level are accessible to every job and step, "
                        "including third-party actions that could exfiltrate them."
                    ),
                    severity=Severity.HIGH,
                    file_path=workflow.path,
                    line_number=line,
                    evidence=evidence,
                )
            )

    # --- Job-level env ---
    for job_name, job_data in workflow.jobs.items():
        if not isinstance(job_data, dict):
            continue
        job_env = job_data.get("env") or {}
        if not isinstance(job_env, dict):
            continue
        for var_name, var_value in job_env.items():
            if not isinstance(var_value, str):
                continue
            if _SECRET_EXPR_RE.search(var_value):
                evidence = f"{var_name}: {var_value}"
                line = _first_line_containing(workflow.raw_content, var_name)
                findings.append(
                    _make_finding(
                        rule_id="AA003",
                        title=f"Secret exposed in job-level env variable '{var_name}'",
                        description=(
                            f"Job '{job_name}' exposes the secret via the environment "
                            f"variable '{var_name}'. This makes the secret accessible "
                            "to all steps in the job, including any third-party actions."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=workflow.path,
                        line_number=line,
                        job_name=job_name,
                        evidence=evidence,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# AA004 – Secret interpolated in run script
# ---------------------------------------------------------------------------


def check_secrets_in_run(workflow: WorkflowFile) -> List[Finding]:
    """Detect ``${{ secrets.* }}`` expressions embedded directly in ``run`` steps (AA004).

    Secrets interpolated directly into shell scripts can appear in error
    messages, debug output, and process listings.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    findings: List[Finding] = []

    for job_name, step_index, step in _iter_steps(workflow):
        run_script = step.get("run")
        if not isinstance(run_script, str):
            continue

        matches = _SECRET_EXPR_RE.findall(run_script)
        if not matches:
            continue

        step_name = _step_display_name(step, step_index)
        # Use the first match as evidence; truncate for readability.
        first_match = matches[0]
        # Find a representative line to attach the finding to.
        line = _first_line_containing(workflow.raw_content, first_match)
        if line is None:
            # Fall back to finding the run: keyword near the step name context
            line = _first_line_containing(workflow.raw_content, "run:")

        findings.append(
            _make_finding(
                rule_id="AA004",
                title="Secret directly interpolated in run script",
                description=(
                    f"Step '{step_name}' in job '{job_name}' embeds a "
                    "'${{ secrets.* }}' expression directly in a 'run' script. "
                    "The secret value is substituted into the shell command before "
                    "execution, which can cause it to appear in logs or error output. "
                    "Use a step-level 'env' variable instead."
                ),
                severity=Severity.HIGH,
                file_path=workflow.path,
                line_number=line,
                job_name=job_name,
                step_name=step_name,
                evidence=first_match,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# AA005 – Unpinned third-party action
# ---------------------------------------------------------------------------


def check_unpinned_actions(workflow: WorkflowFile) -> List[Finding]:
    """Detect ``uses:`` references not pinned to a full commit SHA (AA005).

    Every ``uses:`` entry of the form ``<owner>/<repo>@<ref>`` where ``<ref>``
    is not a 40-character hexadecimal SHA is flagged.  Docker actions
    (``docker://...``) and local actions (``./path``) are exempt.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    findings: List[Finding] = []

    for job_name, step_index, step in _iter_steps(workflow):
        uses_value = step.get("uses")
        if not isinstance(uses_value, str):
            continue

        uses_value = uses_value.strip()

        # Skip local actions and Docker image references.
        if uses_value.startswith("./") or uses_value.startswith("docker://"):
            continue

        match = _USES_RE.match(uses_value)
        if match is None:
            # Unusual format – skip rather than false-positive.
            continue

        action_ref = match.group(2)
        if _is_sha_pinned(action_ref):
            # Already pinned to a full SHA – compliant.
            continue

        step_name = _step_display_name(step, step_index)
        line = _first_line_containing(workflow.raw_content, uses_value)

        findings.append(
            _make_finding(
                rule_id="AA005",
                title=f"Unpinned action: {uses_value}",
                description=(
                    f"Step '{step_name}' in job '{job_name}' references the action "
                    f"'{uses_value}' using a mutable tag or branch ('{action_ref}'). "
                    "A mutable reference allows the action's author — or an attacker "
                    "who has compromised that repository — to silently change the code "
                    "that runs in your workflow. Pin the action to a full 40-character "
                    "commit SHA to ensure reproducibility and prevent supply-chain attacks."
                ),
                severity=Severity.HIGH,
                file_path=workflow.path,
                line_number=line,
                job_name=job_name,
                step_name=step_name,
                evidence=f"uses: {uses_value}",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# AA006 – pull_request_target with head checkout
# ---------------------------------------------------------------------------


def check_pull_request_target(workflow: WorkflowFile) -> List[Finding]:
    """Detect dangerous ``pull_request_target`` + head-ref checkout patterns (AA006).

    The combination of the ``pull_request_target`` trigger (which grants the
    GITHUB_TOKEN write permissions) with a checkout of the PR head ref
    (which executes attacker-controlled code) is a critical vulnerability.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    triggers = workflow.triggers
    if triggers is None:
        return []

    # Check whether pull_request_target is one of the triggers.
    has_prt = False
    if isinstance(triggers, list):
        has_prt = "pull_request_target" in triggers
    elif isinstance(triggers, dict):
        has_prt = "pull_request_target" in triggers
    elif isinstance(triggers, str):
        has_prt = triggers == "pull_request_target"

    if not has_prt:
        return []

    findings: List[Finding] = []

    # Now look for head-ref checkout patterns in any step.
    for job_name, step_index, step in _iter_steps(workflow):
        uses_value = step.get("uses", "")
        if not isinstance(uses_value, str):
            uses_value = ""

        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            with_block = {}

        run_script = step.get("run", "")
        if not isinstance(run_script, str):
            run_script = ""

        # Combine all textual content of the step for pattern matching.
        step_text = " ".join(
            [
                uses_value,
                " ".join(str(v) for v in with_block.values()),
                run_script,
            ]
        )

        for pattern in _HEAD_REF_PATTERNS:
            if pattern in step_text:
                step_name = _step_display_name(step, step_index)
                line = _first_line_containing(workflow.raw_content, pattern)
                if line is None:
                    line = _first_line_containing(
                        workflow.raw_content, "pull_request_target"
                    )

                findings.append(
                    _make_finding(
                        rule_id="AA006",
                        title="pull_request_target with head-ref checkout",
                        description=(
                            f"Job '{job_name}', step '{step_name}' checks out the PR "
                            f"head ref (via '{pattern}') in a workflow triggered by "
                            "'pull_request_target'. This trigger grants the GITHUB_TOKEN "
                            "write permissions while executing in the base-repo context, "
                            "meaning attacker-controlled PR code runs with elevated "
                            "privileges. This is the exact pattern behind major CI/CD "
                            "supply-chain breaches."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=workflow.path,
                        line_number=line,
                        job_name=job_name,
                        step_name=step_name,
                        evidence=f"on: pull_request_target + {pattern}",
                    )
                )
                # Only report each step once (first matching pattern is enough).
                break

    return findings


# ---------------------------------------------------------------------------
# AA007 – Script injection from untrusted GitHub context
# ---------------------------------------------------------------------------


def check_script_injection(workflow: WorkflowFile) -> List[Finding]:
    """Detect untrusted GitHub context values interpolated in ``run`` scripts (AA007).

    Expressions like ``${{ github.event.pull_request.title }}`` embedded
    directly in shell commands allow attackers to inject arbitrary shell code
    by crafting a PR with a malicious title.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    findings: List[Finding] = []

    for job_name, step_index, step in _iter_steps(workflow):
        run_script = step.get("run")
        if not isinstance(run_script, str):
            continue

        matches = _GITHUB_INJECTION_RE.findall(run_script)
        if not matches:
            continue

        step_name = _step_display_name(step, step_index)
        first_match = matches[0]
        line = _first_line_containing(workflow.raw_content, first_match)

        findings.append(
            _make_finding(
                rule_id="AA007",
                title="Potential script injection via untrusted GitHub context",
                description=(
                    f"Step '{step_name}' in job '{job_name}' interpolates a "
                    "user-controlled GitHub context value directly into a shell "
                    "'run' script. An attacker can craft a PR title, issue body, "
                    "or commit message containing shell metacharacters to execute "
                    "arbitrary commands. Pass the value through a step-level "
                    "environment variable instead."
                ),
                severity=Severity.CRITICAL,
                file_path=workflow.path,
                line_number=line,
                job_name=job_name,
                step_name=step_name,
                evidence=first_match,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# AA008 – workflow_dispatch input in run script
# ---------------------------------------------------------------------------


def check_workflow_dispatch_injection(workflow: WorkflowFile) -> List[Finding]:
    """Detect ``${{ inputs.* }}`` expressions interpolated in ``run`` scripts (AA008).

    ``workflow_dispatch`` inputs are supplied by whoever triggers the workflow;
    embedding them directly in shell commands enables command injection.

    Args:
        workflow: The parsed workflow file to check.

    Returns:
        A list of :class:`Finding` objects, possibly empty.
    """
    if not workflow.is_valid:
        return []

    # Only flag if the workflow actually declares a workflow_dispatch trigger.
    triggers = workflow.triggers
    if triggers is None:
        return []

    has_dispatch = False
    if isinstance(triggers, list):
        has_dispatch = "workflow_dispatch" in triggers
    elif isinstance(triggers, dict):
        has_dispatch = "workflow_dispatch" in triggers
    elif isinstance(triggers, str):
        has_dispatch = triggers == "workflow_dispatch"

    if not has_dispatch:
        return []

    findings: List[Finding] = []

    for job_name, step_index, step in _iter_steps(workflow):
        run_script = step.get("run")
        if not isinstance(run_script, str):
            continue

        matches = _INPUTS_EXPR_RE.findall(run_script)
        if not matches:
            continue

        step_name = _step_display_name(step, step_index)
        first_match = matches[0]
        line = _first_line_containing(workflow.raw_content, first_match)

        findings.append(
            _make_finding(
                rule_id="AA008",
                title="workflow_dispatch input interpolated in run script",
                description=(
                    f"Step '{step_name}' in job '{job_name}' embeds a "
                    "'${{ inputs.* }}' expression directly in a shell 'run' script. "
                    "Anyone with permission to trigger the workflow (manually or via "
                    "API) can supply a malicious input value containing shell "
                    "metacharacters to execute arbitrary commands. Use a step-level "
                    "environment variable to safely pass the input value."
                ),
                severity=Severity.HIGH,
                file_path=workflow.path,
                line_number=line,
                job_name=job_name,
                step_name=step_name,
                evidence=first_match,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Rule registry and runner
# ---------------------------------------------------------------------------

#: Ordered list of all registered rule checker functions.
#: Add new rules here to include them in :func:`run_all_rules`.
ALL_RULES: List[RuleChecker] = [
    check_overly_permissive_token,  # AA001
    check_missing_permissions,      # AA002
    check_secrets_in_env,           # AA003
    check_secrets_in_run,           # AA004
    check_unpinned_actions,         # AA005
    check_pull_request_target,      # AA006
    check_script_injection,         # AA007
    check_workflow_dispatch_injection,  # AA008
]


def run_all_rules(workflow: WorkflowFile) -> List[Finding]:
    """Apply every registered security rule to *workflow* and return all findings.

    Rules are applied in the order defined in :data:`ALL_RULES`.  Each rule
    is called independently; an exception raised by one rule does not prevent
    the others from running.

    Args:
        workflow: The parsed workflow file to evaluate.

    Returns:
        A flat list of all :class:`Finding` objects produced by every rule.
        The list is sorted from most to least severe.
    """
    all_findings: List[Finding] = []
    for rule_fn in ALL_RULES:
        try:
            results = rule_fn(workflow)
            all_findings.extend(results)
        except Exception as exc:  # pylint: disable=broad-except
            # Log and continue so one broken rule does not abort the entire scan.
            import logging

            logging.getLogger(__name__).error(
                "Rule %s raised an unexpected error on %s: %s",
                rule_fn.__name__,
                workflow.path,
                exc,
                exc_info=True,
            )

    # Sort findings from most to least severe for consistent output.
    return sorted(all_findings, key=lambda f: f.severity.value, reverse=True)
