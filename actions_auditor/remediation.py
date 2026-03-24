"""Remediation advice and reference links for actions_auditor rules.

This module provides a centralised registry that maps rule IDs (e.g. ``'AA001'``)
to structured :class:`RemediationAdvice` objects containing:

- A concise human-readable recommendation.
- A detailed explanation of *why* the fix is necessary.
- One or more reference URLs pointing to official GitHub documentation,
  security advisories, or best-practice guides.
- An optional code snippet showing a corrected example.

Usage::

    from actions_auditor.remediation import get_remediation, REMEDIATION_REGISTRY

    advice = get_remediation("AA001")
    if advice:
        print(advice.recommendation)
        print(advice.references)

The registry is intentionally a plain ``dict`` literal so that it is easy to
read, audit, and extend without any metaprogramming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class RemediationAdvice:
    """Structured remediation guidance for a single security rule.

    Attributes:
        rule_id: The unique identifier of the rule this advice belongs to.
        recommendation: A short, actionable instruction (one or two sentences).
        detail: A longer explanation of *why* the recommendation matters and
            what can go wrong if ignored.
        references: A list of URLs for further reading.
        example_fix: An optional YAML or shell snippet demonstrating the
            corrected configuration.
    """

    rule_id: str
    recommendation: str
    detail: str
    references: List[str] = field(default_factory=list)
    example_fix: Optional[str] = field(default=None)

    def __str__(self) -> str:
        """Return a compact string with rule_id and recommendation."""
        return f"[{self.rule_id}] {self.recommendation}"


# ---------------------------------------------------------------------------
# Remediation registry
# ---------------------------------------------------------------------------
# Each entry maps a rule_id string to a RemediationAdvice instance.
# Rule IDs follow the pattern AA<NNN>.

REMEDIATION_REGISTRY: Dict[str, RemediationAdvice] = {
    # ------------------------------------------------------------------
    # AA001 – Overly permissive GITHUB_TOKEN (write-all)
    # ------------------------------------------------------------------
    "AA001": RemediationAdvice(
        rule_id="AA001",
        recommendation=(
            "Replace 'permissions: write-all' with an explicit, least-privilege "
            "permissions block listing only the specific scopes your workflow needs."
        ),
        detail=(
            "Granting write-all permissions to the GITHUB_TOKEN gives every job in "
            "the workflow write access to all repository resources (code, issues, "
            "packages, secrets, etc.). If any step in the workflow executes attacker-"
            "controlled code (e.g., via a malicious PR), the token can be used to "
            "push malicious commits, approve pull requests, or exfiltrate secrets. "
            "GitHub's default behaviour already restricts token permissions for "
            "workflows triggered by fork pull requests; explicitly tightening scopes "
            "extends this protection to all trigger types."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
            "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions",
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        ],
        example_fix=(
            "# Instead of:\n"
            "permissions: write-all\n\n"
            "# Use an explicit, minimal scope set:\n"
            "permissions:\n"
            "  contents: read\n"
            "  pull-requests: write\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA002 – Missing top-level permissions declaration
    # ------------------------------------------------------------------
    "AA002": RemediationAdvice(
        rule_id="AA002",
        recommendation=(
            "Add an explicit top-level 'permissions' block to restrict the "
            "GITHUB_TOKEN to the minimum set of scopes required by the workflow."
        ),
        detail=(
            "When no 'permissions' key is present, GitHub grants the token the "
            "default permissions configured for the organisation or repository "
            "(which may include broad write access). Declaring permissions explicitly "
            "ensures that the principle of least privilege is enforced regardless of "
            "the repository's default settings and makes the intended access surface "
            "visible to code reviewers."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
            "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions",
            "https://github.blog/changelog/2021-04-20-github-actions-control-permissions-for-github_token/",
        ],
        example_fix=(
            "# Add a top-level permissions block (read-only baseline):\n"
            "permissions:\n"
            "  contents: read\n\n"
            "# Then grant additional write scopes only to jobs that need them:\n"
            "jobs:\n"
            "  deploy:\n"
            "    permissions:\n"
            "      contents: write\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA003 – Secret exposed in environment variable
    # ------------------------------------------------------------------
    "AA003": RemediationAdvice(
        rule_id="AA003",
        recommendation=(
            "Avoid embedding raw '${{ secrets.* }}' expressions in top-level or "
            "job-level 'env' blocks; pass secrets directly to the steps that need "
            "them using step-level 'env' and prefer dedicated secret-passing "
            "mechanisms (e.g., 'with' inputs for actions)."
        ),
        detail=(
            "Secrets exposed as environment variables are available to all commands "
            "in a job, including third-party actions that may log, transmit, or "
            "otherwise exfiltrate them. Narrowing secret exposure to the individual "
            "step that requires it reduces the blast radius if a supply-chain attack "
            "occurs. Additionally, avoid using secrets in contexts where they can "
            "appear in logs (e.g., echoing environment variables in 'run' steps)."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets",
            "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
            "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idenv",
        ],
        example_fix=(
            "# Instead of exposing the secret at the job level:\n"
            "jobs:\n"
            "  build:\n"
            "    env:\n"
            "      API_KEY: ${{ secrets.API_KEY }}  # ← available to ALL steps\n\n"
            "# Scope it to the step that needs it:\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - name: Call API\n"
            "        run: curl -H \"Authorization: $API_KEY\" https://api.example.com\n"
            "        env:\n"
            "          API_KEY: ${{ secrets.API_KEY }}  # ← limited to this step\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA004 – Secret interpolated directly in run script
    # ------------------------------------------------------------------
    "AA004": RemediationAdvice(
        rule_id="AA004",
        recommendation=(
            "Do not interpolate '${{ secrets.* }}' expressions directly inside "
            "'run' scripts. Instead, pass the secret via a step-level 'env' variable "
            "and reference that variable in the shell script."
        ),
        detail=(
            "When a secret is embedded directly in a 'run' step using expression "
            "syntax (e.g., 'run: curl -u ${{ secrets.TOKEN }}'), the secret value "
            "is substituted into the script text before the runner executes it. This "
            "means the secret can appear in error messages, debug output, and "
            "potentially in the Actions log if the runner's log-masking logic fails. "
            "Using an environment variable keeps the secret out of the script source "
            "and allows the runner to mask it more reliably."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets",
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
        ],
        example_fix=(
            "# Avoid direct interpolation in run scripts:\n"
            "# run: echo ${{ secrets.MY_TOKEN }}  # ← dangerous\n\n"
            "# Instead, use a step env variable:\n"
            "- name: Use token\n"
            "  run: echo \"$MY_TOKEN\"\n"
            "  env:\n"
            "    MY_TOKEN: ${{ secrets.MY_TOKEN }}\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA005 – Third-party action not pinned to a full commit SHA
    # ------------------------------------------------------------------
    "AA005": RemediationAdvice(
        rule_id="AA005",
        recommendation=(
            "Pin every third-party 'uses:' reference to a full 40-character commit "
            "SHA instead of a mutable tag or branch name (e.g., "
            "'uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' "
            "instead of 'uses: actions/checkout@v4')."
        ),
        detail=(
            "Referencing an action by a tag or branch (e.g., '@v3', '@main') allows "
            "the action's author — or an attacker who has compromised the action's "
            "repository — to silently change the code that runs in your workflow "
            "without updating the reference. Pinning to a specific commit SHA ensures "
            "that exactly the audited version of the action is always used. Use a "
            "tool such as 'pin-github-action' or 'Dependabot' to keep pinned SHAs "
            "up-to-date automatically."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
            "https://securitylab.github.com/research/github-actions-building-blocks/",
            "https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot",
            "https://github.com/mheap/pin-github-action",
        ],
        example_fix=(
            "# Unsafe – tag can be moved at any time:\n"
            "- uses: actions/checkout@v4\n\n"
            "# Safe – pinned to a specific commit SHA:\n"
            "- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA006 – pull_request_target with head ref checkout
    # ------------------------------------------------------------------
    "AA006": RemediationAdvice(
        rule_id="AA006",
        recommendation=(
            "Never check out the PR head ref (e.g., 'ref: ${{ github.event.pull_request.head.sha }}')"
            " in a workflow triggered by 'pull_request_target'. If you need to run "
            "code from the PR, use the 'pull_request' trigger instead, which does "
            "not grant elevated GITHUB_TOKEN permissions."
        ),
        detail=(
            "The 'pull_request_target' trigger runs in the context of the *base* "
            "repository (not the fork), which means the GITHUB_TOKEN has write "
            "permissions and secrets are accessible. When such a workflow also checks "
            "out the PR's head commit — effectively running attacker-controlled code "
            "in a privileged context — it creates a direct path to repository "
            "compromise. This exact pattern was the root cause of several high-profile "
            "CI/CD supply-chain incidents in 2021. If labelling or commenting on PRs "
            "from forks is required, use a two-workflow split: a first workflow on "
            "'pull_request' saves artefacts, and a second on 'workflow_run' consumes "
            "them with elevated permissions without checking out PR code."
        ),
        references=[
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
            "https://github.blog/2021-04-22-github-actions-maintainers-must-approve-first-time-contributor-workflow-runs/",
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
        ],
        example_fix=(
            "# DANGEROUS pattern – do not use:\n"
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}  # ← attacker code!\n\n"
            "# SAFE alternative: use 'pull_request' trigger (limited permissions):\n"
            "on: pull_request\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA007 – Script injection from untrusted context
    # ------------------------------------------------------------------
    "AA007": RemediationAdvice(
        rule_id="AA007",
        recommendation=(
            "Do not interpolate GitHub context values (e.g., "
            "'${{ github.event.issue.title }}') directly into 'run' scripts. "
            "Pass them through environment variables so the shell treats them "
            "as data, not executable code."
        ),
        detail=(
            "When user-controlled values such as PR titles, branch names, or issue "
            "bodies are interpolated directly into a shell 'run' command using the "
            "expression syntax '${{ ... }}', an attacker can craft a PR or issue "
            "whose title/body contains shell metacharacters to execute arbitrary "
            "commands in the context of the workflow runner. This is a classic "
            "server-side template injection / command injection vulnerability. The "
            "safe pattern is to assign the context value to an environment variable "
            "and reference that variable in the script; the shell then treats the "
            "variable's contents as a string rather than executable code."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
            "https://securitylab.github.com/research/github-actions-untrusted-input/",
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#good-practices-for-mitigating-script-injection-attacks",
        ],
        example_fix=(
            "# DANGEROUS – attacker-controlled value injected into shell:\n"
            "- run: echo \"PR title: ${{ github.event.pull_request.title }}\"\n\n"
            "# SAFE – pass through env variable:\n"
            "- run: echo \"PR title: $PR_TITLE\"\n"
            "  env:\n"
            "    PR_TITLE: ${{ github.event.pull_request.title }}\n"
        ),
    ),
    # ------------------------------------------------------------------
    # AA008 – Workflow dispatch input used as script argument
    # ------------------------------------------------------------------
    "AA008": RemediationAdvice(
        rule_id="AA008",
        recommendation=(
            "Do not embed 'workflow_dispatch' input values directly in 'run' "
            "scripts. Use an environment variable intermediary so the shell "
            "cannot interpret the input as code."
        ),
        detail=(
            "'workflow_dispatch' inputs are supplied by whoever manually triggers "
            "the workflow (including automated systems that call the API). If an "
            "input value is directly interpolated into a shell command via "
            "'${{ inputs.<name> }}', a malicious actor with permission to trigger "
            "workflows can inject shell commands. Even for internal workflows, "
            "defence-in-depth suggests treating all external input as untrusted."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
            "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_dispatch",
        ],
        example_fix=(
            "# DANGEROUS:\n"
            "- run: deploy.sh ${{ inputs.environment }}\n\n"
            "# SAFE:\n"
            "- run: deploy.sh \"$DEPLOY_ENV\"\n"
            "  env:\n"
            "    DEPLOY_ENV: ${{ inputs.environment }}\n"
        ),
    ),
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_remediation(rule_id: str) -> Optional[RemediationAdvice]:
    """Look up remediation advice for a given rule ID.

    Args:
        rule_id: The rule identifier string (e.g. ``'AA001'``).

    Returns:
        A :class:`RemediationAdvice` instance if the rule is known, or
        ``None`` if no advice is registered for *rule_id*.
    """
    return REMEDIATION_REGISTRY.get(rule_id)


def get_remediation_or_default(rule_id: str) -> RemediationAdvice:
    """Return registered advice for *rule_id*, or a generic fallback.

    Unlike :func:`get_remediation`, this function always returns a
    :class:`RemediationAdvice` instance — useful in contexts where the caller
    cannot easily handle ``None``.

    Args:
        rule_id: The rule identifier string.

    Returns:
        The registered :class:`RemediationAdvice`, or a generic advice object
        pointing to the GitHub Actions security-hardening guide.
    """
    advice = REMEDIATION_REGISTRY.get(rule_id)
    if advice is not None:
        return advice
    return RemediationAdvice(
        rule_id=rule_id,
        recommendation=(
            "Review the flagged configuration against GitHub Actions security "
            "best practices and apply the principle of least privilege."
        ),
        detail=(
            "No specific remediation guidance is registered for this rule. "
            "Refer to the GitHub Actions security hardening guide for general "
            "recommendations."
        ),
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        ],
    )


def list_rule_ids() -> List[str]:
    """Return a sorted list of all rule IDs that have registered remediation advice.

    Returns:
        A sorted list of rule ID strings.
    """
    return sorted(REMEDIATION_REGISTRY.keys())


def format_advice(advice: RemediationAdvice, include_example: bool = True) -> str:
    """Format a :class:`RemediationAdvice` as a plain-text multi-line string.

    Args:
        advice: The advice to format.
        include_example: When ``True`` (the default), the example fix snippet
            is appended if one is available.

    Returns:
        A formatted multi-line string suitable for terminal display.
    """
    lines: List[str] = [
        f"Rule: {advice.rule_id}",
        f"Recommendation: {advice.recommendation}",
        "",
        "Detail:",
        advice.detail,
    ]

    if advice.references:
        lines.append("")
        lines.append("References:")
        for ref in advice.references:
            lines.append(f"  - {ref}")

    if include_example and advice.example_fix:
        lines.append("")
        lines.append("Example fix:")
        for fix_line in advice.example_fix.splitlines():
            lines.append(f"  {fix_line}")

    return "\n".join(lines)
