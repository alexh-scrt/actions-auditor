"""Unit tests for the remediation module (actions_auditor.remediation).

Covers:
- RemediationAdvice dataclass construction and properties
- REMEDIATION_REGISTRY completeness and content
- get_remediation() lookup function
- get_remediation_or_default() fallback behaviour
- list_rule_ids() ordering
- format_advice() output formatting
"""

from __future__ import annotations

import pytest

from actions_auditor.remediation import (
    REMEDIATION_REGISTRY,
    RemediationAdvice,
    format_advice,
    get_remediation,
    get_remediation_or_default,
    list_rule_ids,
)


# ---------------------------------------------------------------------------
# Expected rule IDs – update this list when new rules are added
# ---------------------------------------------------------------------------

EXPECTED_RULE_IDS = {"AA001", "AA002", "AA003", "AA004", "AA005", "AA006", "AA007", "AA008"}


# ---------------------------------------------------------------------------
# RemediationAdvice dataclass tests
# ---------------------------------------------------------------------------


class TestRemediationAdvice:
    """Tests for the RemediationAdvice dataclass."""

    def test_construction_required_fields(self) -> None:
        advice = RemediationAdvice(
            rule_id="AA999",
            recommendation="Do something.",
            detail="Because reasons.",
        )
        assert advice.rule_id == "AA999"
        assert advice.recommendation == "Do something."
        assert advice.detail == "Because reasons."
        assert advice.references == []
        assert advice.example_fix is None

    def test_construction_all_fields(self) -> None:
        advice = RemediationAdvice(
            rule_id="AA000",
            recommendation="Fix it.",
            detail="Long explanation.",
            references=["https://example.com"],
            example_fix="# example",
        )
        assert advice.references == ["https://example.com"]
        assert advice.example_fix == "# example"

    def test_frozen_immutability(self) -> None:
        advice = RemediationAdvice(
            rule_id="AA999",
            recommendation="rec",
            detail="det",
        )
        with pytest.raises((AttributeError, TypeError)):
            advice.rule_id = "CHANGED"  # type: ignore[misc]

    def test_str_representation(self) -> None:
        advice = RemediationAdvice(
            rule_id="AA001",
            recommendation="Use least privilege.",
            detail="detail",
        )
        s = str(advice)
        assert "AA001" in s
        assert "Use least privilege." in s


# ---------------------------------------------------------------------------
# REMEDIATION_REGISTRY tests
# ---------------------------------------------------------------------------


class TestRemediationRegistry:
    """Tests for the REMEDIATION_REGISTRY constant."""

    def test_all_expected_rule_ids_present(self) -> None:
        for rule_id in EXPECTED_RULE_IDS:
            assert rule_id in REMEDIATION_REGISTRY, f"Missing rule: {rule_id}"

    def test_each_entry_is_remediation_advice(self) -> None:
        for rule_id, advice in REMEDIATION_REGISTRY.items():
            assert isinstance(
                advice, RemediationAdvice
            ), f"{rule_id} entry is not a RemediationAdvice"

    def test_rule_id_key_matches_advice_rule_id(self) -> None:
        for key, advice in REMEDIATION_REGISTRY.items():
            assert advice.rule_id == key, (
                f"Key '{key}' does not match advice.rule_id '{advice.rule_id}'"
            )

    def test_each_recommendation_is_non_empty(self) -> None:
        for rule_id, advice in REMEDIATION_REGISTRY.items():
            assert advice.recommendation.strip(), (
                f"Rule {rule_id} has an empty recommendation"
            )

    def test_each_detail_is_non_empty(self) -> None:
        for rule_id, advice in REMEDIATION_REGISTRY.items():
            assert advice.detail.strip(), (
                f"Rule {rule_id} has an empty detail"
            )

    def test_each_entry_has_at_least_one_reference(self) -> None:
        for rule_id, advice in REMEDIATION_REGISTRY.items():
            assert len(advice.references) >= 1, (
                f"Rule {rule_id} has no references"
            )

    def test_references_are_valid_urls(self) -> None:
        for rule_id, advice in REMEDIATION_REGISTRY.items():
            for ref in advice.references:
                assert ref.startswith("https://"), (
                    f"Rule {rule_id} has a non-HTTPS reference: {ref}"
                )


# ---------------------------------------------------------------------------
# get_remediation() tests
# ---------------------------------------------------------------------------


class TestGetRemediation:
    """Tests for the get_remediation() function."""

    def test_returns_advice_for_known_rule(self) -> None:
        advice = get_remediation("AA001")
        assert advice is not None
        assert isinstance(advice, RemediationAdvice)
        assert advice.rule_id == "AA001"

    def test_returns_none_for_unknown_rule(self) -> None:
        advice = get_remediation("XX999")
        assert advice is None

    def test_returns_none_for_empty_string(self) -> None:
        advice = get_remediation("")
        assert advice is None

    @pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULE_IDS))
    def test_all_expected_rules_return_advice(self, rule_id: str) -> None:
        advice = get_remediation(rule_id)
        assert advice is not None, f"get_remediation('{rule_id}') returned None"


# ---------------------------------------------------------------------------
# get_remediation_or_default() tests
# ---------------------------------------------------------------------------


class TestGetRemediationOrDefault:
    """Tests for the get_remediation_or_default() function."""

    def test_returns_registered_advice_for_known_rule(self) -> None:
        advice = get_remediation_or_default("AA001")
        assert advice.rule_id == "AA001"
        assert advice is REMEDIATION_REGISTRY["AA001"]

    def test_returns_fallback_for_unknown_rule(self) -> None:
        advice = get_remediation_or_default("UNKNOWN_RULE")
        assert isinstance(advice, RemediationAdvice)
        assert advice.rule_id == "UNKNOWN_RULE"
        assert len(advice.recommendation) > 0
        assert len(advice.references) >= 1

    def test_fallback_never_returns_none(self) -> None:
        result = get_remediation_or_default("")
        assert result is not None
        assert isinstance(result, RemediationAdvice)


# ---------------------------------------------------------------------------
# list_rule_ids() tests
# ---------------------------------------------------------------------------


class TestListRuleIds:
    """Tests for the list_rule_ids() function."""

    def test_returns_list(self) -> None:
        result = list_rule_ids()
        assert isinstance(result, list)

    def test_all_expected_ids_present(self) -> None:
        ids = set(list_rule_ids())
        assert EXPECTED_RULE_IDS.issubset(ids)

    def test_list_is_sorted(self) -> None:
        ids = list_rule_ids()
        assert ids == sorted(ids)

    def test_no_duplicates(self) -> None:
        ids = list_rule_ids()
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# format_advice() tests
# ---------------------------------------------------------------------------


class TestFormatAdvice:
    """Tests for the format_advice() function."""

    def _sample_advice(self, with_example: bool = True) -> RemediationAdvice:
        return RemediationAdvice(
            rule_id="AA001",
            recommendation="Do the right thing.",
            detail="Because security matters.",
            references=["https://docs.example.com", "https://blog.example.com"],
            example_fix="# Good example\npermissions: read-all" if with_example else None,
        )

    def test_output_is_string(self) -> None:
        advice = self._sample_advice()
        result = format_advice(advice)
        assert isinstance(result, str)

    def test_output_contains_rule_id(self) -> None:
        advice = self._sample_advice()
        result = format_advice(advice)
        assert "AA001" in result

    def test_output_contains_recommendation(self) -> None:
        advice = self._sample_advice()
        result = format_advice(advice)
        assert "Do the right thing." in result

    def test_output_contains_detail(self) -> None:
        advice = self._sample_advice()
        result = format_advice(advice)
        assert "Because security matters." in result

    def test_output_contains_references(self) -> None:
        advice = self._sample_advice()
        result = format_advice(advice)
        assert "https://docs.example.com" in result
        assert "https://blog.example.com" in result

    def test_output_contains_example_when_present(self) -> None:
        advice = self._sample_advice(with_example=True)
        result = format_advice(advice, include_example=True)
        assert "Good example" in result

    def test_output_omits_example_when_disabled(self) -> None:
        advice = self._sample_advice(with_example=True)
        result = format_advice(advice, include_example=False)
        assert "Good example" not in result

    def test_output_omits_example_section_when_none(self) -> None:
        advice = self._sample_advice(with_example=False)
        result = format_advice(advice, include_example=True)
        assert "Example fix" not in result

    def test_aa001_formatted_output_has_content(self) -> None:
        advice = get_remediation("AA001")
        assert advice is not None
        result = format_advice(advice)
        assert len(result) > 100  # Should be a substantive block of text
