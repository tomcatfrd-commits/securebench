"""
Unit tests for remediation profiles.

Profiles define remediation permission independently from benchmark definitions.
These tests verify that profile policy fails closed and that immutable profile
state cannot be modified after construction.
"""

from __future__ import annotations

import pytest

from securebench.core import (
    Profile,
    ProfileRule,
    SafetyClassification,
)


def make_profile(
    *,
    default_classification: SafetyClassification = (
        SafetyClassification.INVESTIGATE
    ),
    rules: dict[str, ProfileRule] | None = None,
    allow_best_effort_rollback: bool = False,
    require_approval_for_unknown: bool = True,
) -> Profile:
    """Create a synthetic remediation profile."""

    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Synthetic profile for unit testing.",
        default_classification=default_classification,
        rules=rules or {},
        allow_best_effort_rollback=allow_best_effort_rollback,
        require_approval_for_unknown=require_approval_for_unknown,
    )


def test_profile_rule_safe_is_automatically_remediable() -> None:
    """An enabled safe rule may enter automatic remediation."""

    profile = make_profile(
        rules={
            "TEST-001": ProfileRule(
                classification=SafetyClassification.SAFE,
                enabled=True,
                require_approval=False,
            ),
        },
    )

    assert profile.allows_automatic_remediation("TEST-001") is True


def test_profile_rule_safe_with_precheck_is_automatically_remediable() -> None:
    """
    safe_with_precheck is eligible for automation, but the policy engine must
    later require the declared prechecks.
    """

    profile = make_profile(
        rules={
            "TEST-001": ProfileRule(
                classification=SafetyClassification.SAFE_WITH_PRECHECK,
                enabled=True,
                require_approval=False,
            ),
        },
    )

    assert profile.allows_automatic_remediation("TEST-001") is True


def test_disabled_safe_rule_cannot_be_remediated() -> None:
    """A disabled rule overrides an otherwise safe classification."""

    profile = make_profile(
        rules={
            "TEST-001": ProfileRule(
                classification=SafetyClassification.SAFE,
                enabled=False,
                require_approval=False,
            ),
        },
    )

    assert profile.allows_automatic_remediation("TEST-001") is False


def test_investigate_rule_cannot_be_remediated() -> None:
    """Investigate controls must not enter automatic remediation."""

    profile = make_profile(
        rules={
            "TEST-001": ProfileRule(
                classification=SafetyClassification.INVESTIGATE,
                enabled=False,
                require_approval=False,
            ),
        },
    )

    assert profile.allows_automatic_remediation("TEST-001") is False


def test_approval_required_rule_cannot_be_remediated_automatically() -> None:
    """
    Approval-required controls may proceed through an approval workflow but
    cannot execute automatically.
    """

    profile = make_profile(
        rules={
            "TEST-001": ProfileRule(
                classification=SafetyClassification.APPROVAL_REQUIRED,
                enabled=False,
                require_approval=True,
            ),
        },
    )

    rule = profile.rule_for("TEST-001")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.require_approval is True
    assert profile.allows_automatic_remediation("TEST-001") is False


def test_prohibited_rule_cannot_be_enabled() -> None:
    """Prohibited controls cannot be enabled for remediation."""

    with pytest.raises(
        ValueError,
        match="prohibited controls cannot be enabled",
    ):
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=True,
            require_approval=False,
        )


def test_prohibited_rule_cannot_require_approval() -> None:
    """
    Prohibited means no remediation workflow is permitted, including an
    approval-based remediation path.
    """

    with pytest.raises(
        ValueError,
        match="prohibited controls cannot require approval",
    ):
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=False,
            require_approval=True,
        )


def test_prohibited_rule_is_disabled() -> None:
    """A valid prohibited rule is necessarily disabled."""

    rule = ProfileRule(
        classification=SafetyClassification.PROHIBITED,
        enabled=False,
        require_approval=False,
    )

    assert rule.enabled is False
    assert rule.require_approval is False


def test_unknown_control_requires_approval_by_default() -> None:
    """
    The production-safe default must fail closed for controls without an
    explicit rule.
    """

    profile = make_profile()

    rule = profile.rule_for("UNKNOWN-001")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True

    assert profile.allows_automatic_remediation(
        "UNKNOWN-001",
    ) is False


def test_unknown_control_can_remain_investigate_when_configured() -> None:
    """
    Profiles may explicitly choose investigation rather than approval for
    unknown controls.
    """

    profile = make_profile(
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN-001")

    assert rule.classification is SafetyClassification.INVESTIGATE
    assert rule.enabled is False
    assert rule.require_approval is False


def test_safe_default_can_be_used_when_explicitly_configured() -> None:
    """
    A profile may define a safe default.

    This is intentionally opt-in; the production-safe profile does not use
    this configuration.
    """

    profile = make_profile(
        default_classification=SafetyClassification.SAFE,
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN-001")

    assert rule.classification is SafetyClassification.SAFE
    assert rule.enabled is True
    assert rule.require_approval is False

    assert profile.allows_automatic_remediation(
        "UNKNOWN-001",
    ) is True


def test_safe_with_precheck_default_can_be_used() -> None:
    """A profile may require prechecks for its default classification."""

    profile = make_profile(
        default_classification=SafetyClassification.SAFE_WITH_PRECHECK,
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN-001")

    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert rule.enabled is True
    assert rule.require_approval is False


def test_approval_required_default_requires_approval() -> None:
    """An approval-required default produces an approval workflow."""

    profile = make_profile(
        default_classification=SafetyClassification.APPROVAL_REQUIRED,
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN-001")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is True
    assert rule.require_approval is True

    assert profile.allows_automatic_remediation(
        "UNKNOWN-001",
    ) is False


def test_prohibited_default_is_disabled() -> None:
    """A prohibited profile default cannot authorize remediation."""

    profile = make_profile(
        default_classification=SafetyClassification.PROHIBITED,
    )

    rule = profile.rule_for("UNKNOWN-001")

    assert rule.classification is SafetyClassification.PROHIBITED
    assert rule.enabled is False
    assert rule.require_approval is False

    assert profile.allows_automatic_remediation(
        "UNKNOWN-001",
    ) is False


def test_explicit_rule_overrides_default_classification() -> None:
    """Explicit control policy takes precedence over the profile default."""

    profile = make_profile(
        default_classification=SafetyClassification.INVESTIGATE,
        rules={
            "TEST-001": ProfileRule(
                classification=SafetyClassification.SAFE,
            ),
        },
    )

    rule = profile.rule_for("TEST-001")

    assert rule.classification is SafetyClassification.SAFE
    assert profile.allows_automatic_remediation("TEST-001") is True


def test_profile_rules_are_immutable() -> None:
    """The profile must not expose a mutable rule dictionary."""

    original_rules = {
        "TEST-001": ProfileRule(
            classification=SafetyClassification.SAFE,
        ),
    }

    profile = make_profile(
        rules=original_rules,
    )

    assert profile.rules["TEST-001"] is original_rules["TEST-001"]

    with pytest.raises(
        TypeError,
    ):
        profile.rules["TEST-002"] = ProfileRule(  # type: ignore[index]
            classification=SafetyClassification.SAFE,
        )


def test_original_rule_mapping_cannot_mutate_profile() -> None:
    """Mutating the source mapping after construction cannot affect Profile."""

    original_rules = {
        "TEST-001": ProfileRule(
            classification=SafetyClassification.SAFE,
        ),
    }

    profile = make_profile(
        rules=original_rules,
    )

    original_rules["TEST-002"] = ProfileRule(
        classification=SafetyClassification.SAFE,
    )

    assert "TEST-002" not in profile.rules
    assert "TEST-001" in profile.rules


def test_profile_is_immutable() -> None:
    """Profile fields cannot be reassigned after construction."""

    profile = make_profile()

    with pytest.raises(
        AttributeError,
    ):
        profile.name = "Modified"  # type: ignore[misc]


def test_empty_control_id_is_rejected() -> None:
    """Profile lookup requires a meaningful control ID."""

    profile = make_profile()

    with pytest.raises(
        ValueError,
        match="control_id must not be empty",
    ):
        profile.rule_for("   ")


def test_invalid_profile_id_is_rejected() -> None:
    """Profile IDs must not be empty."""

    with pytest.raises(
        ValueError,
        match="profile_id must not be empty",
    ):
        Profile(
            profile_id="   ",
            name="Test Profile",
            description="Test",
        )


def test_invalid_profile_name_is_rejected() -> None:
    """Profile names must not be empty."""

    with pytest.raises(
        ValueError,
        match="name must not be empty",
    ):
        Profile(
            profile_id="test-profile",
            name="   ",
            description="Test",
        )


def test_invalid_profile_description_is_rejected() -> None:
    """Profile descriptions must not be empty."""

    with pytest.raises(
        ValueError,
        match="description must not be empty",
    ):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="   ",
        )


def test_best_effort_rollback_setting_must_be_boolean() -> None:
    """Rollback policy configuration must be explicitly boolean."""

    with pytest.raises(
        ValueError,
        match="allow_best_effort_rollback must be boolean",
    ):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test",
            allow_best_effort_rollback="yes",  # type: ignore[arg-type]
        )


def test_unknown_control_setting_must_be_boolean() -> None:
    """Unknown-control approval configuration must be boolean."""

    with pytest.raises(
        ValueError,
        match="require_approval_for_unknown must be boolean",
    ):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test",
            require_approval_for_unknown="yes",  # type: ignore[arg-type]
        )