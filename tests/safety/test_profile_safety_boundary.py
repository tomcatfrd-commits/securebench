from __future__ import annotations

import pytest

from securebench.core.control import SafetyClassification
from securebench.core.profile import Profile, ProfileRule


def make_profile(
    *,
    default_classification: SafetyClassification = (
        SafetyClassification.INVESTIGATE
    ),
    rules: dict[str, ProfileRule] | None = None,
    require_approval_for_unknown: bool = True,
    allow_best_effort_rollback: bool = False,
) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        default_classification=default_classification,
        rules=rules or {},
        require_approval_for_unknown=require_approval_for_unknown,
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


def test_unknown_control_is_fail_closed_by_default() -> None:
    profile = make_profile()

    rule = profile.rule_for("UNKNOWN")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True
    assert profile.allows_automatic_remediation("UNKNOWN") is False


def test_unknown_control_can_require_explicit_approval() -> None:
    profile = make_profile(
        default_classification=SafetyClassification.INVESTIGATE,
        require_approval_for_unknown=True,
    )

    # The current Profile implementation intentionally converts an unknown
    # investigate control into an approval-required, disabled rule.
    # This is the actual fail-closed behavior exposed by rule_for().
    rule = profile.rule_for("UNKNOWN")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True
    assert profile.allows_automatic_remediation("UNKNOWN") is False


def test_unknown_control_can_follow_investigate_without_approval() -> None:
    profile = make_profile(
        default_classification=SafetyClassification.INVESTIGATE,
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN")

    assert rule.classification is SafetyClassification.INVESTIGATE
    assert rule.enabled is False
    assert rule.require_approval is False
    assert profile.allows_automatic_remediation("UNKNOWN") is False


def test_explicit_rule_overrides_default_classification() -> None:
    profile = make_profile(
        default_classification=SafetyClassification.INVESTIGATE,
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.SAFE,
            )
        },
    )

    rule = profile.rule_for("CONTROL-1")

    assert rule.classification is SafetyClassification.SAFE
    assert rule.enabled is True
    assert rule.require_approval is False
    assert profile.allows_automatic_remediation("CONTROL-1") is True


def test_safe_control_can_be_automatically_remediated() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.SAFE,
            )
        }
    )

    assert profile.allows_automatic_remediation("CONTROL-1") is True


def test_safe_with_precheck_can_be_automatically_remediated() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.SAFE_WITH_PRECHECK,
            )
        }
    )

    assert profile.allows_automatic_remediation("CONTROL-1") is True


def test_disabled_safe_control_cannot_be_automatically_remediated() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.SAFE,
                enabled=False,
            )
        }
    )

    assert profile.allows_automatic_remediation("CONTROL-1") is False


def test_investigate_control_cannot_be_automatically_remediated() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.INVESTIGATE,
                enabled=False,
            )
        }
    )

    assert profile.allows_automatic_remediation("CONTROL-1") is False


def test_approval_required_control_cannot_be_automatically_remediated() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.APPROVAL_REQUIRED,
                enabled=True,
                require_approval=True,
            )
        }
    )

    assert profile.allows_automatic_remediation("CONTROL-1") is False


def test_prohibited_control_cannot_be_automatically_remediated() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.PROHIBITED,
                enabled=False,
                require_approval=False,
            )
        }
    )

    assert profile.allows_automatic_remediation("CONTROL-1") is False


def test_best_effort_rollback_is_disabled_by_default() -> None:
    profile = make_profile()

    assert profile.allow_best_effort_rollback is False


def test_best_effort_rollback_requires_explicit_profile_setting() -> None:
    profile = make_profile(
        allow_best_effort_rollback=True,
    )

    assert profile.allow_best_effort_rollback is True


def test_profile_rules_are_immutable() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.SAFE,
            )
        }
    )

    rule = profile.rule_for("CONTROL-1")

    with pytest.raises(AttributeError):
        rule.enabled = False  # type: ignore[misc]


def test_profile_rule_mapping_is_immutable() -> None:
    profile = make_profile(
        rules={
            "CONTROL-1": ProfileRule(
                classification=SafetyClassification.SAFE,
            )
        }
    )

    with pytest.raises(TypeError):
        profile.rules["CONTROL-2"] = ProfileRule(  # type: ignore[index]
            classification=SafetyClassification.SAFE,
        )


def test_approval_required_rule_must_explicitly_require_approval() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            enabled=True,
            require_approval=False,
        )


def test_prohibited_rule_cannot_be_enabled() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=True,
            require_approval=False,
        )


def test_prohibited_rule_cannot_request_approval() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=False,
            require_approval=True,
        )


def test_investigate_rule_cannot_be_enabled() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.INVESTIGATE,
            enabled=True,
            require_approval=False,
        )


def test_empty_control_id_is_rejected() -> None:
    profile = make_profile()

    with pytest.raises(ValueError):
        profile.rule_for("")


def test_whitespace_control_id_is_rejected() -> None:
    profile = make_profile()

    with pytest.raises(ValueError):
        profile.rule_for("   ")


def test_empty_profile_id_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="",
            name="Test Profile",
            description="Test profile.",
        )


def test_empty_profile_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="",
            description="Test profile.",
        )


def test_empty_profile_description_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="",
        )


def test_invalid_default_classification_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile.",
            default_classification="safe",  # type: ignore[arg-type]
        )


def test_invalid_allow_best_effort_rollback_type_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile.",
            allow_best_effort_rollback="yes",  # type: ignore[arg-type]
        )


def test_invalid_require_approval_for_unknown_type_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile.",
            require_approval_for_unknown="yes",  # type: ignore[arg-type]
        )


def test_invalid_profile_rule_key_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile.",
            rules={
                "": ProfileRule(
                    classification=SafetyClassification.SAFE,
                )
            },
        )


def test_invalid_profile_rule_value_is_rejected() -> None:
    with pytest.raises(ValueError):
        Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile.",
            rules={
                "CONTROL-1": object(),  # type: ignore[arg-type]
            },
        )
