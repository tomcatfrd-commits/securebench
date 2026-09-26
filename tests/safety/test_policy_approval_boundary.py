from __future__ import annotations

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.profile import Profile, ProfileRule
from securebench.policy.classifier import ControlClassifier
from securebench.policy.engine import PolicyEngine
from securebench.policy.rules import (
    ClassificationPolicyRule,
    PolicyDecision,
    RollbackPolicyRule,
)


def make_control(
    control_id: str = "TEST-1",
    *,
    rollback_capability: RollbackCapability = (
        RollbackCapability.GUARANTEED
    ),
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title=f"Control {control_id}",
        description="Test control.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit=f"audit.{control_id}",
        remediation=f"remediation.{control_id}",
        rollback=f"rollback.{control_id}",
        verification=f"verification.{control_id}",
        rollback_capability=rollback_capability,
    )


def make_profile(
    control_id: str,
    *,
    classification: SafetyClassification,
    enabled: bool = True,
    require_approval: bool = False,
    allow_best_effort_rollback: bool = False,
) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={
            control_id: ProfileRule(
                classification=classification,
                enabled=enabled,
                require_approval=require_approval,
            )
        },
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


def make_engine() -> PolicyEngine:
    return PolicyEngine(
        classification_rule=ClassificationPolicyRule(),
        rollback_rule=RollbackPolicyRule(),
    )


def test_approval_required_classification_requires_approval() -> None:
    control = make_control()

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        enabled=True,
        require_approval=True,
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.requires_approval is True
    assert evaluation.can_execute_without_approval is False
    assert evaluation.decision is PolicyDecision.REQUIRE_APPROVAL


def test_approval_required_classification_is_not_automatic_remediation() -> None:
    control = make_control()

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        enabled=True,
        require_approval=True,
    )

    classification = ControlClassifier().classify(
        control=control,
        profile=profile,
    )

    assert classification.automatically_remediable is False
    assert classification.requires_approval is True


def test_safe_classification_does_not_require_approval() -> None:
    control = make_control()

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.SAFE,
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.requires_approval is False
    assert evaluation.can_execute_without_approval is True
    assert evaluation.decision is PolicyDecision.ALLOW


def test_safe_with_precheck_is_not_approval_required() -> None:
    control = make_control()

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.SAFE_WITH_PRECHECK,
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.requires_approval is False
    assert evaluation.requires_precheck is True
    assert evaluation.can_execute_without_approval is False
    assert evaluation.decision is PolicyDecision.REQUIRE_PRECHECK


def test_investigate_is_denied_even_if_enabled_is_attempted() -> None:
    control = make_control()

    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={
            control.control_id: ProfileRule(
                classification=SafetyClassification.INVESTIGATE,
                enabled=False,
            )
        },
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.allowed is False
    assert evaluation.can_execute_without_approval is False
    assert evaluation.decision is PolicyDecision.DENY


def test_prohibited_is_denied() -> None:
    control = make_control()

    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={
            control.control_id: ProfileRule(
                classification=SafetyClassification.PROHIBITED,
                enabled=False,
            )
        },
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.allowed is False
    assert evaluation.requires_approval is False
    assert evaluation.can_execute_without_approval is False
    assert evaluation.decision is PolicyDecision.DENY


def test_best_effort_rollback_does_not_bypass_approval() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        enabled=True,
        require_approval=True,
        allow_best_effort_rollback=True,
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.requires_approval is True
    assert evaluation.can_execute_without_approval is False
    assert evaluation.decision is PolicyDecision.REQUIRE_APPROVAL


def test_unsupported_rollback_denies_execution() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.SAFE,
    )

    evaluation = make_engine().evaluate(
        control=control,
        profile=profile,
    )

    assert evaluation.allowed is False
    assert evaluation.can_execute_without_approval is False
    assert evaluation.decision is PolicyDecision.DENY


def test_approval_requirement_cannot_be_silently_removed() -> None:
    control = make_control()

    profile = make_profile(
        control.control_id,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        enabled=True,
        require_approval=True,
    )

    classification = ControlClassifier().classify(
        control=control,
        profile=profile,
    )

    assert classification.requires_approval is True

    with pytest.raises(AttributeError):
        classification.requires_approval = False  # type: ignore[misc]