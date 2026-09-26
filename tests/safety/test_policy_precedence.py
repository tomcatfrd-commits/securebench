from __future__ import annotations

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.profile import Profile, ProfileRule
from securebench.core.result import AuditResult, ComplianceStatus
from securebench.policy.engine import PolicyEngine
from securebench.policy.rules import PolicyDecision


def make_control(
    *,
    control_id: str = "TEST-1",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="audit.test",
        remediation="remediation.test",
        rollback="rollback.test",
        verification="verification.test",
        rollback_capability=rollback_capability,
    )


def make_profile(
    rule: ProfileRule,
    *,
    control_id: str = "TEST-1",
    allow_best_effort_rollback: bool = False,
) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={control_id: rule},
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


def test_deny_has_highest_precedence() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE,
            enabled=True,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.DENY
    assert evaluation.allowed is False
    assert evaluation.requires_precheck is False
    assert evaluation.requires_approval is False


def test_approval_takes_precedence_over_precheck() -> None:
    control = make_control()

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            enabled=False,
            require_approval=True,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.REQUIRE_APPROVAL
    assert evaluation.allowed is True
    assert evaluation.requires_approval is True
    assert evaluation.requires_precheck is False


def test_precheck_takes_precedence_over_allow() -> None:
    control = make_control()

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
            enabled=True,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.REQUIRE_PRECHECK
    assert evaluation.allowed is True
    assert evaluation.requires_precheck is True
    assert evaluation.requires_approval is False


def test_plain_safe_control_is_allowed() -> None:
    control = make_control()

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE,
            enabled=True,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.ALLOW
    assert evaluation.allowed is True
    assert evaluation.can_execute_without_approval is True


def test_investigate_is_denied() -> None:
    control = make_control()

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.INVESTIGATE,
            enabled=False,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.DENY
    assert evaluation.allowed is False


def test_prohibited_is_denied() -> None:
    control = make_control()

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=False,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.DENY
    assert evaluation.allowed is False


def test_best_effort_rollback_can_override_otherwise_safe_control() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE,
            enabled=True,
        ),
        allow_best_effort_rollback=False,
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.DENY
    assert evaluation.allowed is False


def test_best_effort_rollback_is_allowed_when_profile_enables_it() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE,
            enabled=True,
        ),
        allow_best_effort_rollback=True,
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.ALLOW
    assert evaluation.allowed is True


def test_guaranteed_rollback_does_not_require_best_effort_permission() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.GUARANTEED,
    )

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE,
            enabled=True,
        ),
        allow_best_effort_rollback=False,
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert evaluation.decision is PolicyDecision.ALLOW
    assert evaluation.allowed is True


def test_policy_evaluation_contains_rule_results() -> None:
    control = make_control()

    profile = make_profile(
        ProfileRule(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
            enabled=True,
        )
    )

    evaluation = PolicyEngine().evaluate(control, profile)

    assert len(evaluation.rule_results) == 2

    decisions = {
        result.decision
        for result in evaluation.rule_results
    }

    assert PolicyDecision.REQUIRE_PRECHECK in decisions