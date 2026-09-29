from __future__ import annotations

from securebench.core import (
    AuditResult,
    ComplianceStatus,
    Control,
    ControlSeverity,
    Profile,
    ProfileRule,
    RollbackCapability,
    SafetyClassification,
)
from securebench.policy.classifier import ControlClassifier
from securebench.policy.engine import PolicyEngine
from securebench.remediation.planner import PlanAction, RemediationPlanner


def make_control(
    control_id: str = "TEST-1",
    *,
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="audit.test",
        remediation="remediation.test",
        rollback="rollback.test",
        verification="verification.test",
        rollback_capability=rollback_capability,
    )


def make_profile(
    classification: SafetyClassification,
    *,
    enabled: bool = True,
    require_approval: bool = False,
    allow_best_effort_rollback: bool = False,
) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        default_classification=SafetyClassification.INVESTIGATE,
        rules={
            "TEST-1": ProfileRule(
                classification=classification,
                enabled=enabled,
                require_approval=require_approval,
            )
        },
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


def make_audit(
    *,
    status: ComplianceStatus,
    control_id: str = "TEST-1",
    host: str = "production-01",
) -> AuditResult:
    return AuditResult(
        control_id=control_id,
        host=host,
        status=status,
        evidence=(),
    )


def evaluate(
    control: Control,
    profile: Profile,
):
    return PolicyEngine().evaluate(control, profile)


def plan_for(
    control: Control,
    profile: Profile,
    audit: AuditResult,
):
    policy_engine = PolicyEngine()
    planner = RemediationPlanner(policy_engine=policy_engine)

    evaluation = policy_engine.evaluate(control, profile)

    return evaluation, planner.plan(
        (audit,),
        (evaluation,),
    )


def test_safe_control_is_allowed_and_becomes_remediation() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.FAIL),
    )

    assert evaluation.allowed is True
    assert evaluation.can_execute_without_approval is True
    assert evaluation.requires_precheck is False
    assert evaluation.requires_approval is False
    assert plan.items[0].action is PlanAction.REMEDIATE


def test_safe_with_precheck_is_allowed_but_requires_precheck() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE_WITH_PRECHECK)

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.FAIL),
    )

    assert evaluation.allowed is True
    assert evaluation.requires_precheck is True
    assert evaluation.can_execute_without_approval is False
    assert plan.items[0].action is PlanAction.PRECHECK


def test_approval_required_never_becomes_direct_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.APPROVAL_REQUIRED,
        require_approval=True,
    )

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.FAIL),
    )

    assert evaluation.allowed is True
    assert evaluation.requires_approval is True
    assert evaluation.can_execute_without_approval is False
    assert plan.items[0].action is PlanAction.APPROVAL_REQUIRED


def test_investigate_control_is_blocked() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.INVESTIGATE,
        enabled=False,
    )

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.FAIL),
    )

    assert evaluation.allowed is False
    assert evaluation.can_execute_without_approval is False
    assert plan.items[0].action is PlanAction.INVESTIGATE


def test_prohibited_control_is_blocked() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.PROHIBITED,
        enabled=False,
    )

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.FAIL),
    )

    assert evaluation.allowed is False
    assert evaluation.can_execute_without_approval is False
    assert plan.items[0].action is PlanAction.INVESTIGATE


def test_best_effort_rollback_is_denied_by_default() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )
    profile = make_profile(SafetyClassification.SAFE)

    evaluation = evaluate(control, profile)

    assert evaluation.allowed is False


def test_best_effort_rollback_requires_explicit_profile_permission() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )
    profile = make_profile(
        SafetyClassification.SAFE,
        allow_best_effort_rollback=True,
    )

    evaluation = evaluate(control, profile)

    assert evaluation.allowed is True
    assert evaluation.can_execute_without_approval is True


def test_unsupported_rollback_blocks_automatic_remediation() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )
    profile = make_profile(SafetyClassification.SAFE)

    evaluation = evaluate(control, profile)

    assert evaluation.allowed is False
    assert evaluation.can_execute_without_approval is False


def test_policy_deny_takes_precedence_over_precheck() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )
    profile = make_profile(SafetyClassification.SAFE_WITH_PRECHECK)

    evaluation = evaluate(control, profile)

    assert evaluation.allowed is False
    assert evaluation.requires_precheck is False
    assert evaluation.requires_approval is False


def test_policy_preserves_control_identity() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    evaluation = evaluate(control, profile)

    assert evaluation.control is control
    assert evaluation.control_id == control.control_id


def test_investigate_classification_cannot_be_upgraded_by_policy() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.INVESTIGATE,
        enabled=False,
    )

    classification = ControlClassifier().classify(control, profile)

    assert classification.classification is SafetyClassification.INVESTIGATE
    assert classification.automatically_remediable is False


def test_prohibited_classification_cannot_be_upgraded_to_approval() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.PROHIBITED,
        enabled=False,
    )

    classification = ControlClassifier().classify(control, profile)

    assert classification.classification is SafetyClassification.PROHIBITED
    assert classification.requires_approval is False
    assert classification.automatically_remediable is False


def test_compliant_control_is_skipped_even_when_policy_allows_remediation() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.PASS),
    )

    assert evaluation.allowed is True
    assert plan.items == ()


def test_unknown_audit_status_never_becomes_remediation() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    evaluation, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.UNKNOWN),
    )

    assert evaluation.allowed is True
    assert plan.items == ()


def test_failed_audit_is_required_for_remediation() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    _, plan = plan_for(
        control,
        profile,
        make_audit(status=ComplianceStatus.FAIL),
    )

    assert plan.items[0].action is PlanAction.REMEDIATE


def test_policy_evaluation_does_not_execute_remediation() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    evaluation = evaluate(control, profile)

    assert evaluation.allowed is True
    assert evaluation.decision.value == "allow"
