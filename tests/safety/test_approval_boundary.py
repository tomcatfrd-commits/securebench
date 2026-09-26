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
from securebench.policy.rules import (
    ClassificationPolicyRule,
    RollbackPolicyRule,
)
from securebench.remediation.planner import (
    PlanAction,
    RemediationPlanner,
)


def make_control(control_id: str = "TEST-1") -> Control:
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
        rollback_capability=RollbackCapability.GUARANTEED,
    )


def make_engine() -> PolicyEngine:
    return PolicyEngine(
        classification_rule=ClassificationPolicyRule(),
        rollback_rule=RollbackPolicyRule(),
    )


def make_audit(control: Control) -> AuditResult:
    return AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )


def make_plan(
    control: Control,
    *,
    classification: SafetyClassification,
    require_approval: bool,
) -> object:
    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={
            control.control_id: ProfileRule(
                classification=classification,
                enabled=classification
                not in {
                    SafetyClassification.INVESTIGATE,
                    SafetyClassification.PROHIBITED,
                },
                require_approval=require_approval,
            )
        },
    )

    engine = make_engine()

    evaluation = engine.evaluate(
        control=control,
        profile=profile,
    )

    planner = RemediationPlanner(
        policy_engine=engine,
    )

    return planner.plan(
        audits=(make_audit(control),),
        evaluations=(evaluation,),
    )


def test_approval_required_control_never_becomes_remediate() -> None:
    control = make_control()

    plan = make_plan(
        control,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        require_approval=True,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action is PlanAction.APPROVAL_REQUIRED
    assert plan.items[0].requires_approval is True


def test_approval_required_control_is_not_executable() -> None:
    control = make_control()

    plan = make_plan(
        control,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        require_approval=True,
    )

    assert plan.executable_items == ()


def test_approval_required_control_is_explicitly_listed() -> None:
    control = make_control()

    plan = make_plan(
        control,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        require_approval=True,
    )

    assert plan.requires_approval == (plan.items[0],)


def test_investigate_control_cannot_bypass_approval() -> None:
    control = make_control()

    plan = make_plan(
        control,
        classification=SafetyClassification.INVESTIGATE,
        require_approval=False,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action is PlanAction.INVESTIGATE
    assert plan.executable_items == ()


def test_prohibited_control_cannot_bypass_safety_boundary() -> None:
    control = make_control()

    plan = make_plan(
        control,
        classification=SafetyClassification.PROHIBITED,
        require_approval=False,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action is PlanAction.INVESTIGATE
    assert plan.executable_items == ()


def test_safe_control_without_approval_is_remediable() -> None:
    control = make_control()

    plan = make_plan(
        control,
        classification=SafetyClassification.SAFE,
        require_approval=False,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action is PlanAction.REMEDIATE
    assert plan.items[0].requires_approval is False


def test_approval_boundary_does_not_modify_control() -> None:
    control = make_control()

    original = (
        control.control_id,
        control.dependencies,
        control.conflicts,
        control.rollback_capability,
    )

    make_plan(
        control,
        classification=SafetyClassification.APPROVAL_REQUIRED,
        require_approval=True,
    )

    assert (
        control.control_id,
        control.dependencies,
        control.conflicts,
        control.rollback_capability,
    ) == original