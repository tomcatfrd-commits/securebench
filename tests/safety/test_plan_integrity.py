from __future__ import annotations

import pytest

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


def make_policy_engine() -> PolicyEngine:
    return PolicyEngine(
        classification_rule=ClassificationPolicyRule(),
        rollback_rule=RollbackPolicyRule(),
    )


def make_profile(control_id: str) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={
            control_id: ProfileRule(
                classification=SafetyClassification.SAFE,
                enabled=True,
            )
        },
    )


def test_passed_control_is_never_planned_for_remediation() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.PASS,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    plan = planner.plan(
        audits=(audit,),
        evaluations=(evaluation,),
    )

    assert plan.items == ()


def test_failed_safe_control_enters_remediation_plan() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    plan = planner.plan(
        audits=(audit,),
        evaluations=(evaluation,),
    )

    assert len(plan.items) == 1
    assert plan.items[0].control is control
    assert plan.items[0].action is PlanAction.REMEDIATE


def test_unknown_audit_status_does_not_enter_remediation() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.UNKNOWN,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    plan = planner.plan(
        audits=(audit,),
        evaluations=(evaluation,),
    )

    assert plan.items == ()


def test_missing_policy_evaluation_fails_closed() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    with pytest.raises(Exception):
        planner.plan(
            audits=(audit,),
            evaluations=(),
        )


def test_missing_audit_result_fails_closed() -> None:
    control = make_control()

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    with pytest.raises(Exception):
        planner.plan(
            audits=(),
            evaluations=(evaluation,),
        )


def test_duplicate_audit_results_fail_closed() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    with pytest.raises(Exception):
        planner.plan(
            audits=(audit, audit),
            evaluations=(evaluation,),
        )


def test_duplicate_policy_evaluations_fail_closed() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    with pytest.raises(Exception):
        planner.plan(
            audits=(audit,),
            evaluations=(evaluation, evaluation),
        )


def test_plan_items_are_immutable() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    plan = planner.plan(
        audits=(audit,),
        evaluations=(evaluation,),
    )

    item = plan.items[0]

    with pytest.raises(AttributeError):
        item.reason = "modified"  # type: ignore[misc]


def test_plan_does_not_mutate_control() -> None:
    control = make_control()

    original = (
        control.control_id,
        control.dependencies,
        control.conflicts,
        control.metadata,
    )

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )

    evaluation = make_policy_engine().evaluate(
        control=control,
        profile=make_profile(control.control_id),
    )

    planner = RemediationPlanner(
        policy_engine=make_policy_engine(),
    )

    planner.plan(
        audits=(audit,),
        evaluations=(evaluation,),
    )

    assert (
        control.control_id,
        control.dependencies,
        control.conflicts,
        control.metadata,
    ) == original