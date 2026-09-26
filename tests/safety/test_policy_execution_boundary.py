from __future__ import annotations

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.profile import Profile, ProfileRule
from securebench.policy.classifier import ControlClassifier
from securebench.policy.engine import PolicyEngine
from securebench.remediation.planner import (
    PlanAction,
    RemediationPlanner,
)
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
)


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


def make_failed_audit() -> AuditResult:
    return AuditResult(
        control_id="TEST-1",
        host="production-01",
        status=ComplianceStatus.FAIL,
        evidence=(),
    )


def test_safe_control_can_enter_remediation_workflow() -> None:
    control = make_control()
    profile = make_profile(SafetyClassification.SAFE)

    classifier = ControlClassifier()
    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    classification = classifier.classify(control, profile)
    evaluation = policy_engine.evaluate(
        control,
        profile,
    )
    plan = planner.plan(
        (
            make_failed_audit(),
        ),
        (
            evaluation,
        ),
    )

    assert classification.automatically_remediable is True
    assert evaluation.allowed is True
    assert plan.items[0].action is PlanAction.REMEDIATE


def test_safe_with_precheck_never_becomes_direct_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.SAFE_WITH_PRECHECK,
    )

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    evaluation = policy_engine.evaluate(
        control,
        profile,
    )
    plan = planner.plan(
        (
            make_failed_audit(),
        ),
        (
            evaluation,
        ),
    )

    assert evaluation.requires_precheck is True
    assert plan.items[0].action is PlanAction.PRECHECK
    assert plan.items[0].action is not PlanAction.REMEDIATE


def test_approval_required_control_never_becomes_direct_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.APPROVAL_REQUIRED,
        require_approval=True,
    )

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    evaluation = policy_engine.evaluate(
        control,
        profile,
    )
    plan = planner.plan(
        (
            make_failed_audit(),
        ),
        (
            evaluation,
        ),
    )

    assert evaluation.requires_approval is True
    assert plan.items[0].action is PlanAction.APPROVAL_REQUIRED
    assert plan.items[0].action is not PlanAction.REMEDIATE


def test_investigate_control_cannot_enter_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.INVESTIGATE,
        enabled=False,
    )

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    evaluation = policy_engine.evaluate(
        control,
        profile,
    )
    plan = planner.plan(
        (
            make_failed_audit(),
        ),
        (
            evaluation,
        ),
    )

    assert evaluation.allowed is False
    assert plan.items[0].action is PlanAction.INVESTIGATE
    assert plan.items[0].action is not PlanAction.REMEDIATE


def test_prohibited_control_cannot_enter_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.PROHIBITED,
        enabled=False,
    )

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    evaluation = policy_engine.evaluate(
        control,
        profile,
    )
    plan = planner.plan(
        (
            make_failed_audit(),
        ),
        (
            evaluation,
        ),
    )

    assert evaluation.allowed is False
    assert plan.items[0].action is PlanAction.INVESTIGATE
    assert plan.items[0].action is not PlanAction.REMEDIATE


def test_best_effort_rollback_is_not_allowed_by_default() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )
    profile = make_profile(
        SafetyClassification.SAFE,
        allow_best_effort_rollback=False,
    )

    evaluation = PolicyEngine().evaluate(
        control,
        profile,
    )

    assert evaluation.allowed is False


def test_best_effort_rollback_requires_explicit_profile_permission() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.BEST_EFFORT,
    )
    profile = make_profile(
        SafetyClassification.SAFE,
        allow_best_effort_rollback=True,
    )

    evaluation = PolicyEngine().evaluate(
        control,
        profile,
    )

    assert evaluation.allowed is True


def test_unsupported_rollback_blocks_automatic_remediation() -> None:
    control = make_control(
        rollback_capability=RollbackCapability.UNSUPPORTED,
    )
    profile = make_profile(
        SafetyClassification.SAFE,
    )

    evaluation = PolicyEngine().evaluate(
        control,
        profile,
    )

    assert evaluation.allowed is False


def test_policy_cannot_upgrade_investigate_to_safe() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.INVESTIGATE,
        enabled=False,
    )

    classification = ControlClassifier().classify(
        control,
        profile,
    )

    assert classification.classification is SafetyClassification.INVESTIGATE
    assert classification.automatically_remediable is False


def test_policy_cannot_upgrade_prohibited_to_approval() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.PROHIBITED,
        enabled=False,
    )

    classification = ControlClassifier().classify(
        control,
        profile,
    )

    assert classification.classification is SafetyClassification.PROHIBITED
    assert classification.requires_approval is False
    assert classification.automatically_remediable is False


def test_compliant_control_never_enters_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.SAFE,
    )

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    evaluation = policy_engine.evaluate(
        control,
        profile,
    )

    compliant_audit = AuditResult(
        control_id="TEST-1",
        host="production-01",
        status=ComplianceStatus.PASS,
        evidence=(),
    )

    plan = planner.plan(
        (compliant_audit,),
        (evaluation,),
    )

    assert plan.items[0].action is PlanAction.SKIP
    assert plan.items[0].action is not PlanAction.REMEDIATE


def test_unknown_audit_status_does_not_enter_remediation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.SAFE,
    )

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(
        policy_engine=policy_engine,
    )

    evaluation = policy_engine.evaluate(
        control,
        profile,
    )

    unknown_audit = AuditResult(
        control_id="TEST-1",
        host="production-01",
        status=ComplianceStatus.UNKNOWN,
        evidence=(),
    )

    plan = planner.plan(
        (unknown_audit,),
        (evaluation,),
    )

    assert plan.items[0].action is PlanAction.INVESTIGATE
    assert plan.items[0].action is not PlanAction.REMEDIATE