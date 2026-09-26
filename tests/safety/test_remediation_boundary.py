from __future__ import annotations

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    ExecutionResult,
    ExecutionStatus,
)
from securebench.core.profile import Profile, ProfileRule
from securebench.policy.engine import PolicyEngine
from securebench.remediation.engine import RemediationEngine
from securebench.remediation.planner import (
    PlanAction,
    RemediationPlan,
    RemediationPlanItem,
)


def make_control(
    control_id: str = "TEST-1",
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
        rollback_capability=RollbackCapability.GUARANTEED,
    )


def make_profile(
    classification: SafetyClassification,
    *,
    enabled: bool = True,
    require_approval: bool = False,
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
    )


class RecordingRemediationProvider:
    def __init__(self) -> None:
        self.prechecks: list[tuple[str, str]] = []
        self.remediations: list[tuple[str, str]] = []

    def precheck(self, control: Control, host: str):
        self.prechecks.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=False,
            message="Precheck passed.",
        )

    def remediate(self, control: Control, host: str):
        self.remediations.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
            message="Remediation completed.",
        )


def make_plan(
    control: Control,
    *,
    action: PlanAction,
    host: str = "production-01",
) -> RemediationPlan:
    return RemediationPlan(
        items=(
            RemediationPlanItem(
                control=control,
                host=host,
                action=action,
                reason="Test plan.",
            ),
        )
    )


def test_remediation_executes_only_explicit_remediate_action() -> None:
    control = make_control()
    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    engine.execute(plan)

    assert provider.remediations == [
        ("TEST-1", "production-01"),
    ]
    assert provider.prechecks == []


def test_precheck_action_runs_precheck_before_remediation() -> None:
    control = make_control()
    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.PRECHECK,
    )

    engine.execute(plan)

    assert provider.prechecks == [
        ("TEST-1", "production-01"),
    ]
    assert provider.remediations == [
        ("TEST-1", "production-01"),
    ]


def test_skip_action_does_not_modify_target() -> None:
    control = make_control()
    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.SKIP,
    )

    results = engine.execute(plan)

    assert provider.prechecks == []
    assert provider.remediations == []
    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is False


def test_investigate_action_does_not_modify_target() -> None:
    control = make_control()
    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.INVESTIGATE,
    )

    results = engine.execute(plan)

    assert provider.prechecks == []
    assert provider.remediations == []
    assert results[0].changed is False


def test_approval_required_action_does_not_modify_target() -> None:
    control = make_control()
    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.APPROVAL_REQUIRED,
    )

    results = engine.execute(plan)

    assert provider.prechecks == []
    assert provider.remediations == []
    assert results[0].changed is False


def test_failed_precheck_prevents_remediation() -> None:
    control = make_control()

    class FailingPrecheckProvider(RecordingRemediationProvider):
        def precheck(self, control: Control, host: str):
            self.prechecks.append((control.control_id, host))

            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                changed=False,
                message="Precheck failed.",
            )

    provider = FailingPrecheckProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.PRECHECK,
    )

    results = engine.execute(plan)

    assert provider.prechecks == [
        ("TEST-1", "production-01"),
    ]
    assert provider.remediations == []
    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False


def test_failed_remediation_is_preserved() -> None:
    control = make_control()

    class FailingRemediationProvider(RecordingRemediationProvider):
        def remediate(self, control: Control, host: str):
            self.remediations.append((control.control_id, host))

            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                changed=False,
                message="Remediation failed.",
            )

    provider = FailingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(plan)

    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False


def test_remediation_does_not_infer_safety_from_control_metadata() -> None:
    control = make_control()

    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.INVESTIGATE,
    )

    engine.execute(plan)

    assert provider.remediations == []


def test_policy_is_evaluated_before_plan_generation() -> None:
    control = make_control()
    profile = make_profile(
        SafetyClassification.INVESTIGATE,
        enabled=False,
    )

    evaluation = PolicyEngine().evaluate(
        control,
        profile,
    )

    assert evaluation.allowed is False


def test_failed_audit_does_not_by_itself_authorize_remediation() -> None:
    control = make_control()

    audit = AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
        evidence=(),
    )

    assert audit.status is ComplianceStatus.FAIL

    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.INVESTIGATE,
    )

    engine.execute(plan)

    assert provider.remediations == []


def test_remediation_provider_receives_exact_control_identity() -> None:
    control = make_control("CONTROL-EXACT")
    provider = RecordingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    engine.execute(plan)

    assert provider.remediations == [
        ("CONTROL-EXACT", "production-01"),
    ]