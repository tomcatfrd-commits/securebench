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
from securebench.policy import PolicyEngine
from securebench.remediation import (
    PlanAction,
    RemediationPlan,
    RemediationPlanItem,
    RemediationPlanner,
)


def make_control(
    *,
    control_id: str = "TEST-001",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
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
        description="Test profile",
        default_classification=SafetyClassification.INVESTIGATE,
        rules={
            "TEST-001": ProfileRule(
                classification=classification,
                enabled=enabled,
                require_approval=require_approval,
            )
        },
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


def make_audit(
    status: ComplianceStatus,
    *,
    control_id: str = "TEST-001",
    host: str = "server01",
) -> AuditResult:
    return AuditResult(
        control_id=control_id,
        host=host,
        status=status,
        evidence=None,
        message=f"Audit result: {status.value}",
    )


class TestRemediationPlanner:
    def test_passed_control_is_skipped(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.SAFE)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.PASS),
            ],
            profile=profile,
        )

        assert plan.item_count == 1

        item = plan.items[0]

        assert item.control_id == "TEST-001"
        assert item.host == "server01"
        assert item.action is PlanAction.SKIP
        assert item.reason is not None
        assert "compliant" in item.reason.lower()

    def test_failed_safe_control_is_remediated(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.SAFE)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.REMEDIATE
        assert item.control_id == "TEST-001"
        assert item.host == "server01"

    def test_failed_safe_with_precheck_requires_precheck(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.SAFE_WITH_PRECHECK)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.PRECHECK
        assert item.control_id == "TEST-001"
        assert item.host == "server01"

    def test_failed_approval_required_control_requires_approval(self) -> None:
        control = make_control()
        profile = make_profile(
            SafetyClassification.APPROVAL_REQUIRED,
            require_approval=True,
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.APPROVAL_REQUIRED
        assert item.control_id == "TEST-001"
        assert item.host == "server01"

    def test_failed_investigate_control_is_not_remediated(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.INVESTIGATE)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE
        assert item.control_id == "TEST-001"

    def test_failed_prohibited_control_is_not_remediated(self) -> None:
        control = make_control()
        profile = make_profile(
            SafetyClassification.PROHIBITED,
            enabled=False,
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE
        assert item.control_id == "TEST-001"

    def test_unknown_audit_result_requires_investigation(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.SAFE)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.UNKNOWN),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE

    def test_error_audit_result_requires_investigation(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.SAFE)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.ERROR),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE

    def test_best_effort_rollback_denied_by_policy_is_not_remediated(
        self,
    ) -> None:
        control = make_control(
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        profile = make_profile(
            SafetyClassification.SAFE,
            allow_best_effort_rollback=False,
        )

        plan = RemediationPlanner(
            policy_engine=PolicyEngine(),
        ).build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE
        assert item.action is not PlanAction.REMEDIATE
        assert item.action is not PlanAction.PRECHECK

    def test_best_effort_rollback_can_be_planned_when_profile_allows_it(
        self,
    ) -> None:
        control = make_control(
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        profile = make_profile(
            SafetyClassification.SAFE,
            allow_best_effort_rollback=True,
        )

        plan = RemediationPlanner(
            policy_engine=PolicyEngine(),
        ).build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.REMEDIATE

    def test_multiple_controls_produce_deterministic_plan(self) -> None:
        controls = [
            make_control(control_id="B"),
            make_control(control_id="A"),
            make_control(control_id="C"),
        ]

        profile = Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile",
            default_classification=SafetyClassification.INVESTIGATE,
            rules={
                "A": ProfileRule(
                    classification=SafetyClassification.SAFE,
                ),
                "B": ProfileRule(
                    classification=SafetyClassification.SAFE_WITH_PRECHECK,
                ),
                "C": ProfileRule(
                    classification=SafetyClassification.INVESTIGATE,
                ),
            },
        )

        audits = [
            make_audit(ComplianceStatus.FAIL, control_id="C"),
            make_audit(ComplianceStatus.FAIL, control_id="A"),
            make_audit(ComplianceStatus.FAIL, control_id="B"),
        ]

        plan = RemediationPlanner().build(
            controls=controls,
            audits=audits,
            profile=profile,
        )

        assert [item.control_id for item in plan.items] == ["A", "B", "C"]
        assert [item.action for item in plan.items] == [
            PlanAction.REMEDIATE,
            PlanAction.PRECHECK,
            PlanAction.INVESTIGATE,
        ]

    def test_plan_is_immutable(self) -> None:
        control = make_control()
        profile = make_profile(SafetyClassification.SAFE)

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[
                make_audit(ComplianceStatus.FAIL),
            ],
            profile=profile,
        )

        assert isinstance(plan.items, tuple)

        with __import__("pytest").raises(AttributeError):
            plan.items = ()  # type: ignore[misc]

    def test_empty_input_produces_empty_plan(self) -> None:
        profile = make_profile(SafetyClassification.SAFE)

        plan = RemediationPlanner().build(
            controls=[],
            audits=[],
            profile=profile,
        )

        assert isinstance(plan, RemediationPlan)
        assert plan.item_count == 0
        assert plan.items == ()

    def test_plan_item_requires_valid_action(self) -> None:
        item = RemediationPlanItem(
            control_id="TEST-001",
            host="server01",
            action=PlanAction.REMEDIATE,
            reason="Safe remediation",
        )

        assert item.control_id == "TEST-001"
        assert item.host == "server01"
        assert item.action is PlanAction.REMEDIATE

    def test_plan_item_is_immutable(self) -> None:
        item = RemediationPlanItem(
            control_id="TEST-001",
            host="server01",
            action=PlanAction.SKIP,
            reason="Already compliant",
        )

        with __import__("pytest").raises(AttributeError):
            item.action = PlanAction.REMEDIATE  # type: ignore[misc]