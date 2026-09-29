from __future__ import annotations

from dataclasses import replace

import pytest

from securebench.core import (
    ComplianceStatus,
    PlanningError,
    ProfileRule,
    RollbackCapability,
    SafetyClassification,
)
from securebench.remediation import (
    PlanAction,
    RemediationPlan,
    RemediationPlanItem,
    RemediationPlanner,
)
from securebench.policy import PolicyEngine


class TestRemediationPlannerBuild:
    def test_compliant_control_is_skipped(
        self,
        control,
        profile,
        passing_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                    enabled=True,
                    require_approval=False,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[passing_audit],
            profile=profile,
        )

        assert plan.item_count == 1

        item = plan.items[0]

        assert item.control is control
        assert item.control_id == "TEST-001"
        assert item.host == "server01"
        assert item.action is PlanAction.SKIP
        assert item.audit_result is passing_audit
        assert item.policy_evaluation is not None
        assert "compliant" in item.reason.lower()

    def test_failed_safe_control_is_remediated(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                    enabled=True,
                    require_approval=False,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.control is control
        assert item.action is PlanAction.REMEDIATE
        assert item.requires_precheck is False
        assert item.requires_approval is False
        assert item.policy_evaluation is not None

    def test_failed_safe_with_precheck_requires_precheck(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE_WITH_PRECHECK,
                    enabled=True,
                    require_approval=False,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.PRECHECK
        assert item.requires_precheck is True
        assert item.requires_approval is False

    def test_failed_approval_required_control_requires_approval(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.APPROVAL_REQUIRED,
                    enabled=True,
                    require_approval=True,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.APPROVAL_REQUIRED
        assert item.requires_approval is True
        assert item.requires_precheck is False

    @pytest.mark.parametrize(
        "classification",
        [
            SafetyClassification.INVESTIGATE,
            SafetyClassification.PROHIBITED,
        ],
    )
    def test_failed_non_remediable_classification_requires_investigation(
        self,
        control,
        profile,
        failed_audit,
        classification,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=classification,
                    enabled=False,
                    require_approval=False,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE
        assert item.requires_precheck is False
        assert item.requires_approval is False

    @pytest.mark.parametrize(
        "status",
        [
            ComplianceStatus.UNKNOWN,
            ComplianceStatus.ERROR,
        ],
    )
    def test_non_fail_audit_status_requires_investigation(
        self,
        control,
        profile,
        status,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                    enabled=True,
                    require_approval=False,
                )
            },
        )

        audit = replace(
            pytest.importorskip(
                "securebench.core.result"
            ).AuditResult(
                control_id="TEST-001",
                host="server01",
                status=status,
                evidence=None,
                message=f"Audit result: {status.value}",
            )
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE
        assert item.audit_result is audit

    def test_unknown_control_policy_fails_closed(
        self,
        control,
        failed_audit,
    ) -> None:
        from securebench.core import Profile

        profile = Profile(
            profile_id="test-profile",
            name="Test Profile",
            description="Test profile",
            default_classification=SafetyClassification.INVESTIGATE,
            rules={},
            require_approval_for_unknown=True,
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.APPROVAL_REQUIRED
        assert item.policy_evaluation is not None
        assert item.policy_evaluation.allowed is True
        assert item.policy_evaluation.requires_approval is True

    def test_best_effort_rollback_is_denied_by_default(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        control = replace(
            control,
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                    enabled=True,
                    require_approval=False,
                )
            },
            allow_best_effort_rollback=False,
        )

        plan = RemediationPlanner(
            policy_engine=PolicyEngine(),
        ).build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.action is PlanAction.INVESTIGATE
        assert item.policy_evaluation is not None
        assert item.policy_evaluation.allowed is False

    def test_best_effort_rollback_can_be_planned_when_profile_allows_it(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        control = replace(
            control,
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                    enabled=True,
                    require_approval=False,
                )
            },
            allow_best_effort_rollback=True,
        )

        plan = RemediationPlanner(
            policy_engine=PolicyEngine(),
        ).build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        assert plan.items[0].action is PlanAction.REMEDIATE

    def test_create_plan_is_equivalent_to_build(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                    enabled=True,
                    require_approval=False,
                )
            },
        )

        planner = RemediationPlanner()

        build_plan = planner.build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        create_plan = planner.create_plan(
            controls=[control],
            audit_results=[failed_audit],
            profile=profile,
        )

        assert create_plan == build_plan


class TestRemediationPlannerValidation:
    def test_missing_audit_is_rejected(
        self,
        control,
        profile,
    ) -> None:
        with pytest.raises(PlanningError, match="missing corresponding"):
            RemediationPlanner().build(
                controls=[control],
                audits=[],
                profile=profile,
            )

    def test_audit_for_unknown_control_is_rejected(
        self,
        control,
        profile,
    ) -> None:
        audit = pytest.importorskip(
            "securebench.core.result"
        ).AuditResult(
            control_id="UNKNOWN-001",
            host="server01",
            status=ComplianceStatus.FAIL,
            evidence=None,
            message="Audit failed.",
        )

        with pytest.raises(
            PlanningError,
            match="controls that were not supplied",
        ):
            RemediationPlanner().build(
                controls=[control],
                audits=[audit],
                profile=profile,
            )

    def test_duplicate_control_is_rejected(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        with pytest.raises(
            PlanningError,
            match="Duplicate control definition",
        ):
            RemediationPlanner().build(
                controls=[control, control],
                audits=[failed_audit],
                profile=profile,
            )

    def test_duplicate_audit_is_rejected(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        with pytest.raises(
            PlanningError,
            match="Duplicate audit result",
        ):
            RemediationPlanner().build(
                controls=[control],
                audits=[failed_audit, failed_audit],
                profile=profile,
            )

    @pytest.mark.parametrize(
        ("controls", "audits"),
        [
            ("invalid", []),
            ([], "invalid"),
        ],
    )
    def test_input_collections_are_validated(
        self,
        profile,
        controls,
        audits,
    ) -> None:
        with pytest.raises(TypeError):
            RemediationPlanner().build(
                controls=controls,
                audits=audits,
                profile=profile,
            )


class TestRemediationPlannerDeterminism:
    def test_plan_is_deterministically_sorted_by_control_id(
        self,
        profile,
        control,
    ) -> None:
        from securebench.core.result import AuditResult

        controls = [
            replace(control, control_id="CONTROL-B"),
            replace(control, control_id="CONTROL-A"),
            replace(control, control_id="CONTROL-C"),
        ]

        profile = replace(
            profile,
            rules={
                "CONTROL-A": ProfileRule(
                    classification=SafetyClassification.SAFE,
                ),
                "CONTROL-B": ProfileRule(
                    classification=SafetyClassification.SAFE_WITH_PRECHECK,
                ),
                "CONTROL-C": ProfileRule(
                    classification=SafetyClassification.INVESTIGATE,
                    enabled=False,
                ),
            },
        )

        audits = [
            AuditResult(
                control_id="CONTROL-C",
                host="server01",
                status=ComplianceStatus.FAIL,
                evidence=None,
                message="Audit failed.",
            ),
            AuditResult(
                control_id="CONTROL-A",
                host="server01",
                status=ComplianceStatus.FAIL,
                evidence=None,
                message="Audit failed.",
            ),
            AuditResult(
                control_id="CONTROL-B",
                host="server01",
                status=ComplianceStatus.FAIL,
                evidence=None,
                message="Audit failed.",
            ),
        ]

        plan = RemediationPlanner().build(
            controls=controls,
            audits=audits,
            profile=profile,
        )

        assert [item.control_id for item in plan.items] == [
            "CONTROL-A",
            "CONTROL-B",
            "CONTROL-C",
        ]

        assert [item.action for item in plan.items] == [
            PlanAction.REMEDIATE,
            PlanAction.PRECHECK,
            PlanAction.INVESTIGATE,
        ]

    def test_plan_preserves_exact_control_objects(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        assert plan.items[0].control is control

    def test_empty_input_produces_empty_plan(
        self,
        profile,
    ) -> None:
        plan = RemediationPlanner().build(
            controls=[],
            audits=[],
            profile=profile,
        )

        assert isinstance(plan, RemediationPlan)
        assert plan.items == ()
        assert plan.item_count == 0


class TestRemediationPlan:
    def test_plan_is_immutable(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        with pytest.raises(AttributeError):
            plan.items = ()  # type: ignore[misc]

        with pytest.raises(AttributeError):
            plan.items[0].action = PlanAction.SKIP  # type: ignore[misc]

    def test_executable_items_contains_only_remediation_actions(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        assert plan.executable_items == (plan.items[0],)

    def test_requires_precheck_property(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE_WITH_PRECHECK,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        assert plan.requires_precheck == (plan.items[0],)
        assert plan.executable_items == ()

    def test_requires_approval_property(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.APPROVAL_REQUIRED,
                    enabled=True,
                    require_approval=True,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        assert plan.requires_approval == (plan.items[0],)
        assert plan.executable_items == ()


class TestRemediationPlanItem:
    def test_control_id_defaults_to_control_id(
        self,
        control,
    ) -> None:
        item = RemediationPlanItem(
            control=control,
            host="server01",
            action=PlanAction.REMEDIATE,
            reason="Safe remediation.",
        )

        assert item.control_id == control.control_id

    def test_plan_item_is_immutable(
        self,
        control,
    ) -> None:
        item = RemediationPlanItem(
            control=control,
            host="server01",
            action=PlanAction.SKIP,
            reason="Already compliant.",
        )

        with pytest.raises(AttributeError):
            item.action = PlanAction.REMEDIATE  # type: ignore[misc]

    def test_plan_item_keeps_audit_and_policy_context(
        self,
        control,
        profile,
        failed_audit,
    ) -> None:
        profile = replace(
            profile,
            rules={
                "TEST-001": ProfileRule(
                    classification=SafetyClassification.SAFE,
                )
            },
        )

        plan = RemediationPlanner().build(
            controls=[control],
            audits=[failed_audit],
            profile=profile,
        )

        item = plan.items[0]

        assert item.audit_result is failed_audit
        assert item.policy_evaluation is not None
        assert item.policy_evaluation.control is control
