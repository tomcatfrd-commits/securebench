from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from securebench.core.control import Control
from securebench.core.control_graph import ControlGraph
from securebench.core.exceptions import PlanningError
from securebench.core.result import AuditResult, ComplianceStatus
from securebench.policy.engine import PolicyEvaluation, PolicyEngine

from .conflict import ConflictResolver
from .dependency import DependencyResolver


class PlanAction(StrEnum):
    REMEDIATE = "remediate"
    PRECHECK = "precheck"
    APPROVAL_REQUIRED = "approval_required"
    INVESTIGATE = "investigate"
    SKIP = "skip"


@dataclass(frozen=True, slots=True)
class RemediationPlanItem:
    control: Control
    action: PlanAction
    reason: str
    requires_precheck: bool = False
    requires_approval: bool = False


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    items: tuple[RemediationPlanItem, ...]

    @property
    def executable_items(self) -> tuple[RemediationPlanItem, ...]:
        return tuple(
            item for item in self.items if item.action is PlanAction.REMEDIATE
        )

    @property
    def requires_precheck(self) -> tuple[RemediationPlanItem, ...]:
        return tuple(
            item for item in self.items if item.action is PlanAction.PRECHECK
        )

    @property
    def requires_approval(self) -> tuple[RemediationPlanItem, ...]:
        return tuple(
            item
            for item in self.items
            if item.action is PlanAction.APPROVAL_REQUIRED
        )


class RemediationPlanner:
    """
    Convert audit results and policy evaluations into a remediation plan.

    The planner does not execute changes. It only determines what the
    remediation workflow is permitted to consider next.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        graph: ControlGraph | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._graph = graph

    def plan(
        self,
        audits: tuple[AuditResult, ...],
        evaluations: tuple[PolicyEvaluation, ...],
    ) -> RemediationPlan:
        audit_by_control = self._index_audits(audits)
        evaluation_by_control = self._index_evaluations(evaluations)

        if not audit_by_control:
            return RemediationPlan(items=())

        if set(audit_by_control) != set(evaluation_by_control):
            missing_evaluations = sorted(
                set(audit_by_control) - set(evaluation_by_control)
            )
            missing_audits = sorted(
                set(evaluation_by_control) - set(audit_by_control)
            )

            raise PlanningError(
                "Audit and policy evaluation sets do not match: "
                f"missing evaluations={missing_evaluations}, "
                f"missing audits={missing_audits}"
            )

        requested_ids = tuple(
            audit.control_id
            for audit in audits
            if audit.status is ComplianceStatus.FAIL
        )

        if not requested_ids:
            return RemediationPlan(items=())

        controls = self._controls_from_evaluations(evaluations)

        requested_controls = tuple(
            controls[control_id] for control_id in requested_ids
        )

        ordered_controls = self._resolve_order(
            requested_controls=requested_controls,
        )

        items: list[RemediationPlanItem] = []

        for control in ordered_controls:
            audit = audit_by_control.get(control.control_id)
            evaluation = evaluation_by_control.get(control.control_id)

            if audit is None or evaluation is None:
                raise PlanningError(
                    f"Control {control.control_id!r} is required by the plan "
                    "but has no corresponding audit and policy evaluation."
                )

            items.append(
                self._item_from_evaluation(
                    control=control,
                    audit=audit,
                    evaluation=evaluation,
                )
            )

        return RemediationPlan(items=tuple(items))

    @staticmethod
    def _index_audits(
        audits: tuple[AuditResult, ...],
    ) -> dict[str, AuditResult]:
        result: dict[str, AuditResult] = {}

        for audit in audits:
            if audit.control_id in result:
                raise PlanningError(
                    f"Duplicate audit result for control {audit.control_id!r}"
                )

            result[audit.control_id] = audit

        return result

    @staticmethod
    def _index_evaluations(
        evaluations: tuple[PolicyEvaluation, ...],
    ) -> dict[str, PolicyEvaluation]:
        result: dict[str, PolicyEvaluation] = {}

        for evaluation in evaluations:
            if evaluation.control_id in result:
                raise PlanningError(
                    f"Duplicate policy evaluation for control "
                    f"{evaluation.control_id!r}"
                )

            result[evaluation.control_id] = evaluation

        return result

    @staticmethod
    def _controls_from_evaluations(
        evaluations: tuple[PolicyEvaluation, ...],
    ) -> dict[str, Control]:
        controls: dict[str, Control] = {}

        for evaluation in evaluations:
            control = getattr(evaluation, "control", None)

            if not isinstance(control, Control):
                raise PlanningError(
                    f"Policy evaluation for control {evaluation.control_id!r} "
                    "does not contain its Control definition."
                )

            if control.control_id != evaluation.control_id:
                raise PlanningError(
                    f"Policy evaluation/control mismatch: "
                    f"evaluation={evaluation.control_id!r}, "
                    f"control={control.control_id!r}"
                )

            controls[control.control_id] = control

        return controls

    def _resolve_order(
        self,
        requested_controls: tuple[Control, ...],
    ) -> tuple[Control, ...]:
        if self._graph is None:
            return requested_controls

        requested_ids = tuple(
            control.control_id for control in requested_controls
        )

        conflict_resolver = ConflictResolver(self._graph)

        conflicts = conflict_resolver.find_conflicts(requested_ids)

        if conflicts:
            raise PlanningError(
                "Requested controls contain conflicts: "
                + ", ".join(sorted(conflicts))
            )

        dependency_resolver = DependencyResolver(self._graph)

        ordered_ids = dependency_resolver.resolve(requested_ids)

        controls_by_id = {
            control.control_id: control
            for control in requested_controls
        }

        missing_dependency_ids = tuple(
            control_id
            for control_id in ordered_ids
            if control_id not in controls_by_id
        )

        if missing_dependency_ids:
            raise PlanningError(
                "Dependency controls are missing from the supplied "
                "audit/evaluation set: "
                + ", ".join(missing_dependency_ids)
            )

        return tuple(
            controls_by_id[control_id]
            for control_id in ordered_ids
        )

    @staticmethod
    def _item_from_evaluation(
        *,
        control: Control,
        audit: AuditResult,
        evaluation: PolicyEvaluation,
    ) -> RemediationPlanItem:
        if audit.status is ComplianceStatus.PASS:
            return RemediationPlanItem(
                control=control,
                action=PlanAction.SKIP,
                reason="Control is already compliant.",
            )

        if audit.status is not ComplianceStatus.FAIL:
            return RemediationPlanItem(
                control=control,
                action=PlanAction.INVESTIGATE,
                reason=(
                    f"Audit status {audit.status.value!r} does not provide "
                    "sufficient evidence for automatic remediation."
                ),
            )

        if not evaluation.allowed:
            return RemediationPlanItem(
                control=control,
                action=PlanAction.INVESTIGATE,
                reason=evaluation.reason,
            )

        if evaluation.requires_approval:
            return RemediationPlanItem(
                control=control,
                action=PlanAction.APPROVAL_REQUIRED,
                reason=evaluation.reason,
                requires_approval=True,
            )

        if evaluation.requires_precheck:
            return RemediationPlanItem(
                control=control,
                action=PlanAction.PRECHECK,
                reason=evaluation.reason,
                requires_precheck=True,
            )

        return RemediationPlanItem(
            control=control,
            action=PlanAction.REMEDIATE,
            reason=evaluation.reason,
        )