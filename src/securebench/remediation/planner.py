from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from securebench.core.control import Control
from securebench.core.control_graph import ControlGraph
from securebench.core.exceptions import PlanningError
from securebench.core.profile import Profile
from securebench.core.result import AuditResult, ComplianceStatus
from securebench.policy.engine import PolicyEngine, PolicyEvaluation

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
    """
    One control's decision in a remediation plan.

    The item retains the original Control object together with its audit
    result and policy evaluation so that the plan is explainable,
    independently auditable, and does not require reconstructing domain
    objects from identifiers.
    """

    control: Control
    control_id: str
    host: str
    action: PlanAction
    reason: str
    audit_result: AuditResult | None = None
    policy_evaluation: PolicyEvaluation | None = None
    requires_precheck: bool = False
    requires_approval: bool = False


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """Immutable remediation plan."""

    items: tuple[RemediationPlanItem, ...]

    @property
    def item_count(self) -> int:
        return len(self.items)

    @property
    def executable_items(self) -> tuple[RemediationPlanItem, ...]:
        return tuple(
            item
            for item in self.items
            if item.action is PlanAction.REMEDIATE
        )

    @property
    def requires_precheck(self) -> tuple[RemediationPlanItem, ...]:
        return tuple(
            item
            for item in self.items
            if item.action is PlanAction.PRECHECK
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
    Convert audit results into a policy-controlled remediation plan.

    Planning is deliberately separated from execution.

    Workflow:
        controls + audit results + profile
                    |
                    v
             PolicyEngine
                    |
                    v
             RemediationPlan

    No Ansible execution or target-system modification occurs here.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        graph: ControlGraph | None = None,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._graph = graph

    def build(
        self,
        *,
        controls: list[Control] | tuple[Control, ...],
        audits: list[AuditResult] | tuple[AuditResult, ...],
        profile: Profile,
    ) -> RemediationPlan:
        """
        Build a remediation plan from controls and their audit results.

        Policy is evaluated inside the planner so that a caller cannot
        accidentally bypass the policy gate by constructing plan items
        directly.
        """
        normalized_controls = self._normalize_controls(controls)
        normalized_audits = self._normalize_audits(audits)

        if not normalized_controls and not normalized_audits:
            return RemediationPlan(items=())

        controls_by_id = self._index_controls(normalized_controls)
        audits_by_id = self._index_audits(normalized_audits)

        missing_controls = sorted(
            set(audits_by_id) - set(controls_by_id)
        )
        if missing_controls:
            raise PlanningError(
                "Audit results reference controls that were not supplied: "
                + ", ".join(missing_controls)
            )

        missing_audits = sorted(
            set(controls_by_id) - set(audits_by_id)
        )
        if missing_audits:
            raise PlanningError(
                "Controls are missing corresponding audit results: "
                + ", ".join(missing_audits)
            )

        evaluations: dict[str, PolicyEvaluation] = {}

        for control in normalized_controls:
            evaluations[control.control_id] = self._policy_engine.evaluate(
                control,
                profile,
            )

        ordered_controls = self._resolve_order(
            tuple(normalized_controls),
        )

        items = tuple(
            self._build_item(
                control=control,
                audit=audits_by_id[control.control_id],
                evaluation=evaluations[control.control_id],
            )
            for control in ordered_controls
            if audits_by_id[control.control_id].status
            is ComplianceStatus.FAIL
        )

        return RemediationPlan(items=items)

    def create_plan(
        self,
        *,
        controls: list[Control] | tuple[Control, ...],
        audit_results: list[AuditResult] | tuple[AuditResult, ...],
        profile: Profile,
    ) -> RemediationPlan:
        """
        Explicit public alias for build().

        ``create_plan`` is retained as the descriptive workflow API used by
        integration callers.
        """
        return self.build(
            controls=controls,
            audits=audit_results,
            profile=profile,
        )

    def plan(
        self,
        audits: tuple[AuditResult, ...],
        evaluations: tuple[PolicyEvaluation, ...],
    ) -> RemediationPlan:
        """
        Compatibility API for callers that already evaluated policy.

        PolicyEvaluation carries the original Control definition, allowing
        this API to preserve the exact Control object without reconstructing
        it.

        Controls introduced only because they are dependencies may not have
        their own audit result. Such controls are represented with an UNKNOWN
        audit result so they can never become automatically remediable without
        explicit audit evidence.
        """
        audit_by_control = self._index_audits(audits)
        evaluation_by_control = self._index_evaluations(evaluations)

        if not audit_by_control and not evaluation_by_control:
            return RemediationPlan(items=())

        if not audit_by_control or not evaluation_by_control:
            raise PlanningError(
                "Audit and policy evaluation sets must both be provided."
            )

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

        controls = self._controls_from_evaluations(evaluations)

        ordered_controls = self._resolve_order(
            tuple(controls.values()),
        )

        default_host = self._default_host(audits)

        items = tuple(
            self._build_item(
                control=control,
                audit=audit_by_control.get(
                    control.control_id,
                    AuditResult(
                        control_id=control.control_id,
                        host=default_host,
                        status=ComplianceStatus.UNKNOWN,
                        message=(
                            "No direct audit result was supplied for this "
                            "dependency control."
                        ),
                    ),
                ),
                evaluation=evaluation_by_control[control.control_id],
            )
            for control in ordered_controls
            if audit_by_control.get(control.control_id) is not None
            and audit_by_control[control.control_id].status
            is ComplianceStatus.FAIL
        )

        return RemediationPlan(items=items)

    @staticmethod
    def _normalize_controls(
        controls: list[Control] | tuple[Control, ...],
    ) -> tuple[Control, ...]:
        if not isinstance(controls, (list, tuple)):
            raise TypeError("controls must be a list or tuple")

        for control in controls:
            if not isinstance(control, Control):
                raise TypeError("controls must contain Control objects")

        return tuple(controls)

    @staticmethod
    def _normalize_audits(
        audits: list[AuditResult] | tuple[AuditResult, ...],
    ) -> tuple[AuditResult, ...]:
        if not isinstance(audits, (list, tuple)):
            raise TypeError("audits must be a list or tuple")

        for audit in audits:
            if not isinstance(audit, AuditResult):
                raise TypeError(
                    "audits must contain AuditResult objects"
                )

        return tuple(audits)

    @staticmethod
    def _index_controls(
        controls: tuple[Control, ...],
    ) -> dict[str, Control]:
        result: dict[str, Control] = {}

        for control in controls:
            if control.control_id in result:
                raise PlanningError(
                    f"Duplicate control definition for "
                    f"{control.control_id!r}"
                )

            result[control.control_id] = control

        return result

    @staticmethod
    def _index_audits(
        audits: tuple[AuditResult, ...],
    ) -> dict[str, AuditResult]:
        result: dict[str, AuditResult] = {}

        for audit in audits:
            if audit.control_id in result:
                raise PlanningError(
                    f"Duplicate audit result for "
                    f"control {audit.control_id!r}"
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
                    f"Duplicate policy evaluation for "
                    f"control {evaluation.control_id!r}"
                )

            if evaluation.control.control_id != evaluation.control_id:
                raise PlanningError(
                    "Policy evaluation control_id does not match its "
                    "Control definition: "
                    f"{evaluation.control_id!r} != "
                    f"{evaluation.control.control_id!r}"
                )

            result[evaluation.control_id] = evaluation

        return result

    @staticmethod
    def _controls_from_evaluations(
        evaluations: tuple[PolicyEvaluation, ...],
    ) -> dict[str, Control]:
        """
        Recover the exact Control objects carried by PolicyEvaluation.

        The identity is intentionally preserved. The planner must not create
        a reconstructed or partially populated Control object.
        """
        result: dict[str, Control] = {}

        for evaluation in evaluations:
            control = evaluation.control

            if not isinstance(control, Control):
                raise PlanningError(
                    "Policy evaluation does not contain a valid Control "
                    f"definition for {evaluation.control_id!r}."
                )

            if control.control_id != evaluation.control_id:
                raise PlanningError(
                    "Policy evaluation control_id does not match its "
                    "Control definition: "
                    f"{evaluation.control_id!r} != "
                    f"{control.control_id!r}"
                )

            if control.control_id in result:
                raise PlanningError(
                    f"Duplicate control definition for "
                    f"{control.control_id!r}"
                )

            result[control.control_id] = control

        return result

    @staticmethod
    def _default_host(audits: tuple[AuditResult, ...]) -> str:
        """
        Return the host to associate with dependency-only audit results.

        A compatibility plan is normally constructed from audit results for
        one target host. Reject an empty host rather than inventing one.
        """
        if not audits:
            raise PlanningError(
                "Cannot construct dependency audit results without a host."
            )

        hosts = {audit.host for audit in audits}

        if len(hosts) != 1:
            raise PlanningError(
                "Compatibility planning requires audit results for one host; "
                f"received hosts={sorted(hosts)!r}"
            )

        host = next(iter(hosts))

        if not host.strip():
            raise PlanningError(
                "Audit result host must not be empty."
            )

        return host

    def _resolve_order(
        self,
        controls: tuple[Control, ...],
    ) -> tuple[Control, ...]:
        """
        Resolve dependencies/conflicts when a control graph is configured.

        Without a graph, sort by control ID to guarantee deterministic plans.
        """
        if self._graph is None:
            return tuple(
                sorted(
                    controls,
                    key=lambda control: control.control_id,
                )
            )

        requested_ids = tuple(
            control.control_id
            for control in controls
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
            for control in controls
        }

        missing_dependency_ids = tuple(
            control_id
            for control_id in ordered_ids
            if control_id not in controls_by_id
        )

        if missing_dependency_ids:
            raise PlanningError(
                "Dependency controls are missing from the supplied "
                "control/evaluation set: "
                + ", ".join(missing_dependency_ids)
            )

        return tuple(
            controls_by_id[control_id]
            for control_id in ordered_ids
        )

    @staticmethod
    def _build_item(
        *,
        control: Control,
        audit: AuditResult,
        evaluation: PolicyEvaluation,
    ) -> RemediationPlanItem:
        """
        Translate audit state and policy decision into one plan action.

        Compliance is checked before policy because a passing control must
        never enter remediation merely because its policy permits changes.

        This method still understands PASS and UNKNOWN for defensive
        compatibility, but the public planning paths exclude those statuses
        before constructing plan items.
        """
        if audit.status is ComplianceStatus.PASS:
            return RemediationPlanItem(
                control=control,
                control_id=control.control_id,
                host=audit.host,
                action=PlanAction.SKIP,
                reason="Control is already compliant.",
                audit_result=audit,
                policy_evaluation=evaluation,
            )

        if audit.status is not ComplianceStatus.FAIL:
            return RemediationPlanItem(
                control=control,
                control_id=control.control_id,
                host=audit.host,
                action=PlanAction.INVESTIGATE,
                reason=(
                    f"Audit status {audit.status.value!r} does not provide "
                    "sufficient evidence for automatic remediation."
                ),
                audit_result=audit,
                policy_evaluation=evaluation,
            )

        if not evaluation.allowed:
            return RemediationPlanItem(
                control=control,
                control_id=control.control_id,
                host=audit.host,
                action=PlanAction.INVESTIGATE,
                reason=evaluation.reason,
                audit_result=audit,
                policy_evaluation=evaluation,
            )

        if evaluation.requires_approval:
            return RemediationPlanItem(
                control=control,
                control_id=control.control_id,
                host=audit.host,
                action=PlanAction.APPROVAL_REQUIRED,
                reason=evaluation.reason,
                audit_result=audit,
                policy_evaluation=evaluation,
                requires_approval=True,
            )

        if evaluation.requires_precheck:
            return RemediationPlanItem(
                control=control,
                control_id=control.control_id,
                host=audit.host,
                action=PlanAction.PRECHECK,
                reason=evaluation.reason,
                audit_result=audit,
                policy_evaluation=evaluation,
                requires_precheck=True,
            )

        return RemediationPlanItem(
            control=control,
            control_id=control.control_id,
            host=audit.host,
            action=PlanAction.REMEDIATE,
            reason=evaluation.reason,
            audit_result=audit,
            policy_evaluation=evaluation,
        )