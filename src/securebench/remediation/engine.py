"""
Remediation engine.

The remediation engine executes an already-approved remediation plan.

It does not decide which controls are safe. That decision belongs to the
policy and planning layers.

Execution follows this principle:

    Plan first -> execute -> verify -> commit or rollback
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from securebench.core import (
    ChangeStatus,
    ExecutionResult,
    ExecutionStatus,
    Transaction,
)

from .planner import PlanAction, RemediationPlanItem


class RemediationProvider(Protocol):
    """
    Interface implemented by execution backends.

    The provider performs the actual system modification for one control.
    """

    def remediate(
        self,
        control_id: str,
        host: str,
    ) -> ExecutionResult:
        """
        Apply the remediation for one control on one host.
        """
        ...

    def precheck(
        self,
        control_id: str,
        host: str,
    ) -> ExecutionResult:
        """
        Perform host-specific safety checks before remediation.

        A precheck must not modify the target system.
        """
        ...


@dataclass(frozen=True, slots=True)
class RemediationExecution:
    """Result of processing one planned remediation item."""

    control_id: str
    host: str
    action: PlanAction
    result: ExecutionResult | None


class RemediationEngine:
    """
    Execute remediation plan items through a provider.

    Transaction state is updated as execution progresses.
    """

    def __init__(self, provider: RemediationProvider) -> None:
        self._provider = provider

    def execute(
        self,
        *,
        plan_item: RemediationPlanItem,
        transaction: Transaction,
    ) -> RemediationExecution:
        """
        Execute one approved plan item.

        The transaction must already contain a corresponding ChangeRecord.
        """

        change = transaction.get_change(
            control_id=plan_item.control_id,
            host=plan_item.host,
        )

        if plan_item.action is PlanAction.SKIP:
            change.status = ChangeStatus.VERIFIED

            return RemediationExecution(
                control_id=plan_item.control_id,
                host=plan_item.host,
                action=plan_item.action,
                result=None,
            )

        if plan_item.action is PlanAction.INVESTIGATE:
            change.status = ChangeStatus.FAILED

            return RemediationExecution(
                control_id=plan_item.control_id,
                host=plan_item.host,
                action=plan_item.action,
                result=ExecutionResult(
                    control_id=plan_item.control_id,
                    host=plan_item.host,
                    status=ExecutionStatus.SKIPPED,
                    message="Remediation requires investigation.",
                ),
            )

        if plan_item.action is PlanAction.APPROVAL_REQUIRED:
            change.status = ChangeStatus.PLANNED

            return RemediationExecution(
                control_id=plan_item.control_id,
                host=plan_item.host,
                action=plan_item.action,
                result=ExecutionResult(
                    control_id=plan_item.control_id,
                    host=plan_item.host,
                    status=ExecutionStatus.SKIPPED,
                    message="Explicit approval is required.",
                ),
            )

        if plan_item.action is PlanAction.PRECHECK:
            return self._execute_after_precheck(
                plan_item=plan_item,
                transaction=transaction,
            )

        if plan_item.action is PlanAction.REMEDIATE:
            return self._apply(
                plan_item=plan_item,
                transaction=transaction,
            )

        raise ValueError(
            f"unsupported remediation action: {plan_item.action!r}"
        )

    def _execute_after_precheck(
        self,
        *,
        plan_item: RemediationPlanItem,
        transaction: Transaction,
    ) -> RemediationExecution:
        """Run a precheck and remediate only when it succeeds."""

        precheck = self._provider.precheck(
            control_id=plan_item.control_id,
            host=plan_item.host,
        )

        if precheck.status is not ExecutionStatus.SUCCESS:
            change = transaction.get_change(
                control_id=plan_item.control_id,
                host=plan_item.host,
            )

            change.status = ChangeStatus.FAILED
            change.execution_message = (
                "Precheck failed: " + precheck.message
            )

            return RemediationExecution(
                control_id=plan_item.control_id,
                host=plan_item.host,
                action=plan_item.action,
                result=precheck,
            )

        return self._apply(
            plan_item=plan_item,
            transaction=transaction,
        )

    def _apply(
        self,
        *,
        plan_item: RemediationPlanItem,
        transaction: Transaction,
    ) -> RemediationExecution:
        """Apply a remediation after all required gates have passed."""

        change = transaction.get_change(
            control_id=plan_item.control_id,
            host=plan_item.host,
        )

        change.status = ChangeStatus.APPLYING

        result = self._provider.remediate(
            control_id=plan_item.control_id,
            host=plan_item.host,
        )

        change.changed = result.changed
        change.execution_message = result.message

        if result.status is ExecutionStatus.SUCCESS:
            change.status = ChangeStatus.APPLIED
        else:
            change.status = ChangeStatus.FAILED

        return RemediationExecution(
            control_id=plan_item.control_id,
            host=plan_item.host,
            action=plan_item.action,
            result=result,
        )