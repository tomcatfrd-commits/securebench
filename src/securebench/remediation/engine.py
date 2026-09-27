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
from typing import Any, Protocol

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Control,
    ExecutionResult,
    ExecutionStatus,
    Transaction,
)

from .planner import PlanAction, RemediationPlan, RemediationPlanItem


class RemediationProvider(Protocol):
    """
    Interface implemented by execution backends.
    """

    def precheck(self, control: Control, host: str) -> bool:
        """
        Perform host-specific safety checks before remediation.

        Must not modify the target system. Returns True when safe to proceed.
        """
        ...

    def remediate(self, control: Control, host: str) -> Any:
        """
        Apply the remediation for one control on one host.

        May return an ExecutionResult or a mapping with success/changed/message.
        """
        ...


@dataclass(frozen=True, slots=True)
class RemediationResult:
    """Result of processing one planned remediation item."""

    control_id: str
    host: str
    status: ExecutionStatus
    changed: bool = False
    message: str = ""


# Backward-compatible alias expected by package __init__ and older callers.
RemediationExecution = RemediationResult


class RemediationEngine:
    """
    Execute remediation plan items through a provider.

    Transaction state is updated as execution progresses.
    """

    def __init__(self, provider: RemediationProvider) -> None:
        self._provider = provider

    def execute(
        self,
        plan: RemediationPlan,
        transaction: Transaction,
    ) -> list[RemediationResult]:
        """
        Execute every item in the plan against the given transaction.
        """
        results: list[RemediationResult] = []

        for item in plan.items:
            results.append(self._execute_item(item, transaction))

        return results

    def _execute_item(
        self,
        item: RemediationPlanItem,
        transaction: Transaction,
    ) -> RemediationResult:
        control = item.control
        host = item.host
        control_id = getattr(item, "control_id", None) or control.control_id

        if item.action in {
            PlanAction.SKIP,
            PlanAction.INVESTIGATE,
            PlanAction.APPROVAL_REQUIRED,
        }:
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.SKIPPED,
                message=item.reason or f"Action {item.action.value} is not executable.",
            )

        if item.action is PlanAction.PRECHECK:
            return self._run_precheck_then_remediate(control, host, control_id, transaction)

        if item.action is PlanAction.REMEDIATE:
            return self._run_remediate(control, host, control_id, transaction)

        return RemediationResult(
            control_id=control_id,
            host=host,
            status=ExecutionStatus.FAILED,
            message=f"Unsupported remediation action: {item.action!r}",
        )

    def _run_precheck_then_remediate(
        self,
        control: Control,
        host: str,
        control_id: str,
        transaction: Transaction,
    ) -> RemediationResult:
        try:
            ok = bool(self._provider.precheck(control, host))
        except Exception as exc:
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=f"Precheck raised: {exc}",
            )

        if not ok:
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message="Precheck failed.",
            )

        return self._run_remediate(control, host, control_id, transaction)

    def _run_remediate(
        self,
        control: Control,
        host: str,
        control_id: str,
        transaction: Transaction,
    ) -> RemediationResult:
        try:
            raw = self._provider.remediate(control, host)
        except Exception as exc:
            self._record_change(
                transaction,
                control_id=control_id,
                host=host,
                status=ChangeStatus.FAILED,
                message=str(exc),
            )
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=str(exc),
            )

        success, changed, message = self._normalize_provider_result(raw)

        self._record_change(
            transaction,
            control_id=control_id,
            host=host,
            status=ChangeStatus.SUCCESS if success else ChangeStatus.FAILED,
            message=message,
        )

        return RemediationResult(
            control_id=control_id,
            host=host,
            status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILED,
            changed=changed,
            message=message,
        )

    @staticmethod
    def _normalize_provider_result(raw: Any) -> tuple[bool, bool, str]:
        if isinstance(raw, ExecutionResult):
            success = raw.status is ExecutionStatus.SUCCESS
            return success, bool(getattr(raw, "changed", success)), raw.message or ""

        if isinstance(raw, dict):
            success = bool(raw.get("success", False))
            changed = bool(raw.get("changed", success))
            message = str(raw.get("message", ""))
            return success, changed, message

        # Treat truthy non-mapping results as success
        success = bool(raw)
        return success, success, ""

    @staticmethod
    def _record_change(
        transaction: Transaction,
        *,
        control_id: str,
        host: str,
        status: ChangeStatus,
        message: str,
    ) -> None:
        change_id = f"{control_id}:{host}:{len(transaction.changes)}"
        try:
            existing = None
            for change in transaction.changes:
                if change.control_id == control_id and change.host == host:
                    existing = change
                    break
            if existing is not None:
                existing.status = status
                existing.message = message
                return
        except Exception:
            pass

        transaction.add_change(
            ChangeRecord(
                change_id=change_id,
                control_id=control_id,
                host=host,
                status=status,
                message=message,
            )
        )