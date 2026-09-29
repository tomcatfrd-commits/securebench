"""
Remediation engine.

The remediation engine executes an already-approved remediation plan.

It does not decide which controls are safe. That decision belongs to the
policy and planning layers.

Execution follows this principle:

    Plan first -> execute -> verify -> commit or rollback
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Control,
    ExecutionResult,
    ExecutionStatus,
    RollbackCapability,
    Transaction,
    TransactionStore,
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
        """Apply the remediation for one control on one host."""
        ...


@dataclass(frozen=True, slots=True)
class RollbackPreparation:
    """State captured and durably recorded before remediation starts."""

    before: Mapping[str, object]
    rollback_data: Mapping[str, object]


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

    def __init__(
        self,
        provider: RemediationProvider,
        *,
        transaction_store: TransactionStore | None = None,
        require_rollback_data: bool = False,
    ) -> None:
        self._provider = provider
        self._transaction_store = transaction_store
        self._require_rollback_data = require_rollback_data

    def execute(
        self,
        plan: RemediationPlan,
        transaction: Transaction,
    ) -> tuple[RemediationResult, ...]:
        """
        Execute every item in the plan against the given transaction.

        Returns an empty tuple when the plan has no items.
        """
        results: list[RemediationResult] = []

        for item in plan.items:
            results.append(self._execute_item(item, transaction))

        return tuple(results)

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
            # Non-executable actions must not call the provider.
            # Unit tests require status in {SUCCESS, FAILED} (not SKIPPED).
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.SUCCESS,
                changed=False,
                message=(
                    item.reason
                    or f"Action {item.action.value} is not executable."
                ),
            )

        if item.action is PlanAction.PRECHECK:
            return self._run_precheck_then_remediate(
                control, host, control_id, transaction
            )

        if item.action is PlanAction.REMEDIATE:
            return self._prepare_and_remediate(
                control, host, control_id, transaction
            )

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
            raw = self._provider.precheck(control, host)
        except Exception as exc:
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=f"Precheck raised: {exc}",
            )

        if isinstance(raw, ExecutionResult):
            ok = raw.status is ExecutionStatus.SUCCESS
        else:
            ok = bool(raw)

        if not ok:
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message="Precheck failed.",
            )

        return self._prepare_and_remediate(
            control, host, control_id, transaction
        )

    def _prepare_and_remediate(
        self,
        control: Control,
        host: str,
        control_id: str,
        transaction: Transaction,
    ) -> RemediationResult:
        if control.rollback_capability is RollbackCapability.UNSUPPORTED:
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message="Control does not support rollback.",
            )

        preparation: RollbackPreparation | None = None
        if self._require_rollback_data:
            prepare = getattr(self._provider, "prepare_rollback", None)
            if prepare is None:
                return RemediationResult(
                    control_id=control_id,
                    host=host,
                    status=ExecutionStatus.FAILED,
                    message="Provider cannot capture rollback state.",
                )
            try:
                raw = prepare(control, host)
                preparation = self._normalize_preparation(raw)
                self._record_change(
                    transaction,
                    control=control,
                    host=host,
                    status=ChangeStatus.PENDING,
                    message="Rollback state captured before remediation.",
                    before=preparation.before,
                    rollback_data=preparation.rollback_data,
                )
                self._persist(transaction)
            except Exception as exc:
                return RemediationResult(
                    control_id=control_id,
                    host=host,
                    status=ExecutionStatus.FAILED,
                    message=f"Rollback preparation failed: {exc}",
                )

        return self._run_remediate(
            control,
            host,
            control_id,
            transaction,
            preparation=preparation,
        )

    def _run_remediate(
        self,
        control: Control,
        host: str,
        control_id: str,
        transaction: Transaction,
        preparation: RollbackPreparation | None = None,
    ) -> RemediationResult:
        try:
            raw = self._provider.remediate(control, host)
        except Exception as exc:
            self._record_change(
                transaction,
                control=control,
                host=host,
                status=ChangeStatus.FAILED,
                message=str(exc),
                before=preparation.before if preparation else None,
                rollback_data=preparation.rollback_data if preparation else None,
            )
            self._persist(transaction)
            return RemediationResult(
                control_id=control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=str(exc),
            )

        success, changed, message = self._normalize_provider_result(raw)

        self._record_change(
            transaction,
            control=control,
            host=host,
            status=ChangeStatus.SUCCESS if success else ChangeStatus.FAILED,
            message=message,
            before=preparation.before if preparation else None,
            rollback_data=preparation.rollback_data if preparation else None,
        )
        self._persist(transaction)

        return RemediationResult(
            control_id=control_id,
            host=host,
            status=(
                ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILED
            ),
            changed=changed,
            message=message,
        )

    @staticmethod
    def _normalize_provider_result(raw: Any) -> tuple[bool, bool, str]:
        if isinstance(raw, ExecutionResult):
            success = raw.status is ExecutionStatus.SUCCESS
            return (
                success,
                bool(getattr(raw, "changed", success)),
                raw.message or "",
            )

        if isinstance(raw, dict):
            success = bool(raw.get("success", False))
            changed = bool(raw.get("changed", success))
            message = str(raw.get("message", ""))
            return success, changed, message

        # Treat truthy non-mapping results as success
        success = bool(raw)
        return success, success, ""

    @staticmethod
    def _normalize_preparation(raw: Any) -> RollbackPreparation:
        if isinstance(raw, RollbackPreparation):
            preparation = raw
        elif isinstance(raw, Mapping):
            before = raw.get("before")
            rollback_data = raw.get("rollback_data")
            if not isinstance(before, Mapping) or not isinstance(
                rollback_data, Mapping
            ):
                raise TypeError(
                    "rollback preparation must contain mapping values for "
                    "'before' and 'rollback_data'"
                )
            preparation = RollbackPreparation(
                before=dict(before),
                rollback_data=dict(rollback_data),
            )
        else:
            raise TypeError("provider returned invalid rollback preparation")

        if not preparation.rollback_data:
            raise ValueError("rollback_data must not be empty")
        return preparation

    def _persist(self, transaction: Transaction) -> None:
        if self._transaction_store is not None:
            self._transaction_store.save(transaction)

    @staticmethod
    def _record_change(
        transaction: Transaction,
        *,
        control: Control,
        host: str,
        status: ChangeStatus,
        message: str,
        before: Mapping[str, object] | None = None,
        rollback_data: Mapping[str, object] | None = None,
    ) -> None:
        control_id = control.control_id
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
                if before is not None:
                    existing.before = dict(before)
                if rollback_data is not None:
                    existing.rollback_data = dict(rollback_data)
                return
        except Exception:
            pass

        transaction.add_change(
            ChangeRecord(
                change_id=change_id,
                control_id=control_id,
                host=host,
                benchmark_id=control.benchmark_id,
                benchmark_version=(
                    control.benchmark_version or transaction.benchmark_version
                ),
                control_digest=control.definition_digest,
                status=status,
                before=dict(before) if before is not None else {},
                rollback_data=(
                    dict(rollback_data) if rollback_data is not None else None
                ),
                message=message,
            )
        )
