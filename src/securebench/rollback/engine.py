"""
Rollback engine.

Rollback restores the state recorded before remediation.

Rollback is deliberately separate from remediation. A remediation provider
changes the system toward the desired state; a rollback provider restores
the previous state.

The rollback engine operates on a transaction so it can support both:

    1. control-level rollback
    2. transaction-level rollback

Rollback must fail closed: a control without a usable rollback implementation
must not be silently treated as successfully restored.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Control,
    ExecutionResult,
    ExecutionStatus,
    RollbackCapability,
    RollbackError,
    Transaction,
    TransactionStatus,
)


class RollbackProvider(Protocol):
    """
    Interface implemented by control-specific rollback providers.

    The provider is responsible for restoring the state that existed before
    remediation.
    """

    def rollback(
        self,
        control: Control,
        host: str,
        change: ChangeRecord,
    ) -> ExecutionResult:
        """
        Restore one control on one host.

        The implementation must use the transaction's recorded pre-change
        state or another explicitly supported rollback mechanism.
        """
        ...


@dataclass(frozen=True, slots=True)
class RollbackExecution:
    """
    Result of rolling back one control.
    """

    control_id: str
    host: str
    result: ExecutionResult

    @property
    def succeeded(self) -> bool:
        """Return True only when rollback completed successfully."""

        return self.result.status is ExecutionStatus.SUCCESS


class RollbackEngine:
    """
    Execute rollback operations for remediation transactions.

    The engine itself does not know how a specific system setting is restored.
    That responsibility belongs to the RollbackProvider.
    """

    def __init__(self, provider: RollbackProvider) -> None:
        self._provider = provider

    def rollback_control(
        self,
        *,
        control: Control,
        host: str,
        transaction: Transaction,
    ) -> RollbackExecution:
        """
        Roll back one control within a transaction.

        The control must explicitly support rollback. Unsupported rollback
        is treated as a hard error rather than silently ignored.
        """

        if control.rollback_capability is RollbackCapability.UNSUPPORTED:
            raise RollbackError(
                f"control '{control.control_id}' does not support rollback"
            )

        change = transaction.get_change(
            control_id=control.control_id,
            host=host,
        )

        if change.status not in {
            ChangeStatus.APPLIED,
            ChangeStatus.VERIFIED,
            ChangeStatus.FAILED,
            ChangeStatus.ROLLBACK_REQUIRED,
        }:
            raise RollbackError(
                f"control '{control.control_id}' on host '{host}' is in "
                f"state '{change.status.value}' and cannot be rolled back"
            )

        change.status = ChangeStatus.ROLLBACK_REQUIRED

        result = self._provider.rollback(
            control=control,
            host=host,
            change=change,
        )

        change.rollback_message = result.message

        if result.status is ExecutionStatus.SUCCESS:
            change.status = ChangeStatus.ROLLED_BACK
        else:
            change.status = ChangeStatus.ROLLBACK_REQUIRED

        return RollbackExecution(
            control_id=control.control_id,
            host=host,
            result=result,
        )

    def rollback_transaction(
        self,
        *,
        controls: dict[str, Control],
        transaction: Transaction,
    ) -> tuple[RollbackExecution, ...]:
        """
        Roll back all applicable changes in reverse execution order.

        Reverse order is important because later changes may depend on
        earlier state.

        The transaction is marked ROLLING_BACK before execution begins.
        It is marked ROLLED_BACK only when every applicable change succeeds.
        """

        if transaction.status not in {
            TransactionStatus.ROLLBACK_REQUIRED,
            TransactionStatus.FAILED,
        }:
            raise RollbackError(
                f"transaction '{transaction.transaction_id}' is in state "
                f"'{transaction.status.value}' and cannot be rolled back"
            )

        transaction.status = TransactionStatus.ROLLING_BACK

        results: list[RollbackExecution] = []

        for change in reversed(transaction.changes):
            if change.status not in {
                ChangeStatus.APPLIED,
                ChangeStatus.VERIFIED,
                ChangeStatus.FAILED,
                ChangeStatus.ROLLBACK_REQUIRED,
            }:
                continue

            control = controls.get(change.control_id)

            if control is None:
                change.status = ChangeStatus.ROLLBACK_REQUIRED
                change.rollback_message = (
                    "Control definition is unavailable; rollback cannot "
                    "be safely performed."
                )

                results.append(
                    RollbackExecution(
                        control_id=change.control_id,
                        host=change.host,
                        result=ExecutionResult(
                            control_id=change.control_id,
                            host=change.host,
                            status=ExecutionStatus.FAILED,
                            changed=False,
                            message=change.rollback_message,
                        ),
                    )
                )
                continue

            try:
                result = self.rollback_control(
                    control=control,
                    host=change.host,
                    transaction=transaction,
                )
            except RollbackError as exc:
                change.status = ChangeStatus.ROLLBACK_REQUIRED
                change.rollback_message = str(exc)

                result = RollbackExecution(
                    control_id=change.control_id,
                    host=change.host,
                    result=ExecutionResult(
                        control_id=change.control_id,
                        host=change.host,
                        status=ExecutionStatus.FAILED,
                        changed=False,
                        message=str(exc),
                    ),
                )

            results.append(result)

        if all(result.succeeded for result in results):
            transaction.mark_rolled_back()
        else:
            transaction.status = TransactionStatus.ROLLBACK_REQUIRED

        return tuple(results)