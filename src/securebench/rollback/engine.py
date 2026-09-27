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
from typing import Any, Protocol

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Control,
    Profile,
    RollbackCapability,
    Transaction,
)


class RollbackProvider(Protocol):
    """
    Interface implemented by control-specific rollback providers.
    """

    def rollback(
        self,
        control: Control,
        host: str,
    ) -> "RollbackExecution":
        """
        Restore one control on one host.
        """
        ...


@dataclass(frozen=True, slots=True)
class RollbackExecution:
    """
    Result of rolling back one control.
    """

    control_id: str
    host: str
    success: bool
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.control_id, str) or not self.control_id.strip():
            raise ValueError("control_id must be a non-empty string")
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("message must be a non-empty string")

    @property
    def succeeded(self) -> bool:
        """Return True only when rollback completed successfully."""

        return self.success


@dataclass(frozen=True, slots=True)
class TransactionRollbackResult:
    """Aggregate result of rolling back a whole transaction."""

    success: bool
    executions: tuple[RollbackExecution, ...] = ()


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
        profile: Profile | None = None,
    ) -> RollbackExecution:
        """
        Roll back one control within a transaction.

        Unsupported or disallowed best-effort rollback fails closed
        without calling the provider.
        """
        change = self._find_change(transaction, control.control_id, host)

        if change is None:
            return RollbackExecution(
                control_id=control.control_id,
                host=host,
                success=False,
                message=(
                    f"No change found for control '{control.control_id}' "
                    f"on host '{host}'."
                ),
            )

        if control.rollback_capability is RollbackCapability.UNSUPPORTED:
            return RollbackExecution(
                control_id=control.control_id,
                host=host,
                success=False,
                message=(
                    f"Rollback unsupported for control '{control.control_id}'."
                ),
            )

        if control.rollback_capability is RollbackCapability.BEST_EFFORT:
            allow = (
                profile is not None
                and getattr(profile, "allow_best_effort_rollback", False)
            )
            if not allow:
                return RollbackExecution(
                    control_id=control.control_id,
                    host=host,
                    success=False,
                    message=(
                        f"Best-effort rollback for control "
                        f"'{control.control_id}' is denied by policy."
                    ),
                )

        if change.status is not ChangeStatus.SUCCESS:
            return RollbackExecution(
                control_id=control.control_id,
                host=host,
                success=False,
                message=(
                    f"Only successful changes can be rolled back; "
                    f"change status is '{change.status.value}'."
                ),
            )

        try:
            raw = self._call_provider(control=control, host=host, change=change)
        except Exception as exc:
            change.status = ChangeStatus.ROLLBACK_REQUIRED
            return RollbackExecution(
                control_id=control.control_id,
                host=host,
                success=False,
                message=str(exc) or "Provider raised an unexpected error.",
            )

        result = self._normalize_result(
            raw,
            control_id=control.control_id,
            host=host,
        )

        if result.success:
            change.status = ChangeStatus.ROLLED_BACK
        else:
            change.status = ChangeStatus.ROLLBACK_REQUIRED

        return result

    def rollback_transaction(
        self,
        *,
        transaction: Transaction,
        controls: dict[str, Control],
        profile: Profile | None = None,
    ) -> TransactionRollbackResult:
        """
        Roll back all successful changes in reverse order.

        Stops early on the first failure (fail-closed).
        An empty transaction is treated as successfully rolled back.
        """
        results: list[RollbackExecution] = []

        for change in reversed(transaction.changes):
            if change.status is not ChangeStatus.SUCCESS:
                continue

            control = controls.get(change.control_id)
            if control is None:
                # Coordinator tests expect KeyError for missing definitions.
                raise KeyError(change.control_id)

            result = self.rollback_control(
                control=control,
                host=change.host,
                transaction=transaction,
                profile=profile,
            )
            results.append(result)

            if not result.success:
                break

        # Empty result set (no successful changes to roll back) is success.
        overall_success = all(r.success for r in results)

        if overall_success and not any(
            c.status is ChangeStatus.SUCCESS for c in transaction.changes
        ):
            transaction.mark_rolled_back()
        elif results and not overall_success:
            transaction.mark_rollback_required()

        return TransactionRollbackResult(
            success=overall_success,
            executions=tuple(results),
        )

    def _call_provider(
        self,
        *,
        control: Control,
        host: str,
        change: ChangeRecord,
    ) -> Any:
        """
        Call the provider with either (control, host, change) or (control, host).
        """
        try:
            return self._provider.rollback(
                control=control,
                host=host,
                change=change,
            )
        except TypeError:
            return self._provider.rollback(
                control=control,
                host=host,
            )

    @staticmethod
    def _normalize_result(
        raw: Any,
        *,
        control_id: str,
        host: str,
    ) -> RollbackExecution:
        if isinstance(raw, RollbackExecution):
            return raw

        if isinstance(raw, bool):
            return RollbackExecution(
                control_id=control_id,
                host=host,
                success=raw,
                message=(
                    "Rollback completed" if raw else "Rollback failed"
                ),
            )

        success = bool(getattr(raw, "success", False))
        message = str(getattr(raw, "message", "") or "")
        if not message:
            message = (
                "Rollback completed" if success else "Rollback failed"
            )
        return RollbackExecution(
            control_id=control_id,
            host=host,
            success=success,
            message=message,
        )

    @staticmethod
    def _find_change(
        transaction: Transaction,
        control_id: str,
        host: str,
    ) -> ChangeRecord | None:
        for change in transaction.changes:
            if change.control_id == control_id and change.host == host:
                return change
        return None