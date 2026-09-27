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
    Profile,
    RollbackCapability,
    RollbackError,
    Transaction,
    TransactionStatus,
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
    message: str = ""

    @property
    def succeeded(self) -> bool:
        """Return True only when rollback completed successfully."""

        return self.success


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
        # Locate the matching change by control_id + host
        change = self._find_change(transaction, control.control_id, host)

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
                    f"change is in state '{change.status.value}'."
                ),
            )

        try:
            result = self._provider.rollback(control=control, host=host)
        except Exception as exc:  # provider failure must not mark rolled back
            change.status = ChangeStatus.ROLLBACK_REQUIRED
            return RollbackExecution(
                control_id=control.control_id,
                host=host,
                success=False,
                message=str(exc),
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
    ) -> tuple[RollbackExecution, ...]:
        """
        Roll back all successful changes in reverse order.

        Stops early on the first failure (fail-closed).
        """
        results: list[RollbackExecution] = []

        for change in reversed(transaction.changes):
            if change.status is not ChangeStatus.SUCCESS:
                continue

            control = controls.get(change.control_id)
            if control is None:
                change.status = ChangeStatus.ROLLBACK_REQUIRED
                results.append(
                    RollbackExecution(
                        control_id=change.control_id,
                        host=change.host,
                        success=False,
                        message=(
                            "Control definition is missing; "
                            "rollback cannot be performed."
                        ),
                    )
                )
                # fail-closed: stop further rollbacks
                break

            result = self.rollback_control(
                control=control,
                host=change.host,
                transaction=transaction,
                profile=profile,
            )
            results.append(result)

            if not result.success:
                break

        if results and all(r.success for r in results):
            # only mark fully rolled back when every attempted change succeeded
            # and no successful changes remain
            if not any(
                c.status is ChangeStatus.SUCCESS for c in transaction.changes
            ):
                transaction.mark_rolled_back()
        elif results:
            transaction.mark_rollback_required()

        return tuple(results)

    @staticmethod
    def _find_change(
        transaction: Transaction,
        control_id: str,
        host: str,
    ) -> ChangeRecord:
        for change in transaction.changes:
            if change.control_id == control_id and change.host == host:
                return change
        raise RollbackError(
            f"No change found for control '{control_id}' on host '{host}'."
        )