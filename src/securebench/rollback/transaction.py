"""
Transaction-level rollback coordination.
"""

from __future__ import annotations

from dataclasses import dataclass

from securebench.core import (
    Control,
    Transaction,
)

from .engine import RollbackEngine, RollbackExecution
from .snapshot import Snapshot, SnapshotProvider


@dataclass(frozen=True, slots=True)
class TransactionRollbackResult:
    """Complete result of a transaction rollback operation."""

    success: bool
    transaction_id: str = ""
    control_results: tuple[RollbackExecution, ...] = ()
    snapshot_restored: bool = False
    snapshot: Snapshot | None = None

    @property
    def succeeded(self) -> bool:
        return self.success


class TransactionRollbackCoordinator:
    """
    Coordinate rollback of a complete SecureBench transaction.
    """

    def __init__(
        self,
        *,
        rollback_engine: RollbackEngine,
        snapshot_provider: SnapshotProvider | None = None,
    ) -> None:
        self._rollback_engine = rollback_engine
        self._snapshot_provider = snapshot_provider

    def rollback(
        self,
        *,
        transaction: Transaction,
        controls: dict[str, Control],
        snapshot: Snapshot | None = None,
        profile=None,
    ) -> TransactionRollbackResult:
        """
        Roll back successful changes in reverse order via the rollback engine.
        """
        # Coordinator tests expect KeyError when a successful change has no
        # control definition in the supplied map.
        for change in transaction.changes:
            if change.status is None:
                continue
            from securebench.core import ChangeStatus

            if (
                change.status is ChangeStatus.SUCCESS
                and change.control_id not in controls
            ):
                raise KeyError(change.control_id)

        engine_result = self._rollback_engine.rollback_transaction(
            transaction=transaction,
            controls=controls,
            profile=profile,
        )

        success = bool(getattr(engine_result, "success", False))
        executions = tuple(getattr(engine_result, "executions", ()) or ())

        snapshot_restored = False
        if snapshot is not None and success:
            if self._snapshot_provider is None:
                success = False
            else:
                try:
                    snapshot_restored = bool(
                        self._snapshot_provider.restore(snapshot)
                    )
                    success = success and snapshot_restored
                except Exception:
                    success = False
                    snapshot_restored = False

        if success:
            transaction.mark_rolled_back()
        elif transaction.changes:
            try:
                transaction.mark_rollback_required()
            except Exception:
                pass

        return TransactionRollbackResult(
            success=success,
            transaction_id=transaction.transaction_id,
            control_results=executions,
            snapshot_restored=snapshot_restored,
            snapshot=snapshot,
        )