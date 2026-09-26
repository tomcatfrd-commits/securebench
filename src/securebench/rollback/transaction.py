"""
Transaction-level rollback coordination.

This module coordinates control rollback and optional infrastructure
snapshot restoration.

The important distinction is:

    Control rollback
        restores individual configuration changes.

    Snapshot rollback
        restores a broader system state.

A transaction may use either mechanism or both, depending on policy and
control capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass

from securebench.core import (
    ExecutionResult,
    ExecutionStatus,
    RollbackError,
    Transaction,
    TransactionStatus,
)

from .engine import RollbackEngine, RollbackExecution
from .snapshot import Snapshot, SnapshotProvider


@dataclass(frozen=True, slots=True)
class TransactionRollbackResult:
    """
    Complete result of a transaction rollback operation.
    """

    transaction_id: str
    control_results: tuple[RollbackExecution, ...]
    snapshot_restored: bool = False
    snapshot: Snapshot | None = None

    @property
    def succeeded(self) -> bool:
        """
        Return True only when every requested rollback mechanism succeeded.
        """

        return all(
            result.succeeded
            for result in self.control_results
        ) and (
            self.snapshot is None
            or self.snapshot_restored
        )


class TransactionRollbackCoordinator:
    """
    Coordinate rollback of a complete SecureBench transaction.

    This class deliberately does not decide whether rollback should happen.
    That decision belongs to the transaction lifecycle and higher-level
    orchestration.

    Its responsibility is to perform the requested rollback consistently.
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
        controls: dict[str, object],
        snapshot: Snapshot | None = None,
    ) -> TransactionRollbackResult:
        """
        Roll back a transaction.

        ``controls`` is intentionally accepted as a mapping whose values are
        validated at runtime by RollbackEngine. This keeps this coordinator
        independent of benchmark loading details while allowing the existing
        rollback engine to remain authoritative.

        If a snapshot is supplied, it is restored only after control-level
        rollback has been attempted successfully.

        The coordinator fails closed when snapshot restoration is requested
        but no snapshot provider is configured.
        """

        if transaction.status not in {
            TransactionStatus.ROLLBACK_REQUIRED,
            TransactionStatus.FAILED,
        }:
            raise RollbackError(
                f"transaction '{transaction.transaction_id}' is in state "
                f"'{transaction.status.value}' and cannot be rolled back"
            )

        typed_controls = self._validate_controls(controls)

        control_results = self._rollback_engine.rollback_transaction(
            controls=typed_controls,
            transaction=transaction,
        )

        all_controls_succeeded = all(
            result.succeeded
            for result in control_results
        )

        if not all_controls_succeeded:
            transaction.status = TransactionStatus.ROLLBACK_REQUIRED

            return TransactionRollbackResult(
                transaction_id=transaction.transaction_id,
                control_results=control_results,
                snapshot_restored=False,
                snapshot=snapshot,
            )

        if snapshot is None:
            return TransactionRollbackResult(
                transaction_id=transaction.transaction_id,
                control_results=control_results,
                snapshot_restored=False,
                snapshot=None,
            )

        if self._snapshot_provider is None:
            transaction.status = TransactionStatus.ROLLBACK_REQUIRED

            raise RollbackError(
                "snapshot restoration was requested, but no snapshot "
                "provider is configured"
            )

        try:
            self._snapshot_provider.restore(
                snapshot=snapshot,
            )
        except Exception as exc:
            transaction.status = TransactionStatus.ROLLBACK_REQUIRED

            raise RollbackError(
                f"failed to restore snapshot '{snapshot.snapshot_id}': {exc}"
            ) from exc

        transaction.status = TransactionStatus.ROLLED_BACK

        return TransactionRollbackResult(
            transaction_id=transaction.transaction_id,
            control_results=control_results,
            snapshot_restored=True,
            snapshot=snapshot,
        )

    @staticmethod
    def _validate_controls(
        controls: dict[str, object],
    ) -> dict[str, object]:
        """
        Validate the control mapping before rollback starts.

        The actual control type validation remains in RollbackEngine because
        this coordinator should not duplicate its domain rules.
        """

        if not controls:
            raise RollbackError(
                "transaction rollback requires at least one control definition"
            )

        for control_id in controls:
            if not isinstance(control_id, str) or not control_id.strip():
                raise RollbackError(
                    "control mapping contains an invalid control ID"
                )

        return controls