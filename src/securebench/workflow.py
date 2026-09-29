"""Production remediation workflow with mandatory verification and rollback."""

from __future__ import annotations

from dataclasses import dataclass

from securebench.core import (
    ChangeStatus,
    ComplianceStatus,
    Control,
    ExecutionStatus,
    Profile,
    Transaction,
    TransactionStore,
    VerificationResult,
)
from securebench.remediation import RemediationEngine, RemediationPlan, RemediationResult
from securebench.rollback import RollbackEngine
from securebench.rollback.engine import TransactionRollbackResult
from securebench.verification import VerificationEngine


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    committed: bool
    rolled_back: bool
    remediation_results: tuple[RemediationResult, ...]
    verification_results: tuple[VerificationResult, ...]
    rollback_result: TransactionRollbackResult | None = None


class ProductionRemediationWorkflow:
    """Apply an immutable plan and never commit without verification."""

    def __init__(
        self,
        *,
        remediation_engine: RemediationEngine,
        verification_engine: VerificationEngine,
        rollback_engine: RollbackEngine,
        transaction_store: TransactionStore,
    ) -> None:
        self._remediation_engine = remediation_engine
        self._verification_engine = verification_engine
        self._rollback_engine = rollback_engine
        self._transaction_store = transaction_store

    def execute(
        self,
        *,
        plan: RemediationPlan,
        transaction: Transaction,
        controls: dict[str, Control],
        profile: Profile,
    ) -> WorkflowResult:
        self._transaction_store.save(transaction)
        remediation_results = self._remediation_engine.execute(plan, transaction)

        remediation_failed = any(
            result.status is ExecutionStatus.FAILED
            for result in remediation_results
        )
        verification_results: list[VerificationResult] = []

        if not remediation_failed:
            for change in transaction.changes:
                if change.status is not ChangeStatus.SUCCESS:
                    continue
                control = controls.get(change.control_id)
                if control is None:
                    remediation_failed = True
                    break
                verification = self._verification_engine.verify(
                    control,
                    change.host,
                )
                verification_results.append(verification)
                if verification.status is not ComplianceStatus.PASS:
                    remediation_failed = True
                    break

        if not remediation_failed:
            transaction.mark_committed()
            self._transaction_store.save(transaction)
            return WorkflowResult(
                committed=True,
                rolled_back=False,
                remediation_results=remediation_results,
                verification_results=tuple(verification_results),
            )

        transaction.mark_rollback_required()
        self._transaction_store.save(transaction)
        rollback_result = self._rollback_engine.rollback_transaction(
            transaction=transaction,
            controls=controls,
            profile=profile,
        )
        self._transaction_store.save(transaction)
        return WorkflowResult(
            committed=False,
            rolled_back=rollback_result.success,
            remediation_results=remediation_results,
            verification_results=tuple(verification_results),
            rollback_result=rollback_result,
        )
