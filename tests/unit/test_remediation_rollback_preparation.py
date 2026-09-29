from __future__ import annotations

from pathlib import Path

from securebench.core import (
    ChangeStatus,
    ExecutionResult,
    ExecutionStatus,
    Transaction,
    TransactionStore,
)
from securebench.remediation.engine import RemediationEngine, RollbackPreparation
from securebench.remediation.planner import PlanAction, RemediationPlan, RemediationPlanItem


class PreparedProvider:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def prepare_rollback(self, control, host):
        self.calls.append("prepare")
        return RollbackPreparation(
            before={"module_loaded": False},
            rollback_data={"state_path": "/var/lib/securebench/tx-001"},
        )

    def remediate(self, control, host):
        self.calls.append("remediate")
        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
        )


def test_production_mode_persists_rollback_data_before_remediation(
    tmp_path: Path,
    control,
) -> None:
    provider = PreparedProvider()
    store = TransactionStore(tmp_path)
    transaction = Transaction(
        transaction_id="tx-001",
        benchmark_id=control.benchmark_id,
        benchmark_version=control.benchmark_version or "2.0.0",
    )
    plan = RemediationPlan(
        items=(
            RemediationPlanItem(
                control=control,
                host="server01",
                action=PlanAction.REMEDIATE,
                reason="Approved production remediation.",
            ),
        )
    )

    result = RemediationEngine(
        provider,
        transaction_store=store,
        require_rollback_data=True,
    ).execute(plan, transaction)

    assert result[0].status is ExecutionStatus.SUCCESS
    assert provider.calls == ["prepare", "remediate"]
    assert transaction.changes[0].status is ChangeStatus.SUCCESS
    assert transaction.changes[0].rollback_data
    assert store.load("tx-001").changes[0].rollback_data


def test_production_mode_refuses_provider_without_state_capture(control) -> None:
    class UnsafeProvider:
        def remediate(self, control, host):
            raise AssertionError("must not execute")

    plan = RemediationPlan(
        items=(
            RemediationPlanItem(
                control=control,
                host="server01",
                action=PlanAction.REMEDIATE,
                reason="Test.",
            ),
        )
    )

    result = RemediationEngine(
        UnsafeProvider(),
        require_rollback_data=True,
    ).execute(plan, Transaction(transaction_id="tx-unsafe"))

    assert result[0].status is ExecutionStatus.FAILED
    assert "capture rollback state" in result[0].message
