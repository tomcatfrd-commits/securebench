from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from securebench.core import (
    ComplianceStatus,
    ExecutionResult,
    ExecutionStatus,
    Profile,
    Transaction,
    TransactionStatus,
    TransactionStore,
    VerificationResult,
)
from securebench.remediation import RemediationEngine
from securebench.remediation.engine import RollbackPreparation
from securebench.remediation.planner import PlanAction, RemediationPlan, RemediationPlanItem
from securebench.rollback import RollbackEngine, RollbackExecution
from securebench.verification import VerificationEngine
from securebench.workflow import ProductionRemediationWorkflow


class WorkflowProvider:
    def prepare_rollback(self, control, host):
        return RollbackPreparation(
            before={"value": "before"},
            rollback_data={"backup": "stored"},
        )

    def remediate(self, control, host):
        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
        )


class VerificationProvider:
    def __init__(self, status: ComplianceStatus) -> None:
        self.status = status

    def verify(self, control, host):
        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=self.status,
        )


class RollbackProvider:
    def __init__(self) -> None:
        self.calls = 0

    def rollback(self, control, host, change):
        self.calls += 1
        assert change.rollback_data == {"backup": "stored"}
        return RollbackExecution(
            control_id=control.control_id,
            host=host,
            success=True,
            message="Original state restored.",
        )


def build_workflow(
    tmp_path: Path,
    verification_status: ComplianceStatus,
):
    store = TransactionStore(tmp_path)
    remediation_provider = WorkflowProvider()
    rollback_provider = RollbackProvider()
    workflow = ProductionRemediationWorkflow(
        remediation_engine=RemediationEngine(
            remediation_provider,
            transaction_store=store,
            require_rollback_data=True,
        ),
        verification_engine=VerificationEngine(
            VerificationProvider(verification_status)
        ),
        rollback_engine=RollbackEngine(rollback_provider),
        transaction_store=store,
    )
    return workflow, store, rollback_provider


def workflow_inputs(control, profile):
    control = replace(
        control,
        benchmark_version="2.0.0",
        definition_digest="a" * 64,
    )
    profile = replace(
        profile,
        benchmark_id=control.benchmark_id,
        benchmark_version=control.benchmark_version,
    )
    transaction = Transaction(
        transaction_id="tx-workflow",
        profile_id=profile.profile_id,
        benchmark_id=control.benchmark_id,
        benchmark_version=control.benchmark_version,
        host="server01",
    )
    plan = RemediationPlan(
        items=(
            RemediationPlanItem(
                control=control,
                host="server01",
                action=PlanAction.REMEDIATE,
                reason="Approved test remediation.",
            ),
        )
    )
    return control, profile, transaction, plan


def test_workflow_commits_only_after_successful_verification(
    tmp_path: Path,
    control,
    profile: Profile,
) -> None:
    workflow, store, rollback_provider = build_workflow(
        tmp_path,
        ComplianceStatus.PASS,
    )
    control, profile, transaction, plan = workflow_inputs(control, profile)

    result = workflow.execute(
        plan=plan,
        transaction=transaction,
        controls={control.control_id: control},
        profile=profile,
    )

    assert result.committed is True
    assert result.rolled_back is False
    assert transaction.status is TransactionStatus.COMMITTED
    assert store.load(transaction.transaction_id).status is TransactionStatus.COMMITTED
    assert rollback_provider.calls == 0


def test_workflow_rolls_back_failed_verification(
    tmp_path: Path,
    control,
    profile: Profile,
) -> None:
    workflow, store, rollback_provider = build_workflow(
        tmp_path,
        ComplianceStatus.FAIL,
    )
    control, profile, transaction, plan = workflow_inputs(control, profile)

    result = workflow.execute(
        plan=plan,
        transaction=transaction,
        controls={control.control_id: control},
        profile=profile,
    )

    assert result.committed is False
    assert result.rolled_back is True
    assert transaction.status is TransactionStatus.ROLLED_BACK
    assert store.load(transaction.transaction_id).status is TransactionStatus.ROLLED_BACK
    assert rollback_provider.calls == 1
