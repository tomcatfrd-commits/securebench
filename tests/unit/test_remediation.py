from __future__ import annotations

from dataclasses import dataclass

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.result import ComplianceStatus, ExecutionStatus
from securebench.core.transaction import Transaction
from securebench.policy.classifier import ControlClassifier
from securebench.policy.engine import PolicyEngine
from securebench.remediation.engine import RemediationEngine
from securebench.remediation.planner import (
    PlanAction,
    RemediationPlan,
    RemediationPlanItem,
    RemediationPlanner,
)


def make_control(
    control_id: str = "TEST-1",
    classification: SafetyClassification = SafetyClassification.SAFE,
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=rollback_capability,
        metadata={
            "safety": {
                "default": classification.value,
                "prechecks": (),
            },
            "requirements": {
                "setting": "expected",
            },
        },
    )


@dataclass
class FakeRemediationProvider:
    precheck_result: bool = True
    remediation_success: bool = True

    def __post_init__(self) -> None:
        self.precheck_calls: list[tuple[str, str]] = []
        self.remediation_calls: list[tuple[str, str]] = []

    def precheck(self, control: Control, host: str) -> bool:
        self.precheck_calls.append((control.control_id, host))
        return self.precheck_result

    def remediate(self, control: Control, host: str):
        self.remediation_calls.append((control.control_id, host))

        return {
            "success": self.remediation_success,
            "changed": self.remediation_success,
            "message": (
                "Remediation succeeded."
                if self.remediation_success
                else "Remediation failed."
            ),
        }


def make_plan_item(
    control: Control,
    action: PlanAction,
    host: str = "server01",
) -> RemediationPlanItem:
    return RemediationPlanItem(
        control=control,
        host=host,
        action=action,
        reason=f"Test action: {action.value}",
    )


def make_plan(*items: RemediationPlanItem) -> RemediationPlan:
    return RemediationPlan(items=tuple(items))


def test_remediation_engine_applies_remediate_action() -> None:
    provider = FakeRemediationProvider()
    engine = RemediationEngine(provider=provider)

    control = make_control()
    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.REMEDIATE,
        )
    )

    transaction = Transaction(transaction_id="tx-001")

    results = engine.execute(plan, transaction)

    assert len(results) == 1
    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].control_id == "TEST-1"
    assert results[0].host == "server01"

    assert provider.remediation_calls == [
        ("TEST-1", "server01"),
    ]


def test_remediation_engine_runs_precheck_before_remediation() -> None:
    provider = FakeRemediationProvider(precheck_result=True)
    engine = RemediationEngine(provider=provider)

    control = make_control(
        classification=SafetyClassification.SAFE_WITH_PRECHECK,
    )

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.PRECHECK,
        )
    )

    transaction = Transaction(transaction_id="tx-002")

    results = engine.execute(plan, transaction)

    assert len(results) == 1
    assert results[0].status is ExecutionStatus.SUCCESS

    assert provider.precheck_calls == [
        ("TEST-1", "server01"),
    ]

    assert provider.remediation_calls == [
        ("TEST-1", "server01"),
    ]


def test_failed_precheck_blocks_remediation() -> None:
    provider = FakeRemediationProvider(precheck_result=False)
    engine = RemediationEngine(provider=provider)

    control = make_control(
        classification=SafetyClassification.SAFE_WITH_PRECHECK,
    )

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.PRECHECK,
        )
    )

    transaction = Transaction(transaction_id="tx-003")

    results = engine.execute(plan, transaction)

    assert len(results) == 1
    assert results[0].status is ExecutionStatus.FAILED

    assert provider.precheck_calls == [
        ("TEST-1", "server01"),
    ]

    assert provider.remediation_calls == []


def test_failed_remediation_returns_failed_result() -> None:
    provider = FakeRemediationProvider(remediation_success=False)
    engine = RemediationEngine(provider=provider)

    control = make_control()

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.REMEDIATE,
        )
    )

    transaction = Transaction(transaction_id="tx-004")

    results = engine.execute(plan, transaction)

    assert len(results) == 1
    assert results[0].status is ExecutionStatus.FAILED
    assert provider.remediation_calls == [
        ("TEST-1", "server01"),
    ]


@pytest.mark.parametrize(
    "action",
    [
        PlanAction.SKIP,
        PlanAction.INVESTIGATE,
        PlanAction.APPROVAL_REQUIRED,
    ],
)
def test_non_executable_actions_are_not_remediated(
    action: PlanAction,
) -> None:
    provider = FakeRemediationProvider()
    engine = RemediationEngine(provider=provider)

    control = make_control()

    plan = make_plan(
        make_plan_item(
            control,
            action,
        )
    )

    transaction = Transaction(transaction_id="tx-005")

    results = engine.execute(plan, transaction)

    assert len(results) == 1
    assert results[0].status in {
        ExecutionStatus.SUCCESS,
        ExecutionStatus.FAILED,
    }

    assert provider.precheck_calls == []
    assert provider.remediation_calls == []


def test_empty_plan_produces_no_results() -> None:
    provider = FakeRemediationProvider()
    engine = RemediationEngine(provider=provider)

    transaction = Transaction(transaction_id="tx-006")

    results = engine.execute(
        make_plan(),
        transaction,
    )

    assert results == ()
    assert provider.precheck_calls == []
    assert provider.remediation_calls == []


def test_remediation_preserves_plan_order() -> None:
    provider = FakeRemediationProvider()
    engine = RemediationEngine(provider=provider)

    controls = [
        make_control("TEST-1"),
        make_control("TEST-2"),
        make_control("TEST-3"),
    ]

    plan = make_plan(
        make_plan_item(controls[0], PlanAction.REMEDIATE),
        make_plan_item(controls[1], PlanAction.REMEDIATE),
        make_plan_item(controls[2], PlanAction.REMEDIATE),
    )

    transaction = Transaction(transaction_id="tx-007")

    results = engine.execute(plan, transaction)

    assert [result.control_id for result in results] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]

    assert provider.remediation_calls == [
        ("TEST-1", "server01"),
        ("TEST-2", "server01"),
        ("TEST-3", "server01"),
    ]


def test_precheck_is_not_remediation_when_precheck_fails() -> None:
    provider = FakeRemediationProvider(precheck_result=False)
    engine = RemediationEngine(provider=provider)

    control = make_control(
        classification=SafetyClassification.SAFE_WITH_PRECHECK,
    )

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.PRECHECK,
        )
    )

    transaction = Transaction(transaction_id="tx-008")

    result = engine.execute(plan, transaction)[0]

    assert result.status is ExecutionStatus.FAILED
    assert provider.precheck_calls
    assert provider.remediation_calls == []


def test_remediation_failure_does_not_report_success() -> None:
    provider = FakeRemediationProvider(remediation_success=False)
    engine = RemediationEngine(provider=provider)

    control = make_control()

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.REMEDIATE,
        )
    )

    transaction = Transaction(transaction_id="tx-009")

    result = engine.execute(plan, transaction)[0]

    assert result.status is not ExecutionStatus.SUCCESS


def test_transaction_receives_change_record_for_successful_remediation() -> None:
    provider = FakeRemediationProvider()
    engine = RemediationEngine(provider=provider)

    control = make_control()

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.REMEDIATE,
        )
    )

    transaction = Transaction(transaction_id="tx-010")

    results = engine.execute(plan, transaction)

    assert results[0].status is ExecutionStatus.SUCCESS
    assert transaction.change_count == 1
    assert transaction.successful_changes


def test_remediation_engine_does_not_modify_control() -> None:
    provider = FakeRemediationProvider()
    engine = RemediationEngine(provider=provider)

    control = make_control()

    original = (
        control.control_id,
        control.title,
        control.description,
        control.metadata,
    )

    plan = make_plan(
        make_plan_item(
            control,
            PlanAction.REMEDIATE,
        )
    )

    transaction = Transaction(transaction_id="tx-011")

    engine.execute(plan, transaction)

    current = (
        control.control_id,
        control.title,
        control.description,
        control.metadata,
    )

    assert current == original