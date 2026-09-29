from __future__ import annotations

from securebench.core import (
    ChangeStatus,
    ExecutionResult,
    ExecutionStatus,
)
from securebench.remediation.engine import RemediationEngine
from securebench.remediation.planner import (
    PlanAction,
    RemediationPlan,
    RemediationPlanItem,
)


def make_plan(
    control,
    *,
    action: PlanAction,
    host: str = "production-01",
    reason: str = "Test plan.",
) -> RemediationPlan:
    return RemediationPlan(
        items=(
            RemediationPlanItem(
                control=control,
                host=host,
                action=action,
                reason=reason,
            ),
        )
    )


class RecordingProvider:
    def __init__(self) -> None:
        self.prechecks: list[tuple[str, str]] = []
        self.remediations: list[tuple[str, str]] = []

    def precheck(self, control, host: str):
        self.prechecks.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=False,
            message="Precheck passed.",
        )

    def remediate(self, control, host: str):
        self.remediations.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
            message="Remediation completed.",
        )


class FailingPrecheckProvider(RecordingProvider):
    def precheck(self, control, host: str):
        self.prechecks.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.FAILED,
            changed=False,
            message="Precheck failed.",
        )


class FailingRemediationProvider(RecordingProvider):
    def remediate(self, control, host: str):
        self.remediations.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.FAILED,
            changed=False,
            message="Remediation failed.",
        )


class RaisingRemediationProvider(RecordingProvider):
    def remediate(self, control, host: str):
        self.remediations.append((control.control_id, host))
        raise RuntimeError("backend failure")


def test_remediate_action_calls_provider_once(
    control,
    transaction,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert len(results) == 1
    assert results[0].control_id == control.control_id
    assert results[0].host == "production-01"
    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is True

    assert provider.prechecks == []
    assert provider.remediations == [
        (control.control_id, "production-01"),
    ]

    assert transaction.change_count == 1
    assert transaction.changes[0].control_id == control.control_id
    assert transaction.changes[0].host == "production-01"
    assert transaction.changes[0].status is ChangeStatus.SUCCESS


def test_precheck_action_runs_precheck_before_remediation(
    control,
    transaction,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.PRECHECK,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is True

    assert provider.prechecks == [
        (control.control_id, "production-01"),
    ]
    assert provider.remediations == [
        (control.control_id, "production-01"),
    ]

    assert transaction.change_count == 1
    assert transaction.changes[0].status is ChangeStatus.SUCCESS


def test_failed_precheck_prevents_remediation(
    control,
    transaction,
) -> None:
    provider = FailingPrecheckProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.PRECHECK,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False
    assert results[0].message == "Precheck failed."

    assert provider.prechecks == [
        (control.control_id, "production-01"),
    ]
    assert provider.remediations == []

    # A failed precheck must not create a remediation change.
    assert transaction.change_count == 0


def test_failed_remediation_is_recorded_in_transaction(
    control,
    transaction,
) -> None:
    provider = FailingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False
    assert results[0].message == "Remediation failed."

    assert provider.remediations == [
        (control.control_id, "production-01"),
    ]

    assert transaction.change_count == 1
    assert transaction.changes[0].status is ChangeStatus.FAILED
    assert transaction.changes[0].control_id == control.control_id


def test_provider_exception_becomes_failed_execution_result(
    control,
    transaction,
) -> None:
    provider = RaisingRemediationProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False
    assert "backend failure" in results[0].message

    assert provider.remediations == [
        (control.control_id, "production-01"),
    ]

    assert transaction.change_count == 1
    assert transaction.changes[0].status is ChangeStatus.FAILED
    assert transaction.changes[0].message == "backend failure"


def test_skip_action_never_calls_provider(
    control,
    transaction,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.SKIP,
        reason="Already compliant.",
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is False
    assert results[0].message == "Already compliant."

    assert provider.prechecks == []
    assert provider.remediations == []
    assert transaction.change_count == 0


def test_investigate_action_never_calls_provider(
    control,
    transaction,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.INVESTIGATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is False

    assert provider.prechecks == []
    assert provider.remediations == []
    assert transaction.change_count == 0


def test_approval_required_action_never_calls_provider(
    control,
    transaction,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.APPROVAL_REQUIRED,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is False

    assert provider.prechecks == []
    assert provider.remediations == []
    assert transaction.change_count == 0


def test_engine_requires_transaction_for_execution(
    control,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    try:
        engine.execute(plan)  # type: ignore[call-arg]
    except TypeError:
        pass
    else:
        raise AssertionError(
            "RemediationEngine.execute() must require a Transaction."
        )


def test_empty_plan_does_not_touch_transaction(
    transaction,
) -> None:
    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = RemediationPlan(items=())

    results = engine.execute(
        plan,
        transaction,
    )

    assert results == ()
    assert transaction.change_count == 0
    assert provider.prechecks == []
    assert provider.remediations == []


def test_engine_preserves_control_identity(
    control,
    transaction,
) -> None:
    received: list[object] = []

    class IdentityProvider(RecordingProvider):
        def remediate(self, received_control, host: str):
            received.append(received_control)

            return super().remediate(
                received_control,
                host,
            )

    provider = IdentityProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    engine.execute(
        plan,
        transaction,
    )

    assert received == [control]
    assert received[0] is control


def test_multiple_plan_items_share_the_same_transaction(
    control,
    transaction,
) -> None:
    second_control = type(control)(
        control_id="TEST-002",
        benchmark_id=control.benchmark_id,
        title="Second test control",
        description=control.description,
        platform=control.platform,
        severity=control.severity,
        audit=control.audit,
        remediation=control.remediation,
        rollback=control.rollback,
        verification=control.verification,
        rollback_capability=control.rollback_capability,
    )

    provider = RecordingProvider()
    engine = RemediationEngine(provider=provider)

    plan = RemediationPlan(
        items=(
            RemediationPlanItem(
                control=control,
                host="production-01",
                action=PlanAction.REMEDIATE,
                reason="First control.",
            ),
            RemediationPlanItem(
                control=second_control,
                host="production-01",
                action=PlanAction.REMEDIATE,
                reason="Second control.",
            ),
        )
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert len(results) == 2
    assert all(
        result.status is ExecutionStatus.SUCCESS
        for result in results
    )

    assert transaction.change_count == 2
    assert [
        change.control_id
        for change in transaction.changes
    ] == [
        "TEST-001",
        "TEST-002",
    ]


def test_provider_mapping_result_is_normalized(
    control,
    transaction,
) -> None:
    class MappingProvider(RecordingProvider):
        def remediate(self, control, host: str):
            self.remediations.append(
                (control.control_id, host),
            )

            return {
                "success": True,
                "changed": False,
                "message": "No change was necessary.",
            }

    provider = MappingProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is False
    assert results[0].message == "No change was necessary."

    assert transaction.change_count == 1
    assert transaction.changes[0].status is ChangeStatus.SUCCESS


def test_truthy_provider_result_is_normalized(
    control,
    transaction,
) -> None:
    class BooleanProvider(RecordingProvider):
        def remediate(self, control, host: str):
            self.remediations.append(
                (control.control_id, host),
            )
            return True

    provider = BooleanProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.SUCCESS
    assert results[0].changed is True
    assert transaction.change_count == 1
    assert transaction.changes[0].status is ChangeStatus.SUCCESS


def test_falsy_provider_result_is_recorded_as_failure(
    control,
    transaction,
) -> None:
    class FalseProvider(RecordingProvider):
        def remediate(self, control, host: str):
            self.remediations.append(
                (control.control_id, host),
            )
            return False

    provider = FalseProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.REMEDIATE,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False
    assert transaction.change_count == 1
    assert transaction.changes[0].status is ChangeStatus.FAILED


def test_failed_precheck_exception_does_not_modify_transaction(
    control,
    transaction,
) -> None:
    class RaisingPrecheckProvider(RecordingProvider):
        def precheck(self, control, host: str):
            self.prechecks.append(
                (control.control_id, host),
            )
            raise RuntimeError("precheck backend failure")

    provider = RaisingPrecheckProvider()
    engine = RemediationEngine(provider=provider)

    plan = make_plan(
        control,
        action=PlanAction.PRECHECK,
    )

    results = engine.execute(
        plan,
        transaction,
    )

    assert results[0].status is ExecutionStatus.FAILED
    assert results[0].changed is False
    assert "precheck backend failure" in results[0].message

    assert provider.remediations == []
    assert transaction.change_count == 0