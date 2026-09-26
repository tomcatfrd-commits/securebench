from __future__ import annotations

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.exceptions import ExecutionError
from securebench.execution.base import ExecutionBackend, ExecutionContext


def make_control(
    control_id: str = "TEST-1",
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="audit.test",
        remediation="remediation.test",
        rollback="rollback.test",
        verification="verification.test",
        rollback_capability=RollbackCapability.GUARANTEED,
    )


def make_context(
    *,
    check_mode: bool = False,
) -> ExecutionContext:
    return ExecutionContext(
        inventory="inventory.ini",
        variables={"environment": "production"},
        check_mode=check_mode,
        extra={},
    )


class RecordingBackend(ExecutionBackend):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def audit(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ):
        self.calls.append(("audit", control.control_id, host))
        return {"operation": "audit"}

    def precheck(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ):
        self.calls.append(("precheck", control.control_id, host))
        return {"operation": "precheck"}

    def remediate(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ):
        self.calls.append(("remediate", control.control_id, host))
        return {"operation": "remediate"}

    def rollback(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ):
        self.calls.append(("rollback", control.control_id, host))
        return {"operation": "rollback"}

    def verify(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ):
        self.calls.append(("verify", control.control_id, host))
        return {"operation": "verify"}

    def close(self) -> None:
        self.calls.append(("close", "", ""))


def test_execution_context_is_immutable() -> None:
    context = make_context()

    with pytest.raises(AttributeError):
        context.inventory = "changed.ini"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        context.check_mode = True  # type: ignore[misc]


def test_execution_context_preserves_check_mode() -> None:
    context = make_context(check_mode=True)

    assert context.check_mode is True


def test_backend_receives_exact_control_and_host() -> None:
    backend = RecordingBackend()
    control = make_control()

    backend.audit(
        control,
        "production-01",
        make_context(),
    )

    assert backend.calls == [
        ("audit", "TEST-1", "production-01"),
    ]


def test_backend_operations_are_explicit() -> None:
    backend = RecordingBackend()
    control = make_control()
    context = make_context()

    backend.audit(control, "production-01", context)
    backend.precheck(control, "production-01", context)
    backend.remediate(control, "production-01", context)
    backend.verify(control, "production-01", context)
    backend.rollback(control, "production-01", context)

    assert backend.calls == [
        ("audit", "TEST-1", "production-01"),
        ("precheck", "TEST-1", "production-01"),
        ("remediate", "TEST-1", "production-01"),
        ("verify", "TEST-1", "production-01"),
        ("rollback", "TEST-1", "production-01"),
    ]


def test_backend_does_not_change_control() -> None:
    backend = RecordingBackend()
    control = make_control()

    original = (
        control.control_id,
        control.title,
        control.dependencies,
        control.conflicts,
    )

    backend.remediate(
        control,
        "production-01",
        make_context(),
    )

    assert (
        control.control_id,
        control.title,
        control.dependencies,
        control.conflicts,
    ) == original


def test_check_mode_is_passed_to_backend_context() -> None:
    backend = RecordingBackend()
    context = make_context(check_mode=True)

    backend.remediate(
        make_control(),
        "production-01",
        context,
    )

    assert context.check_mode is True


def test_backend_can_target_multiple_hosts_without_state_leakage() -> None:
    backend = RecordingBackend()
    control = make_control()
    context = make_context()

    backend.audit(control, "production-01", context)
    backend.audit(control, "production-02", context)

    assert backend.calls == [
        ("audit", "TEST-1", "production-01"),
        ("audit", "TEST-1", "production-02"),
    ]


def test_backend_close_is_explicit() -> None:
    backend = RecordingBackend()

    backend.close()

    assert backend.calls == [
        ("close", "", ""),
    ]


def test_backend_failure_is_not_silently_converted_to_success() -> None:
    class FailingBackend(RecordingBackend):
        def remediate(
            self,
            control: Control,
            host: str,
            context: ExecutionContext,
        ):
            raise ExecutionError("remediation backend failed")

    backend = FailingBackend()

    with pytest.raises(ExecutionError, match="remediation backend failed"):
        backend.remediate(
            make_control(),
            "production-01",
            make_context(),
        )


def test_backend_does_not_automatically_remediate_during_audit() -> None:
    backend = RecordingBackend()

    backend.audit(
        make_control(),
        "production-01",
        make_context(),
    )

    operations = [operation for operation, _, _ in backend.calls]

    assert operations == ["audit"]
    assert "remediate" not in operations
    assert "rollback" not in operations


def test_backend_does_not_automatically_remediate_during_verification() -> None:
    backend = RecordingBackend()

    backend.verify(
        make_control(),
        "production-01",
        make_context(),
    )

    operations = [operation for operation, _, _ in backend.calls]

    assert operations == ["verify"]
    assert "remediate" not in operations
    assert "rollback" not in operations


def test_backend_does_not_automatically_rollback_during_verification() -> None:
    backend = RecordingBackend()

    backend.verify(
        make_control(),
        "production-01",
        make_context(),
    )

    operations = [operation for operation, _, _ in backend.calls]

    assert "rollback" not in operations


def test_backend_does_not_automatically_remediate_during_precheck() -> None:
    backend = RecordingBackend()

    backend.precheck(
        make_control(),
        "production-01",
        make_context(),
    )

    operations = [operation for operation, _, _ in backend.calls]

    assert operations == ["precheck"]
    assert "remediate" not in operations


def test_backend_operation_does_not_mutate_context_variables() -> None:
    backend = RecordingBackend()
    context = make_context()

    original_variables = dict(context.variables)

    backend.remediate(
        make_control(),
        "production-01",
        context,
    )

    assert context.variables == original_variables