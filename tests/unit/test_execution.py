from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from securebench.execution.base import ExecutionContext


def make_control(control_id: str = "TEST-1") -> Control:
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
        rollback_capability=RollbackCapability.GUARANTEED,
        metadata={
            "safety": {
                "default": SafetyClassification.SAFE.value,
                "prechecks": (),
            },
            "requirements": {
                "setting": "expected",
            },
        },
    )


def test_execution_context_has_safe_defaults() -> None:
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    assert context.inventory == "inventory.yml"
    assert context.variables == {}
    assert context.check_mode is False
    assert context.extra == {}


def test_execution_context_accepts_variables() -> None:
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={
            "ansible_user": "admin",
            "environment": "production",
        },
    )

    assert context.variables["ansible_user"] == "admin"
    assert context.variables["environment"] == "production"


def test_execution_context_accepts_check_mode() -> None:
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
        check_mode=True,
    )

    assert context.check_mode is True


def test_execution_context_accepts_extra_backend_data() -> None:
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
        extra={
            "playbooks": {
                "audit": "audit.yml",
                "remediate": "remediate.yml",
            },
        },
    )

    assert context.extra["playbooks"]["audit"] == "audit.yml"
    assert context.extra["playbooks"]["remediate"] == "remediate.yml"


def test_execution_context_does_not_require_ansible_specific_fields() -> None:
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={"target": "server01"},
    )

    assert context.inventory == "inventory.yml"
    assert context.variables["target"] == "server01"


@dataclass
class FakeExecutionBackend:
    audit_result: AuditResult | None = None
    precheck_result: bool = True
    remediation_result: ExecutionResult | None = None
    rollback_result: ExecutionResult | None = None
    verification_result: VerificationResult | None = None

    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def audit(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> AuditResult:
        self.calls.append(("audit", control.control_id, host))

        if self.audit_result is not None:
            return self.audit_result

        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.PASS,
            evidence=(),
        )

    def precheck(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> bool:
        self.calls.append(("precheck", control.control_id, host))
        return self.precheck_result

    def remediate(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        self.calls.append(("remediate", control.control_id, host))

        if self.remediation_result is not None:
            return self.remediation_result

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
        )

    def rollback(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        self.calls.append(("rollback", control.control_id, host))

        if self.rollback_result is not None:
            return self.rollback_result

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
        )

    def verify(
        self,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> VerificationResult:
        self.calls.append(("verify", control.control_id, host))

        if self.verification_result is not None:
            return self.verification_result

        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.PASS,
            evidence=(),
        )

    def close(self) -> None:
        self.calls.append(("close", "", ""))


def test_execution_backend_contract_covers_all_operations() -> None:
    backend = FakeExecutionBackend()
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )
    control = make_control()

    audit = backend.audit(control, "server01", context)
    precheck = backend.precheck(control, "server01", context)
    remediation = backend.remediate(control, "server01", context)
    rollback = backend.rollback(control, "server01", context)
    verification = backend.verify(control, "server01", context)

    assert audit.status is ComplianceStatus.PASS
    assert precheck is True
    assert remediation.status is ExecutionStatus.SUCCESS
    assert rollback.status is ExecutionStatus.SUCCESS
    assert verification.status is ComplianceStatus.PASS


def test_execution_backend_records_operation_order() -> None:
    backend = FakeExecutionBackend()
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )
    control = make_control()

    backend.audit(control, "server01", context)
    backend.precheck(control, "server01", context)
    backend.remediate(control, "server01", context)
    backend.verify(control, "server01", context)
    backend.rollback(control, "server01", context)

    assert backend.calls == [
        ("audit", "TEST-1", "server01"),
        ("precheck", "TEST-1", "server01"),
        ("remediate", "TEST-1", "server01"),
        ("verify", "TEST-1", "server01"),
        ("rollback", "TEST-1", "server01"),
    ]


def test_execution_backend_receives_same_context() -> None:
    backend = FakeExecutionBackend()
    context = ExecutionContext(
        inventory="production.yml",
        variables={"environment": "production"},
        check_mode=True,
        extra={"timeout": 30},
    )

    control = make_control()

    result = backend.audit(control, "server01", context)

    assert result.status is ComplianceStatus.PASS
    assert context.inventory == "production.yml"
    assert context.variables["environment"] == "production"
    assert context.check_mode is True
    assert context.extra["timeout"] == 30


def test_failed_precheck_is_returned_as_false() -> None:
    backend = FakeExecutionBackend(precheck_result=False)
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    assert backend.precheck(make_control(), "server01", context) is False


def test_failed_remediation_is_not_reported_as_success() -> None:
    backend = FakeExecutionBackend(
        remediation_result=ExecutionResult(
            control_id="TEST-1",
            host="server01",
            status=ExecutionStatus.FAILED,
            changed=False,
            message="Remediation failed.",
        )
    )

    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    result = backend.remediate(
        make_control(),
        "server01",
        context,
    )

    assert result.status is ExecutionStatus.FAILED
    assert result.succeeded is False


def test_failed_rollback_is_not_reported_as_success() -> None:
    backend = FakeExecutionBackend(
        rollback_result=ExecutionResult(
            control_id="TEST-1",
            host="server01",
            status=ExecutionStatus.FAILED,
            changed=False,
            message="Rollback failed.",
        )
    )

    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    result = backend.rollback(
        make_control(),
        "server01",
        context,
    )

    assert result.status is ExecutionStatus.FAILED
    assert result.succeeded is False


def test_failed_verification_is_not_reported_as_verified() -> None:
    backend = FakeExecutionBackend(
        verification_result=VerificationResult(
            control_id="TEST-1",
            host="server01",
            status=ComplianceStatus.FAIL,
            evidence=(),
            message="Expected state was not observed.",
        )
    )

    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    result = backend.verify(
        make_control(),
        "server01",
        context,
    )

    assert result.status is ComplianceStatus.FAIL
    assert result.verified is False


def test_close_is_explicit_backend_lifecycle_operation() -> None:
    backend = FakeExecutionBackend()

    backend.close()

    assert backend.calls == [
        ("close", "", ""),
    ]


def test_execution_context_can_be_used_without_extra_configuration() -> None:
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    assert context.extra == {}
    assert context.check_mode is False


def test_execution_context_preserves_nested_backend_configuration() -> None:
    playbooks: dict[str, Any] = {
        "audit": "audit.yml",
        "precheck": "precheck.yml",
        "remediate": "remediate.yml",
        "rollback": "rollback.yml",
        "verify": "verify.yml",
    }

    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
        extra={"playbooks": playbooks},
    )

    assert context.extra["playbooks"] == playbooks


def test_backend_can_handle_multiple_hosts() -> None:
    backend = FakeExecutionBackend()
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )
    control = make_control()

    backend.audit(control, "server01", context)
    backend.audit(control, "server02", context)

    assert backend.calls == [
        ("audit", "TEST-1", "server01"),
        ("audit", "TEST-1", "server02"),
    ]


def test_backend_does_not_change_control_during_operations() -> None:
    backend = FakeExecutionBackend()
    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )
    control = make_control()

    original = (
        control.control_id,
        control.title,
        control.description,
        control.metadata,
    )

    backend.audit(control, "server01", context)
    backend.precheck(control, "server01", context)
    backend.remediate(control, "server01", context)
    backend.verify(control, "server01", context)
    backend.rollback(control, "server01", context)

    current = (
        control.control_id,
        control.title,
        control.description,
        control.metadata,
    )

    assert current == original


def test_execution_backend_can_return_unknown_audit_result() -> None:
    backend = FakeExecutionBackend(
        audit_result=AuditResult(
            control_id="TEST-1",
            host="server01",
            status=ComplianceStatus.UNKNOWN,
            evidence=(),
            message="Audit could not determine state.",
        )
    )

    context = ExecutionContext(
        inventory="inventory.yml",
        variables={},
    )

    result = backend.audit(
        make_control(),
        "server01",
        context,
    )

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.compliant is False