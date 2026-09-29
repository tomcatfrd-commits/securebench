from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.profile import Profile, ProfileRule
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    ExecutionResult,
    ExecutionStatus,
)
from securebench.core.transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
)
from securebench.rollback.engine import RollbackExecution


PROJECT_ROOT = Path(__file__).resolve().parents[1]

BENCHMARK_PATH = (
    PROJECT_ROOT
    / "benchmarks"
    / "cis"
    / "ubuntu"
    / "24.04"
    / "benchmark.yml"
)

PROFILE_PATH = PROJECT_ROOT / "profiles" / "production-safe.yml"


@pytest.fixture()
def benchmark_path() -> Path:
    return BENCHMARK_PATH


@pytest.fixture()
def production_profile_path() -> Path:
    return PROFILE_PATH


@pytest.fixture()
def control() -> Control:
    return make_control()


@pytest.fixture()
def profile() -> Profile:
    return make_profile()


@pytest.fixture()
def transaction() -> Transaction:
    return make_transaction()


@pytest.fixture()
def successful_change() -> ChangeRecord:
    return make_change()


@pytest.fixture()
def failed_audit() -> AuditResult:
    return make_audit(ComplianceStatus.FAIL)


@pytest.fixture()
def passing_audit() -> AuditResult:
    return make_audit(ComplianceStatus.PASS)


@pytest.fixture()
def unknown_audit() -> AuditResult:
    return make_audit(ComplianceStatus.UNKNOWN)


@pytest.fixture()
def recording_remediation_provider() -> RecordingRemediationProvider:
    return RecordingRemediationProvider()


@pytest.fixture()
def recording_rollback_provider() -> RecordingRollbackProvider:
    return RecordingRollbackProvider()


def make_control(
    *,
    control_id: str = "TEST-001",
    benchmark_id: str = "test-benchmark",
    host_platform: str = "ubuntu-24.04",
    severity: ControlSeverity = ControlSeverity.MEDIUM,
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
    dependencies: tuple[str, ...] = (),
    conflicts: tuple[str, ...] = (),
    metadata: dict[str, object] | None = None,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id=benchmark_id,
        title="Test control",
        description="Test control description.",
        platform=host_platform,
        severity=severity,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=rollback_capability,
        dependencies=dependencies,
        conflicts=conflicts,
        metadata=metadata or {},
    )


def make_profile(
    *,
    profile_id: str = "test-profile",
    default_classification: SafetyClassification = (
        SafetyClassification.INVESTIGATE
    ),
    rules: dict[str, ProfileRule] | None = None,
    allow_best_effort_rollback: bool = False,
    require_approval_for_unknown: bool = True,
) -> Profile:
    return Profile(
        profile_id=profile_id,
        name="Test Profile",
        description="Test profile.",
        default_classification=default_classification,
        rules=rules or {},
        allow_best_effort_rollback=allow_best_effort_rollback,
        require_approval_for_unknown=require_approval_for_unknown,
    )


def make_rule(
    classification: SafetyClassification,
    *,
    enabled: bool | None = None,
    require_approval: bool | None = None,
) -> ProfileRule:
    if enabled is None:
        enabled = classification not in {
            SafetyClassification.INVESTIGATE,
            SafetyClassification.PROHIBITED,
        }

    if require_approval is None:
        require_approval = (
            classification is SafetyClassification.APPROVAL_REQUIRED
        )

    return ProfileRule(
        classification=classification,
        enabled=enabled,
        require_approval=require_approval,
    )


def make_audit(
    status: ComplianceStatus,
    *,
    control_id: str = "TEST-001",
    host: str = "server01",
    evidence: tuple[object, ...] = (),
    message: str = "",
) -> AuditResult:
    return AuditResult(
        control_id=control_id,
        host=host,
        status=status,
        evidence=evidence,
        message=message or f"Audit result: {status.value}",
    )


def make_transaction(
    *,
    transaction_id: str = "txn-001",
    profile_id: str | None = None,
    benchmark_id: str | None = None,
    host: str | None = "server01",
) -> Transaction:
    return Transaction(
        transaction_id=transaction_id,
        profile_id=profile_id,
        benchmark_id=benchmark_id,
        host=host,
    )


def make_change(
    *,
    change_id: str = "change-001",
    control_id: str = "TEST-001",
    host: str = "server01",
    status: ChangeStatus = ChangeStatus.SUCCESS,
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
    details: dict[str, object] | None = None,
    rollback_data: dict[str, object] | None = None,
    message: str = "Test change.",
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id=control_id,
        host=host,
        status=status,
        before=before or {},
        after=after or {},
        details=details or {},
        rollback_data=rollback_data,
        message=message,
    )


class RecordingRemediationProvider:
    def __init__(
        self,
        *,
        precheck_result: object = True,
        remediation_result: object | None = None,
    ) -> None:
        self.precheck_result = precheck_result
        self.remediation_result = (
            remediation_result
            if remediation_result is not None
            else ExecutionResult(
                control_id="TEST-001",
                host="server01",
                status=ExecutionStatus.SUCCESS,
                changed=True,
                message="Remediation completed.",
            )
        )

        self.prechecks: list[tuple[str, str]] = []
        self.remediations: list[tuple[str, str]] = []

    def precheck(
        self,
        control: Control,
        host: str,
    ) -> object:
        self.prechecks.append(
            (control.control_id, host),
        )
        return self.precheck_result

    def remediate(
        self,
        control: Control,
        host: str,
    ) -> object:
        self.remediations.append(
            (control.control_id, host),
        )

        if isinstance(self.remediation_result, ExecutionResult):
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=self.remediation_result.status,
                changed=self.remediation_result.changed,
                message=self.remediation_result.message,
            )

        return self.remediation_result


class RecordingRollbackProvider:
    def __init__(
        self,
        *,
        success: bool = True,
    ) -> None:
        self.success = success
        self.calls: list[tuple[str, str, str]] = []

    def rollback(
        self,
        control: Control,
        host: str,
        change: ChangeRecord,
    ) -> RollbackExecution:
        self.calls.append(
            (
                control.control_id,
                host,
                change.change_id,
            )
        )

        return RollbackExecution(
            control_id=control.control_id,
            host=host,
            success=self.success,
            message=(
                "Rollback completed."
                if self.success
                else "Rollback failed."
            ),
        )


@pytest.fixture()
def isolated_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    monkeypatch.chdir(tmp_path)
    yield tmp_path