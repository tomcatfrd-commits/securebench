from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.result import ComplianceStatus, ExecutionStatus
from securebench.execution.ansible import (
    AnsibleExecutionBackend,
    AnsibleExecutionError,
    AnsibleExecutor,
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


def make_context(
    tmp_path: Path,
    *,
    check_mode: bool = False,
) -> ExecutionContext:
    playbooks = {
        "audit": str(tmp_path / "audit.yml"),
        "precheck": str(tmp_path / "precheck.yml"),
        "remediate": str(tmp_path / "remediate.yml"),
        "rollback": str(tmp_path / "rollback.yml"),
        "verify": str(tmp_path / "verify.yml"),
    }

    return ExecutionContext(
        inventory=str(tmp_path / "inventory.yml"),
        variables={
            "ansible_user": "admin",
        },
        check_mode=check_mode,
        extra={
            "playbooks": playbooks,
        },
    )


class FakeExecutor:
    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        playbook: str,
        inventory: str,
        extra_vars: dict[str, Any],
        *,
        check_mode: bool = False,
    ):
        self.calls.append(
            {
                "playbook": playbook,
                "inventory": inventory,
                "extra_vars": extra_vars,
                "check_mode": check_mode,
            }
        )

        return type(
            "FakeRunResult",
            (),
            {
                "returncode": self.returncode,
                "stdout": self.stdout,
                "stderr": self.stderr,
            },
        )()


def test_ansible_executor_builds_basic_command() -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ):
        calls.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="ok",
            stderr="",
        )

    executor = AnsibleExecutor(
        runner=fake_run,
    )

    result = executor.run(
        playbook="playbook.yml",
        inventory="inventory.yml",
        extra_vars={"control_id": "TEST-1"},
    )

    assert result.returncode == 0
    assert result.stdout == "ok"
    assert result.stderr == ""

    assert len(calls) == 1

    command = calls[0]

    assert command[0] == "ansible-playbook"
    assert "-i" in command
    assert "inventory.yml" in command
    assert "playbook.yml" in command
    assert "--extra-vars" in command


def test_ansible_executor_serializes_extra_vars_as_json() -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ):
        calls.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="ok",
            stderr="",
        )

    executor = AnsibleExecutor(
        runner=fake_run,
    )

    variables = {
        "control_id": "TEST-1",
        "host": "server01",
        "operation": "audit",
        "nested": {
            "expected": False,
        },
    }

    executor.run(
        playbook="audit.yml",
        inventory="inventory.yml",
        extra_vars=variables,
    )

    command = calls[0]
    extra_vars_index = command.index("--extra-vars")

    serialized = command[extra_vars_index + 1]
    parsed = json.loads(serialized)

    assert parsed == variables


def test_ansible_executor_adds_check_mode() -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ):
        calls.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="ok",
            stderr="",
        )

    executor = AnsibleExecutor(
        runner=fake_run,
    )

    executor.run(
        playbook="audit.yml",
        inventory="inventory.yml",
        extra_vars={},
        check_mode=True,
    )

    assert "--check" in calls[0]


def test_ansible_executor_does_not_add_check_mode_when_disabled() -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ):
        calls.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="ok",
            stderr="",
        )

    executor = AnsibleExecutor(
        runner=fake_run,
    )

    executor.run(
        playbook="audit.yml",
        inventory="inventory.yml",
        extra_vars={},
        check_mode=False,
    )

    assert "--check" not in calls[0]


def test_ansible_executor_returns_nonzero_result_without_hiding_failure() -> None:
    def fake_run(
        command: list[str],
        **kwargs: Any,
    ):
        return subprocess.CompletedProcess(
            args=command,
            returncode=2,
            stdout="failed output",
            stderr="fatal error",
        )

    executor = AnsibleExecutor(
        runner=fake_run,
    )

    result = executor.run(
        playbook="audit.yml",
        inventory="inventory.yml",
        extra_vars={},
    )

    assert result.returncode == 2
    assert result.stdout == "failed output"
    assert result.stderr == "fatal error"


def test_ansible_executor_raises_on_runner_exception() -> None:
    def fake_run(
        command: list[str],
        **kwargs: Any,
    ):
        raise OSError("ansible-playbook not found")

    executor = AnsibleExecutor(
        runner=fake_run,
    )

    with pytest.raises(AnsibleExecutionError, match="ansible-playbook"):
        executor.run(
            playbook="audit.yml",
            inventory="inventory.yml",
            extra_vars={},
        )


def test_backend_audit_selects_audit_playbook(tmp_path: Path) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    result = backend.audit(
        make_control(),
        "server01",
        context,
    )

    assert result.status in {
        ComplianceStatus.PASS,
        ComplianceStatus.UNKNOWN,
        ComplianceStatus.FAIL,
        ComplianceStatus.ERROR,
    }

    assert len(executor.calls) == 1
    assert executor.calls[0]["playbook"] == str(
        tmp_path / "audit.yml"
    )
    assert executor.calls[0]["inventory"] == str(
        tmp_path / "inventory.yml"
    )


def test_backend_precheck_selects_precheck_playbook(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    result = backend.precheck(
        make_control(),
        "server01",
        context,
    )

    assert result is True

    assert len(executor.calls) == 1
    assert executor.calls[0]["playbook"] == str(
        tmp_path / "precheck.yml"
    )


def test_backend_remediate_selects_remediation_playbook(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    result = backend.remediate(
        make_control(),
        "server01",
        context,
    )

    assert result.status is ExecutionStatus.SUCCESS

    assert len(executor.calls) == 1
    assert executor.calls[0]["playbook"] == str(
        tmp_path / "remediate.yml"
    )


def test_backend_rollback_selects_rollback_playbook(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    change = type(
        "Change",
        (),
        {
            "change_id": "change-001",
            "control_id": "TEST-1",
            "host": "server01",
            "status": "success",
            "before": None,
            "after": None,
            "rollback_data": None,
        },
    )()

    result = backend.rollback(
        make_control(),
        "server01",
        change,
        context,
    )

    assert result.status is ExecutionStatus.SUCCESS

    assert len(executor.calls) == 1
    assert executor.calls[0]["playbook"] == str(
        tmp_path / "rollback.yml"
    )


def test_backend_verify_selects_verification_playbook(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    result = backend.verify(
        make_control(),
        "server01",
        context,
    )

    assert result.status in {
        ComplianceStatus.PASS,
        ComplianceStatus.UNKNOWN,
        ComplianceStatus.FAIL,
        ComplianceStatus.ERROR,
    }

    assert len(executor.calls) == 1
    assert executor.calls[0]["playbook"] == str(
        tmp_path / "verify.yml"
    )


def test_backend_passes_control_id_host_and_operation(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    backend.audit(
        make_control("TEST-42"),
        "server99",
        context,
    )

    extra_vars = executor.calls[0]["extra_vars"]

    assert extra_vars["control_id"] == "TEST-42"
    assert extra_vars["host"] == "server99"
    assert extra_vars["operation"] == "audit"


def test_backend_passes_context_variables(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)

    context = ExecutionContext(
        inventory=str(tmp_path / "inventory.yml"),
        variables={
            "environment": "production",
            "ansible_user": "admin",
        },
        extra={
            "playbooks": {
                "audit": str(tmp_path / "audit.yml"),
                "precheck": str(tmp_path / "precheck.yml"),
                "remediate": str(tmp_path / "remediate.yml"),
                "rollback": str(tmp_path / "rollback.yml"),
                "verify": str(tmp_path / "verify.yml"),
            },
        },
    )

    backend.audit(
        make_control(),
        "server01",
        context,
    )

    extra_vars = executor.calls[0]["extra_vars"]

    assert extra_vars["environment"] == "production"
    assert extra_vars["ansible_user"] == "admin"


def test_backend_fails_when_playbook_mapping_is_missing(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)

    context = ExecutionContext(
        inventory=str(tmp_path / "inventory.yml"),
        variables={},
        extra={
            "playbooks": {},
        },
    )

    with pytest.raises(AnsibleExecutionError):
        backend.audit(
            make_control(),
            "server01",
            context,
        )

    assert executor.calls == []


def test_backend_fails_when_playbook_configuration_is_missing(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor()
    backend = AnsibleExecutionBackend(executor=executor)

    context = ExecutionContext(
        inventory=str(tmp_path / "inventory.yml"),
        variables={},
        extra={},
    )

    with pytest.raises(AnsibleExecutionError):
        backend.audit(
            make_control(),
            "server01",
            context,
        )

    assert executor.calls == []


def test_backend_remediation_failure_is_reported_as_failed(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor(
        returncode=2,
        stdout="",
        stderr="remediation failed",
    )

    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    result = backend.remediate(
        make_control(),
        "server01",
        context,
    )

    assert result.status is ExecutionStatus.FAILED
    assert result.succeeded is False


def test_backend_rollback_failure_is_reported_as_failed(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor(
        returncode=2,
        stdout="",
        stderr="rollback failed",
    )

    backend = AnsibleExecutionBackend(executor=executor)
    context = make_context(tmp_path)

    change = type(
        "Change",
        (),
        {
            "change_id": "change-001",
            "control_id": "TEST-1",
            "host": "server01",
            "status": "success",
            "before": None,
            "after": None,
            "rollback_data": None,
        },
    )()

    result = backend.rollback(
        make_control(),
        "server01",
        change,
        context,
    )

    assert result.status is ExecutionStatus.FAILED
    assert result.succeeded is False