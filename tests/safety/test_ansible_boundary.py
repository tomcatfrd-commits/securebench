from __future__ import annotations

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.result import ComplianceStatus, ExecutionStatus
from securebench.execution.ansible import (
    AnsibleExecutionBackend,
    AnsibleExecutor,
    AnsibleExecutionError,
)
from securebench.execution.base import ExecutionContext


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
        self.calls: list[tuple[str, ...]] = []

    def run(self, command: list[str]):
        self.calls.append(tuple(command))

        return type(
            "CompletedProcess",
            (),
            {
                "returncode": self.returncode,
                "stdout": self.stdout,
                "stderr": self.stderr,
            },
        )()


def make_context(
    *,
    check_mode: bool = False,
    playbooks: dict[str, str] | None = None,
) -> ExecutionContext:
    extra = {}

    if playbooks is not None:
        extra["playbooks"] = playbooks

    return ExecutionContext(
        inventory="inventory.ini",
        variables={"environment": "production"},
        check_mode=check_mode,
        extra=extra,
    )


def test_ansible_executor_rejects_empty_command() -> None:
    executor = AnsibleExecutor()

    with pytest.raises(ValueError):
        executor.run([])


def test_ansible_executor_raises_on_nonzero_exit() -> None:
    fake = FakeExecutor(
        returncode=2,
        stderr="ansible failed",
    )

    executor = AnsibleExecutor(runner=fake.run)

    result = executor.run(
        [
            "ansible-playbook",
            "playbook.yml",
        ]
    )
    assert result.returncode == 2
    assert result.stderr == "ansible failed"


def test_ansible_executor_preserves_successful_result() -> None:
    fake = FakeExecutor(
        returncode=0,
        stdout="PLAY RECAP\nchanged=1",
    )

    executor = AnsibleExecutor(runner=fake.run)

    result = executor.run(
        [
            "ansible-playbook",
            "playbook.yml",
        ]
    )

    assert result.returncode == 0
    assert "PLAY RECAP" in result.stdout


def test_backend_requires_playbook_mapping() -> None:
    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=FakeExecutor().run,
        )
    )

    with pytest.raises(AnsibleExecutionError):
        backend.audit(
            make_control(),
            "test-host",
            make_context(),
        )


def test_backend_does_not_accept_unknown_operation() -> None:
    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=FakeExecutor().run,
        )
    )

    context = make_context(
        playbooks={
            "audit": "audit.yml",
        }
    )

    with pytest.raises(AnsibleExecutionError):
        backend._playbook_for(
            "unsupported-operation",
            context,
        )


def test_backend_audit_uses_configured_playbook() -> None:
    fake = FakeExecutor(
        stdout="audit completed",
    )

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    result = backend.audit(
        make_control(),
        "test-host",
        make_context(
            playbooks={
                "audit": "audit.yml",
            }
        ),
    )

    assert result.status is ExecutionStatus.SUCCESS
    assert fake.calls


def test_backend_precheck_uses_configured_playbook() -> None:
    fake = FakeExecutor()

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    result = backend.precheck(
        make_control(),
        "test-host",
        make_context(
            playbooks={
                "precheck": "precheck.yml",
            }
        ),
    )

    assert result.succeeded
    assert fake.calls


def test_backend_remediation_uses_configured_playbook() -> None:
    fake = FakeExecutor()

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    result = backend.remediate(
        make_control(),
        "test-host",
        make_context(
            playbooks={
                "remediate": "remediate.yml",
            }
        ),
    )

    assert result.succeeded
    assert fake.calls


def test_backend_rollback_uses_configured_playbook() -> None:
    fake = FakeExecutor()

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    result = backend.rollback(
        make_control(),
        "test-host",
        make_context(
            playbooks={
                "rollback": "rollback.yml",
            }
        ),
    )

    assert result.succeeded
    assert fake.calls


def test_backend_verify_uses_configured_playbook() -> None:
    fake = FakeExecutor()

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    result = backend.verify(
        make_control(),
        "test-host",
        make_context(
            playbooks={
                "verify": "verify.yml",
            }
        ),
    )

    assert result.status is ExecutionStatus.SUCCESS
    assert fake.calls


def test_backend_passes_check_mode_to_executor() -> None:
    fake = FakeExecutor()

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    backend.precheck(
        make_control(),
        "test-host",
        make_context(
            check_mode=True,
            playbooks={
                "precheck": "precheck.yml",
            },
        ),
    )

    command = fake.calls[0]

    assert "--check" in command


def test_backend_does_not_modify_execution_context() -> None:
    fake = FakeExecutor()

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    context = make_context(
        playbooks={
            "audit": "audit.yml",
        }
    )

    original_inventory = context.inventory
    original_variables = dict(context.variables)
    original_check_mode = context.check_mode

    backend.audit(
        make_control(),
        "test-host",
        context,
    )

    assert context.inventory == original_inventory
    assert context.variables == original_variables
    assert context.check_mode is original_check_mode


def test_backend_propagates_ansible_failure() -> None:
    fake = FakeExecutor(
        returncode=1,
        stderr="playbook failed",
    )

    backend = AnsibleExecutionBackend(
        executor=AnsibleExecutor(
            runner=fake.run,
        )
    )

    result = backend.remediate(
        make_control(),
        "test-host",
        make_context(
            playbooks={
                "remediate": "remediate.yml",
            }
        ),
    )
    assert result.status is ExecutionStatus.FAILED