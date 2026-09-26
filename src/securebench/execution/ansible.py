"""
Ansible execution backend.

This module is the bridge between SecureBench and ansible-core.

SecureBench decides:

    what control to process
    whether it is allowed
    when it may execute
    what must be verified
    when rollback is required

Ansible performs:

    remote execution
    privilege escalation
    configuration changes
    read-only inspection

The backend intentionally does not contain benchmark policy.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from securebench.core import (
    Control,
    ExecutionResult,
    ExecutionStatus,
)

from .base import ExecutionBackend, ExecutionContext


@dataclass(frozen=True, slots=True)
class AnsibleRunResult:
    """
    Normalized result returned by an ansible-core invocation.
    """

    return_code: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        """Return True when ansible-playbook exited successfully."""

        return self.return_code == 0


class AnsibleExecutionError(RuntimeError):
    """Raised when ansible-core cannot be invoked successfully."""


class AnsibleExecutor:
    """
    Thin subprocess wrapper around ansible-playbook.

    Keeping subprocess handling here prevents the higher-level execution
    backend from becoming coupled to command construction details.
    """

    def __init__(
        self,
        *,
        executable: str = "ansible-playbook",
    ) -> None:
        self._executable = executable

    def run(
        self,
        *,
        playbook: str,
        inventory: str | None,
        extra_vars: Mapping[str, Any] | None = None,
        check_mode: bool = False,
        limit: str | None = None,
        tags: Sequence[str] = (),
    ) -> AnsibleRunResult:
        """
        Execute ansible-playbook.

        Parameters
        ----------
        playbook:
            Path to the playbook to execute.

        inventory:
            Ansible inventory path or inventory specification.

        extra_vars:
            Variables passed to Ansible as JSON.

        check_mode:
            Adds Ansible ``--check`` so the backend requests a dry run.

        limit:
            Optional host limit.

        tags:
            Optional Ansible tags.
        """

        command = [
            self._executable,
            playbook,
        ]

        if inventory:
            command.extend(["--inventory", inventory])

        if extra_vars:
            command.extend(
                [
                    "--extra-vars",
                    json.dumps(extra_vars),
                ]
            )

        if check_mode:
            command.append("--check")

        if limit:
            command.extend(["--limit", limit])

        if tags:
            command.extend(["--tags", ",".join(tags)])

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise AnsibleExecutionError(
                f"failed to execute '{self._executable}': {exc}"
            ) from exc

        return AnsibleRunResult(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class AnsibleExecutionBackend(ExecutionBackend):
    """
    SecureBench execution backend using ansible-core.

    Control definitions refer to named SecureBench operations. The backend
    maps those operations to Ansible playbooks through ``ExecutionContext``.

    This first implementation deliberately keeps that mapping explicit
    rather than inventing a dynamic playbook-discovery mechanism.
    """

    def __init__(
        self,
        *,
        executor: AnsibleExecutor | None = None,
    ) -> None:
        self._executor = executor or AnsibleExecutor()

    def audit(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute the Ansible audit operation for a control."""

        return self._run_operation(
            operation="audit",
            control=control,
            host=host,
            context=context,
        )

    def precheck(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute the Ansible precheck operation for a control."""

        return self._run_operation(
            operation="precheck",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def remediate(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute the Ansible remediation operation for a control."""

        return self._run_operation(
            operation="remediate",
            control=control,
            host=host,
            context=context,
        )

    def rollback(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
        rollback_data: Mapping[str, Any],
    ) -> ExecutionResult:
        """
        Execute the Ansible rollback operation.

        Rollback data is explicitly passed as variables so the rollback
        implementation can restore the state recorded before remediation.
        """

        variables = dict(context.variables)
        variables["securebench_rollback_data"] = dict(rollback_data)

        rollback_context = ExecutionContext(
            inventory=context.inventory,
            variables=variables,
            check_mode=context.check_mode,
            extra=context.extra,
        )

        return self._run_operation(
            operation="rollback",
            control=control,
            host=host,
            context=rollback_context,
        )

    def verify(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute the independent Ansible verification operation."""

        return self._run_operation(
            operation="verify",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def close(self) -> None:
        """No persistent resources are currently maintained."""

    def _run_operation(
        self,
        *,
        operation: str,
        control: Control,
        host: str,
        context: ExecutionContext,
        check_mode: bool | None = None,
    ) -> ExecutionResult:
        """
        Run a named SecureBench operation through Ansible.

        The actual playbook path is supplied through ``context.extra``:

            context.extra["playbooks"]["audit"]
            context.extra["playbooks"]["precheck"]
            context.extra["playbooks"]["remediate"]
            context.extra["playbooks"]["rollback"]
            context.extra["playbooks"]["verify"]

        This keeps the backend independent from the repository layout.
        """

        playbooks = context.extra.get("playbooks")

        if not isinstance(playbooks, Mapping):
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=(
                    "Ansible playbook mapping is missing from execution context."
                ),
            )

        playbook = playbooks.get(operation)

        if not isinstance(playbook, str) or not playbook.strip():
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=(
                    f"No Ansible playbook configured for operation "
                    f"'{operation}'."
                ),
            )

        variables = dict(context.variables)

        variables.update(
            {
                "securebench_control_id": control.control_id,
                "securebench_host": host,
                "securebench_operation": operation,
            }
        )

        effective_check_mode = (
            context.check_mode
            if check_mode is None
            else check_mode
        )

        try:
            result = self._executor.run(
                playbook=playbook,
                inventory=context.inventory,
                extra_vars=variables,
                check_mode=effective_check_mode,
                limit=host,
            )
        except AnsibleExecutionError as exc:
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=str(exc),
            )

        if result.succeeded:
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.SUCCESS,
                changed=not effective_check_mode,
                message=result.stdout,
                details={
                    "return_code": result.return_code,
                    "stderr": result.stderr,
                    "operation": operation,
                },
            )

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.FAILED,
            changed=False,
            message=(
                f"Ansible operation '{operation}' failed "
                f"with return code {result.return_code}."
            ),
            details={
                "return_code": result.return_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "operation": operation,
            },
        )