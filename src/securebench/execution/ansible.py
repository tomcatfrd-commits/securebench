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
from typing import Any, Callable, Mapping, Sequence

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

    A custom ``runner`` may be injected for tests. It must accept a
    command list and return an object with ``returncode``, ``stdout``,
    and ``stderr`` attributes (compatible with ``subprocess.CompletedProcess``).
    """

    def __init__(
        self,
        *,
        executable: str = "ansible-playbook",
        runner: Callable[[list[str]], Any] | None = None,
    ) -> None:
        self._executable = executable
        self._runner = runner or self._default_runner

    def run(self, command: list[str] | None = None, **kwargs: Any) -> AnsibleRunResult:
        """
        Execute a command list (test / low-level API) or build a playbook
        invocation from keyword arguments (backend API).
        """
        if command is not None and kwargs:
            raise TypeError("run() accepts either a command list or keyword args, not both")

        if command is not None:
            if not command:
                raise ValueError("command must not be empty")
            return self._invoke(list(command))

        # High-level playbook invocation used by AnsibleExecutionBackend
        playbook = kwargs.get("playbook")
        if not playbook:
            raise ValueError("playbook is required when calling run() with keywords")

        built: list[str] = [self._executable, str(playbook)]

        inventory = kwargs.get("inventory")
        if inventory:
            built.extend(["--inventory", str(inventory)])

        extra_vars = kwargs.get("extra_vars")
        if extra_vars:
            built.extend(["--extra-vars", json.dumps(extra_vars)])

        if kwargs.get("check_mode"):
            built.append("--check")

        limit = kwargs.get("limit")
        if limit:
            built.extend(["--limit", str(limit)])

        tags = kwargs.get("tags") or ()
        if tags:
            built.extend(["--tags", ",".join(tags)])

        return self._invoke(built)

    def _invoke(self, command: list[str]) -> AnsibleRunResult:
        try:
            completed = self._runner(command)
        except OSError as exc:
            raise AnsibleExecutionError(
                f"failed to execute command {command!r}: {exc}"
            ) from exc

        return_code = getattr(completed, "returncode", getattr(completed, "return_code", 1))
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""

        if return_code != 0:
            raise AnsibleExecutionError(
                f"command failed with exit code {return_code}: {stderr or stdout}"
            )

        return AnsibleRunResult(
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
        )

    @staticmethod
    def _default_runner(command: list[str]) -> Any:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )


class AnsibleExecutionBackend(ExecutionBackend):
    """
    SecureBench execution backend using ansible-core.

    Control definitions refer to named SecureBench operations. The backend
    maps those operations to Ansible playbooks through ``ExecutionContext``.
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
        return self._run_operation(
            operation="audit",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def precheck(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
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
        return self._run_operation(
            operation="remediate",
            control=control,
            host=host,
            context=context,
            check_mode=context.check_mode,
        )

    def rollback(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        return self._run_operation(
            operation="rollback",
            control=control,
            host=host,
            context=context,
            check_mode=False,
        )

    def verify(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        return self._run_operation(
            operation="verify",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def _run_operation(
        self,
        *,
        operation: str,
        control: Control,
        host: str,
        context: ExecutionContext,
        check_mode: bool | None = None,
    ) -> ExecutionResult:
        playbooks = {}
        if context.extra and isinstance(context.extra, Mapping):
            playbooks = context.extra.get("playbooks") or {}

        if not playbooks:
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message="Ansible playbook mapping is missing from execution context.",
            )

        playbook = playbooks.get(operation)
        if not isinstance(playbook, str) or not playbook.strip():
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=(
                    f"No Ansible playbook configured for operation '{operation}'."
                ),
            )

        variables = dict(context.variables or {})
        variables.update(
            {
                "securebench_control_id": control.control_id,
                "securebench_host": host,
                "securebench_operation": operation,
            }
        )

        effective_check_mode = (
            context.check_mode if check_mode is None else check_mode
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