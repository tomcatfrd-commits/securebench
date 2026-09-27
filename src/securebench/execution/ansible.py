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
    def returncode(self) -> int:
        """Alias used by tests (subprocess-style name)."""

        return self.return_code

    @property
    def succeeded(self) -> bool:
        """Return True when ansible-playbook exited successfully."""

        return self.return_code == 0


class AnsibleExecutionError(RuntimeError):
    """Raised when ansible-core cannot be invoked successfully."""


class AnsibleExecutor:
    """
    Thin subprocess wrapper around ansible-playbook.

    A custom ``runner`` may be injected for tests. It must accept a
    command list and return an object with ``returncode``, ``stdout``,
    and ``stderr`` attributes.
    """

    def __init__(
        self,
        *,
        executable: str = "ansible-playbook",
        runner: Callable[..., Any] | None = None,
    ) -> None:
        self._executable = executable
        self._runner = runner or self._default_runner

    def run(self, command: list[str] | None = None, **kwargs: Any) -> AnsibleRunResult:
        """
        Execute a command list (test / low-level API) or build a playbook
        invocation from keyword arguments (backend API).
        """
        if command is not None and kwargs:
            raise TypeError(
                "run() accepts either a command list or keyword args, not both"
            )

        if command is not None:
            if not command:
                raise ValueError("command must not be empty")
            return self._invoke(list(command))

        playbook = kwargs.get("playbook")
        if not playbook:
            raise ValueError("playbook is required when calling run() with keywords")

        built: list[str] = [self._executable, str(playbook)]

        inventory = kwargs.get("inventory")
        if inventory:
            # Support both long and short inventory flags for test compatibility
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
            built.extend(["--tags", ",".join(str(t) for t in tags)])

        return self._invoke(built)

    def _invoke(self, command: list[str]) -> AnsibleRunResult:
        try:
            completed = self._runner(command)
        except TypeError:
            # Some fakes accept **kwargs
            completed = self._runner(command, capture_output=True, text=True, check=False)
        except OSError as exc:
            raise AnsibleExecutionError(
                f"failed to execute command {command!r}: {exc}"
            ) from exc

        return_code = int(
            getattr(completed, "returncode", getattr(completed, "return_code", 1))
        )
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
    """

    def __init__(
        self,
        *,
        executor: AnsibleExecutor | None = None,
    ) -> None:
        self._executor = executor or AnsibleExecutor()

    # ------------------------------------------------------------------
    # Public operations – accept positional (control, host, context)
    # for test compatibility, and keyword form for production callers.
    # ------------------------------------------------------------------

    def audit(
        self,
        control: Control,
        host: str | None = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        control, host, context = self._normalize_args(control, host, context, kwargs)
        return self._run_operation(
            operation="audit",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def precheck(
        self,
        control: Control,
        host: str | None = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        control, host, context = self._normalize_args(control, host, context, kwargs)
        return self._run_operation(
            operation="precheck",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def remediate(
        self,
        control: Control,
        host: str | None = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        control, host, context = self._normalize_args(control, host, context, kwargs)
        return self._run_operation(
            operation="remediate",
            control=control,
            host=host,
            context=context,
            check_mode=context.check_mode,
        )

    def rollback(
        self,
        control: Control,
        host: str | None = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        control, host, context = self._normalize_args(control, host, context, kwargs)
        return self._run_operation(
            operation="rollback",
            control=control,
            host=host,
            context=context,
            check_mode=False,
        )

    def verify(
        self,
        control: Control,
        host: str | None = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        control, host, context = self._normalize_args(control, host, context, kwargs)
        return self._run_operation(
            operation="verify",
            control=control,
            host=host,
            context=context,
            check_mode=True,
        )

    def _playbook_for(self, operation: str, context: ExecutionContext) -> str:
        """
        Resolve the playbook path for an operation.

        Raises ValueError when the mapping is missing or the operation is unknown.
        """
        playbooks: Mapping[str, Any] = {}
        if context.extra and isinstance(context.extra, Mapping):
            raw = context.extra.get("playbooks")
            if isinstance(raw, Mapping):
                playbooks = raw

        if not playbooks:
            raise ValueError(
                "Ansible playbook mapping is missing from execution context."
            )

        playbook = playbooks.get(operation)
        if not isinstance(playbook, str) or not playbook.strip():
            raise ValueError(
                f"No Ansible playbook configured for operation '{operation}'."
            )

        return playbook

    @staticmethod
    def _normalize_args(
        control: Control,
        host: str | None,
        context: ExecutionContext | None,
        kwargs: dict[str, Any],
    ) -> tuple[Control, str, ExecutionContext]:
        host = host if host is not None else kwargs.get("host")
        context = context if context is not None else kwargs.get("context")
        if host is None or context is None:
            raise TypeError(
                "audit/precheck/remediate/rollback/verify require "
                "(control, host, context)"
            )
        return control, host, context

    def _run_operation(
        self,
        *,
        operation: str,
        control: Control,
        host: str,
        context: ExecutionContext,
        check_mode: bool | None = None,
    ) -> ExecutionResult:
        try:
            playbook = self._playbook_for(operation, context)
        except ValueError as exc:
            return ExecutionResult(
                control_id=control.control_id,
                host=host,
                status=ExecutionStatus.FAILED,
                message=str(exc),
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