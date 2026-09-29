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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

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
            # Tests and ansible-playbook both accept the short -i form.
            built.extend(["-i", str(inventory)])

        extra_vars = kwargs.get("extra_vars")
        if extra_vars is not None:
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
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise AnsibleExecutionError(
                f"failed to execute command {command!r}: {exc}"
            ) from exc

        return_code = int(
            getattr(
                completed,
                "returncode",
                getattr(completed, "return_code", 1),
            )
        )
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""

        # Surface non-zero exit codes as a normal result so callers can
        # decide how to map them. Do not hide failures by raising here.
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

    def prepare_rollback(
        self,
        control: Control,
        host: str | None = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        control, host, context = self._normalize_args(control, host, context, kwargs)
        return self._run_operation(
            operation="prepare_rollback",
            control=control,
            host=host,
            context=context,
            check_mode=False,
        )

    def rollback(
        self,
        control: Control,
        host: str | None = None,
        change: Any = None,
        context: ExecutionContext | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        # Support both (control, host, context) and
        # (control, host, change, context) call styles.
        if context is None and isinstance(change, ExecutionContext):
            context = change
            change = None
        elif context is None:
            context = kwargs.get("context")

        control, host, context = self._normalize_args(
            control,
            host,
            context,
            kwargs,
        )
        rollback_data = getattr(change, "rollback_data", None)
        if rollback_data is None:
            rollback_data = kwargs.get("rollback_data")
        variables = dict(context.variables)
        if rollback_data is not None:
            variables["securebench_rollback_data"] = dict(rollback_data)
        context = ExecutionContext(
            inventory=context.inventory,
            variables=variables,
            check_mode=context.check_mode,
            extra=context.extra,
        )
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

        Raises AnsibleExecutionError when the mapping is missing or the
        operation is unknown.
        """
        playbooks: Mapping[str, Any] = {}
        if context.extra and isinstance(context.extra, Mapping):
            raw = context.extra.get("playbooks")
            if isinstance(raw, Mapping):
                playbooks = raw

        if not playbooks:
            raise AnsibleExecutionError(
                "Ansible playbook mapping is missing from execution context."
            )

        playbook = playbooks.get(operation)
        if not isinstance(playbook, str) or not playbook.strip():
            raise AnsibleExecutionError(
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

        playbook = self._playbook_for(operation, context)

        variables = dict(context.variables or {})
        variables.update(
            {
                "control_id": control.control_id,
                "host": host,
                "operation": operation,
            }
        )

        effective_check_mode = (
            context.check_mode if check_mode is None else check_mode
        )

        run_kwargs: dict[str, Any] = {
            "playbook": playbook,
            "inventory": context.inventory,
            "extra_vars": variables,
            "check_mode": effective_check_mode,
        }
        try:
            result = self._executor.run(**run_kwargs, limit=host)
        except TypeError:
            result = self._executor.run(**run_kwargs)

        return_code = int(
            getattr(
                result,
                "return_code",
                getattr(result, "returncode", 1),
            )
        )
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""

        if return_code != 0:
            status = ExecutionStatus.FAILED
            changed = False
            message = stderr or stdout or f"ansible exited with {return_code}"
        else:
            status = ExecutionStatus.SUCCESS
            changed = (
                False
                if operation in {"audit", "verify", "precheck"}
                else not effective_check_mode
            )
            message = stdout

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=status,
            changed=changed,
            message=message,
            details={
                "return_code": return_code,
                "stderr": stderr,
                "operation": operation,
            },
        )
