"""
Execution backend abstraction.

SecureBench owns security policy, planning, transaction handling, and
verification orchestration.

An execution backend owns the mechanics of communicating with target
systems.

The first backend will be Ansible, but the SecureBench core must not depend
directly on Ansible-specific APIs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping

from securebench.core import (
    Control,
    ExecutionResult,
)


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """
    Context supplied to an execution backend.

    The context contains execution-related information without embedding
    benchmark or policy decisions.

    Parameters
    ----------
    inventory:
        Target inventory or host information understood by the backend.

    variables:
        Backend variables required during execution.

    check_mode:
        Whether the backend must perform a dry run without changing the
        target system.

    extra:
        Backend-specific extensions that do not belong in the core domain
        model.
    """

    inventory: str | None = None
    variables: Mapping[str, Any] = field(default_factory=dict)
    check_mode: bool = False
    extra: Mapping[str, Any] = field(default_factory=dict)


class ExecutionBackend(ABC):
    """
    Abstract interface for system execution.

    Implementations may use Ansible, SSH, an API, or another mechanism.

    The core application interacts with this interface rather than directly
    invoking a specific automation framework.
    """

    @abstractmethod
    def audit(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Collect information required to audit a control.

        Implementations MUST NOT modify the target system.
        """

    @abstractmethod
    def precheck(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Perform safety checks before remediation.

        Implementations MUST NOT modify the target system.
        """

    @abstractmethod
    def remediate(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Apply the requested control remediation.
        """

    @abstractmethod
    def rollback(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
        rollback_data: Mapping[str, Any],
    ) -> ExecutionResult:
        """
        Restore the state captured before remediation.

        ``rollback_data`` is produced by the transaction/evidence layer and
        must not be silently ignored by implementations.
        """

    @abstractmethod
    def verify(
        self,
        *,
        control: Control,
        host: str,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Independently verify the resulting target state.

        Verification MUST NOT remediate the target.
        """

    def close(self) -> None:
        """
        Release backend resources.

        Backends that do not maintain resources do not need to override this.
        """