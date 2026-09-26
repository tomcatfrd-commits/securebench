"""
SecureBench execution package.

Execution backends provide the mechanism used to inspect, modify, verify,
and restore target systems.

The core SecureBench logic remains independent of the selected backend.
"""

from .ansible import (
    AnsibleExecutionBackend,
    AnsibleExecutionError,
    AnsibleExecutor,
    AnsibleRunResult,
)
from .base import (
    ExecutionBackend,
    ExecutionContext,
)

__all__ = [
    "AnsibleExecutionBackend",
    "AnsibleExecutionError",
    "AnsibleExecutor",
    "AnsibleRunResult",
    "ExecutionBackend",
    "ExecutionContext",
]