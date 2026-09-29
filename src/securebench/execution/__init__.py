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
from .cis_ubuntu_2404 import CISUbuntu2404V200Provider

__all__ = [
    "AnsibleExecutionBackend",
    "AnsibleExecutionError",
    "AnsibleExecutor",
    "AnsibleRunResult",
    "CISUbuntu2404V200Provider",
    "ExecutionBackend",
    "ExecutionContext",
]
