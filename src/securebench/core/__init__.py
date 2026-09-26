"""
SecureBench core domain package.

The core package contains the benchmark-independent domain objects and
configuration loaders used throughout SecureBench.
"""

from .benchmark import Benchmark
from .control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from .exceptions import (
    AuditError,
    BenchmarkError,
    ConfigurationError,
    ControlError,
    ExecutionError,
    PlanningError,
    PolicyError,
    ProfileError,
    RollbackError,
    SafetyViolation,
    SecureBenchError,
    TransactionError,
    VerificationError,
)
from .loader import ConfigurationLoader
from .profile import Profile, ProfileRule
from .result import (
    AuditResult,
    ComplianceStatus,
    Evidence,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from .transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)

__all__ = [
    "AuditError",
    "AuditResult",
    "Benchmark",
    "BenchmarkError",
    "ChangeRecord",
    "ChangeStatus",
    "ComplianceStatus",
    "ConfigurationError",
    "ConfigurationLoader",
    "Control",
    "ControlError",
    "ControlSeverity",
    "Evidence",
    "ExecutionError",
    "ExecutionResult",
    "ExecutionStatus",
    "PlanningError",
    "PolicyError",
    "Profile",
    "ProfileError",
    "ProfileRule",
    "RollbackError",
    "RollbackCapability",
    "SafetyClassification",
    "SafetyViolation",
    "SecureBenchError",
    "Transaction",
    "TransactionError",
    "TransactionStatus",
    "VerificationError",
    "VerificationResult",
]