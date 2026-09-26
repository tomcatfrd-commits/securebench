"""
SecureBench exception hierarchy.

The core layer uses domain-specific exceptions so higher layers can
distinguish expected security-automation failures from programming errors.
"""


class SecureBenchError(Exception):
    """Base exception for all SecureBench application errors."""


class ConfigurationError(SecureBenchError):
    """Raised when SecureBench configuration is invalid."""


class BenchmarkError(SecureBenchError):
    """Raised when benchmark data is invalid or cannot be loaded."""


class ControlError(SecureBenchError):
    """Raised when a control definition is invalid or unusable."""


class ProfileError(SecureBenchError):
    """Raised when a remediation profile is invalid or unusable."""


class PolicyError(SecureBenchError):
    """Raised when a policy decision cannot be evaluated safely."""


class AuditError(SecureBenchError):
    """Raised when auditing cannot produce a reliable result."""


class PlanningError(SecureBenchError):
    """Raised when a remediation plan cannot be safely constructed."""


class ExecutionError(SecureBenchError):
    """Raised when an execution backend cannot perform an operation."""


class VerificationError(SecureBenchError):
    """Raised when post-remediation verification cannot be completed."""


class RollbackError(SecureBenchError):
    """Raised when rollback cannot be completed reliably."""


class TransactionError(SecureBenchError):
    """Raised when a transaction reaches an invalid lifecycle state."""


class SafetyViolation(SecureBenchError):
    """
    Raised when an operation would violate SecureBench safety policy.

    This exception is intentionally separate from PolicyError because a
    safety violation should be treated as a hard stop rather than as an
    ordinary policy-evaluation failure.
    """