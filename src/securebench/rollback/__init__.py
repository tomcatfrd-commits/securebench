"""
SecureBench rollback package.

The rollback layer restores system state after unsuccessful or rejected
remediation transactions.
"""

from .engine import RollbackEngine, RollbackExecution, RollbackProvider
from .snapshot import (
    Snapshot,
    SnapshotCapability,
    SnapshotProvider,
    UnsupportedSnapshotProvider,
)
from .transaction import (
    TransactionRollbackCoordinator,
    TransactionRollbackResult,
)

__all__ = [
    "RollbackEngine",
    "RollbackExecution",
    "RollbackProvider",
    "Snapshot",
    "SnapshotCapability",
    "SnapshotProvider",
    "TransactionRollbackCoordinator",
    "TransactionRollbackResult",
    "UnsupportedSnapshotProvider",
]