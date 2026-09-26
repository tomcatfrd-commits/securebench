"""
SecureBench audit package.

The audit layer determines the current state of target systems without
modifying them.
"""

from .engine import (
    AuditEngine,
    AuditProvider,
    AuditRequest,
    UnsupportedAuditProvider,
)
from .evidence import EvidenceRecord, EvidenceStore, create_evidence

__all__ = [
    "AuditEngine",
    "AuditProvider",
    "AuditRequest",
    "EvidenceRecord",
    "EvidenceStore",
    "UnsupportedAuditProvider",
    "create_evidence",
]