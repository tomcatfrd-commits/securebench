"""
SecureBench verification package.

The verification layer independently determines whether a remediation
resulted in the required security state.
"""

from .engine import (
    UnsupportedVerificationProvider,
    VerificationEngine,
    VerificationProvider,
)

__all__ = [
    "UnsupportedVerificationProvider",
    "VerificationEngine",
    "VerificationProvider",
]