"""
SecureBench.

Modular security benchmark auditing, remediation, verification,
and rollback platform.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("securebench")
except PackageNotFoundError:
    # The package may be imported directly from the source tree before
    # it has been installed into the active Python environment.
    __version__ = "0.1.0"

__all__ = ["__version__"]