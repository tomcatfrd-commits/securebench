"""
Security control domain model.

A Control is the fundamental benchmark unit in SecureBench.

A control describes:

    - what security property is expected,
    - how the current state is audited,
    - how remediation can be performed,
    - how the change can be rolled back,
    - how the resulting state is independently verified,
    - and what safety relationships exist with other controls.

The Control model is benchmark-independent. CIS, STIG, vendor benchmarks,
and custom benchmarks can all use the same abstraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class SafetyClassification(StrEnum):
    """Maximum automation level permitted for a control."""

    SAFE = "safe"
    SAFE_WITH_PRECHECK = "safe_with_precheck"
    INVESTIGATE = "investigate"
    APPROVAL_REQUIRED = "approval_required"
    PROHIBITED = "prohibited"


class RollbackCapability(StrEnum):
    """Strength of the rollback mechanism available for a control."""

    GUARANTEED = "guaranteed"
    BEST_EFFORT = "best_effort"
    UNSUPPORTED = "unsupported"


class ControlSeverity(StrEnum):
    """Security severity assigned to a benchmark control."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _freeze_metadata(value: object) -> object:
    """
    Recursively convert metadata containers into immutable equivalents.

    Benchmark metadata is configuration, not runtime state. Keeping it
    immutable prevents a loaded Control from being silently modified later by
    policy, audit, or remediation code.
    """

    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _freeze_metadata(item)
                for key, item in value.items()
            }
        )

    if isinstance(value, list):
        return tuple(
            _freeze_metadata(item)
            for item in value
        )

    if isinstance(value, tuple):
        return tuple(
            _freeze_metadata(item)
            for item in value
        )

    if isinstance(value, set):
        return frozenset(
            _freeze_metadata(item)
            for item in value
        )

    return value


@dataclass(frozen=True, slots=True)
class Control:
    """
    Immutable security benchmark control.

    Parameters
    ----------
    control_id:
        Stable identifier for the control.

    benchmark_id:
        Identifier of the benchmark that owns this control.

    title:
        Human-readable control title.

    description:
        Explanation of the expected security state.

    platform:
        Target platform identifier.

    severity:
        Security severity.

    audit:
        Identifier of the audit implementation.

    remediation:
        Identifier of the remediation implementation.

    rollback:
        Identifier of the rollback implementation.

    verification:
        Identifier of the independent verification implementation.

    rollback_capability:
        Declared rollback strength.

    dependencies:
        Control IDs that must be satisfied before this control can safely
        execute.

    conflicts:
        Control IDs that cannot safely coexist with this control.

    metadata:
        Benchmark-specific structured metadata.

        Metadata deliberately remains extensible so benchmark-specific
        information such as CIS levels, rationale, references, requirements,
        and safety declarations does not have to be hard-coded into the
        benchmark-independent domain model.
    """

    control_id: str
    benchmark_id: str
    title: str
    description: str
    platform: str
    severity: ControlSeverity

    audit: str
    remediation: str
    rollback: str
    verification: str

    rollback_capability: RollbackCapability

    dependencies: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()

    metadata: Mapping[str, object] = field(
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        """Validate the control definition and freeze mutable inputs."""

        required_strings = {
            "control_id": self.control_id,
            "benchmark_id": self.benchmark_id,
            "title": self.title,
            "description": self.description,
            "platform": self.platform,
            "audit": self.audit,
            "remediation": self.remediation,
            "rollback": self.rollback,
            "verification": self.verification,
        }

        for field_name, value in required_strings.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{field_name} must be a non-empty string"
                )

        if not isinstance(self.severity, ControlSeverity):
            raise TypeError(
                "severity must be a ControlSeverity"
            )

        if not isinstance(
                self.rollback_capability,
                RollbackCapability,
        ):
            raise TypeError(
                "rollback_capability must be a RollbackCapability"
            )

        self._validate_relationships()

        if not isinstance(self.metadata, Mapping):
            raise TypeError(
                "metadata must be a mapping"
            )

        object.__setattr__(
            self,
            "metadata",
            _freeze_metadata(self.metadata),
        )

    def _validate_relationships(self) -> None:
        """Validate dependency and conflict relationships."""

        for relationship_name, relationships in (
            ("dependency", self.dependencies),
            ("conflict", self.conflicts),
        ):
            if not isinstance(relationships, tuple):
                raise ValueError(
                    f"{relationship_name}s must be a tuple"
                )

            seen: set[str] = set()

            for related_control_id in relationships:
                if (
                    not isinstance(
                        related_control_id,
                        str,
                    )
                    or not related_control_id.strip()
                ):
                    raise ValueError(
                        f"{relationship_name} control IDs must be "
                        "non-empty strings"
                    )

                if related_control_id in seen:
                    raise ValueError(
                        f"duplicate {relationship_name}: "
                        f"{related_control_id}"
                    )

                seen.add(related_control_id)

                if related_control_id == self.control_id:
                    if relationship_name == "dependency":
                        raise ValueError(
                            f"control '{self.control_id}' cannot "
                            "depend on itself"
                        )
                    else:
                        raise ValueError(
                            f"control '{self.control_id}' cannot "
                            "conflict with itself"
                        )

    @property
    def safety_metadata(self) -> Mapping[str, object]:
        """
        Return the optional benchmark safety metadata.

        This is a convenience accessor. Policy decisions must still be made
        through Profile and PolicyEngine rather than by directly trusting
        benchmark metadata.
        """

        value = self.metadata.get("safety", {})

        if not isinstance(value, Mapping):
            raise ValueError(
                f"control '{self.control_id}' has invalid safety metadata"
            )

        return value

    @property
    def requirements_metadata(self) -> Mapping[str, object]:
        """
        Return optional benchmark requirement metadata.

        Requirement metadata describes what a control expects from the target;
        it does not itself perform an audit or remediation.
        """

        value = self.metadata.get("requirements", {})

        if not isinstance(value, Mapping):
            raise ValueError(
                f"control '{self.control_id}' has invalid requirements metadata"
            )

        return value


def is_valid_control_id(control_id: str) -> bool:
    """
    Return whether a control ID is syntactically valid.

    The benchmark format may use identifiers such as:

        CIS-1.1.1.1
        STIG-UBTU-22-010000
        CUSTOM-SSH-001

    The domain model intentionally does not impose a vendor-specific ID
    grammar. It only requires a non-empty string.
    """

    return isinstance(control_id, str) and bool(control_id.strip())