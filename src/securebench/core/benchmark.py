"""
Benchmark domain model.

A Benchmark defines the controls that describe a target security state.

The benchmark is intentionally independent from remediation policy. It answers
what should be true, while profiles and policy determine what SecureBench is
allowed to change.
"""

from __future__ import annotations

from dataclasses import dataclass

from .control import Control


@dataclass(frozen=True, slots=True)
class Benchmark:
    """
    Immutable collection of security controls.

    A benchmark also owns the control dependency/conflict graph. References
    between controls must therefore point to controls that actually belong to
    this benchmark.

    Parameters
    ----------
    benchmark_id:
        Stable benchmark identifier.

    name:
        Human-readable benchmark name.

    version:
        Benchmark version.

    platform:
        Target platform identifier.

    description:
        Human-readable benchmark description.

    controls:
        Complete set of controls belonging to the benchmark.
    """

    benchmark_id: str
    name: str
    version: str
    platform: str
    description: str
    controls: tuple[Control, ...]

    def __post_init__(self) -> None:
        """Validate benchmark metadata and its control graph."""

        if not self.benchmark_id.strip():
            raise ValueError("benchmark_id must not be empty")

        if not self.name.strip():
            raise ValueError("name must not be empty")

        if not self.version.strip():
            raise ValueError("version must not be empty")

        if not self.platform.strip():
            raise ValueError("platform must not be empty")

        if not self.description.strip():
            raise ValueError("description must not be empty")

        if not isinstance(self.controls, tuple):
            raise ValueError("controls must be a tuple")

        control_ids: set[str] = set()

        for control in self.controls:
            if not isinstance(control, Control):
                raise ValueError(
                    "benchmark controls must contain Control instances"
                )

            if control.control_id in control_ids:
                raise ValueError(
                    f"duplicate control ID: {control.control_id}"
                )

            control_ids.add(control.control_id)

            if control.benchmark_id != self.benchmark_id:
                raise ValueError(
                    f"control '{control.control_id}' belongs to benchmark "
                    f"'{control.benchmark_id}', not '{self.benchmark_id}'"
                )

        self._validate_control_references(
            control_ids=control_ids,
        )

    def _validate_control_references(
        self,
        *,
        control_ids: set[str],
    ) -> None:
        """
        Validate dependency and conflict references.

        These references are execution-safety relationships, not merely
        descriptive metadata. A dangling reference could cause the planner
        to omit a prerequisite or fail to recognize a conflict.

        Therefore the benchmark must fail closed instead of accepting an
        incomplete control graph.
        """

        for control in self.controls:
            for dependency in control.dependencies:
                if dependency not in control_ids:
                    raise ValueError(
                        f"unknown dependency '{dependency}' referenced by "
                        f"control '{control.control_id}'"
                    )

            for conflict in control.conflicts:
                if conflict not in control_ids:
                    raise ValueError(
                        f"unknown conflict '{conflict}' referenced by "
                        f"control '{control.control_id}'"
                    )

    @classmethod
    def from_controls(
        cls,
        *,
        benchmark_id: str,
        name: str,
        version: str,
        platform: str,
        description: str,
        controls: list[Control] | tuple[Control, ...],
    ) -> Benchmark:
        """
        Construct a benchmark from an iterable collection of controls.

        The public domain model stores controls as a tuple so that a loaded
        benchmark cannot be mutated accidentally after validation.
        """

        return cls(
            benchmark_id=benchmark_id,
            name=name,
            version=version,
            platform=platform,
            description=description,
            controls=tuple(controls),
        )

    def get_control(
        self,
        control_id: str,
    ) -> Control:
        """
        Return a control by ID.

        Raises
        ------
        KeyError
            If the control does not exist.
        """

        if not control_id.strip():
            raise ValueError("control_id must not be empty")

        for control in self.controls:
            if control.control_id == control_id:
                return control

        raise KeyError(
            f"control '{control_id}' does not exist in benchmark "
            f"'{self.benchmark_id}'"
        )

    def has_control(
        self,
        control_id: str,
    ) -> bool:
        """Return whether the benchmark contains the requested control."""

        if not control_id.strip():
            raise ValueError("control_id must not be empty")

        return any(
            control.control_id == control_id
            for control in self.controls
        )

    @property
    def control_count(self) -> int:
        """Return the number of controls in the benchmark."""

        return len(self.controls)