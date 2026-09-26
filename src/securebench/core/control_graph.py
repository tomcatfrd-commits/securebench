from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .benchmark import Benchmark
from .control import Control
from .exceptions import BenchmarkError


@dataclass(frozen=True, slots=True)
class ControlGraph:
    """
    Immutable dependency/conflict graph for a benchmark.

    The graph is derived from Control metadata. It does not modify the
    benchmark or controls and contains only control relationships.
    """

    controls: tuple[Control, ...]
    dependencies: dict[str, tuple[str, ...]]
    conflicts: dict[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        control_ids = tuple(control.control_id for control in self.controls)

        if len(set(control_ids)) != len(control_ids):
            raise BenchmarkError(
                "Control graph cannot contain duplicate control IDs."
            )

        control_id_set = set(control_ids)

        for control_id, dependencies in self.dependencies.items():
            if control_id not in control_id_set:
                raise BenchmarkError(
                    f"Dependency graph references unknown control: {control_id}"
                )

            for dependency_id in dependencies:
                if dependency_id not in control_id_set:
                    raise BenchmarkError(
                        f"Control {control_id} depends on unknown control "
                        f"{dependency_id}."
                    )

                if dependency_id == control_id:
                    raise BenchmarkError(
                        f"Control {control_id} cannot depend on itself."
                    )

        for control_id, conflicts in self.conflicts.items():
            if control_id not in control_id_set:
                raise BenchmarkError(
                    f"Conflict graph references unknown control: {control_id}"
                )

            for conflict_id in conflicts:
                if conflict_id not in control_id_set:
                    raise BenchmarkError(
                        f"Control {control_id} conflicts with unknown control "
                        f"{conflict_id}."
                    )

                if conflict_id == control_id:
                    raise BenchmarkError(
                        f"Control {control_id} cannot conflict with itself."
                    )

    @classmethod
    def from_benchmark(cls, benchmark: Benchmark) -> ControlGraph:
        controls = tuple(benchmark.controls)
        control_ids = {control.control_id for control in controls}

        dependencies = {
            control.control_id: tuple(control.dependencies)
            for control in controls
        }

        conflicts = {
            control.control_id: tuple(control.conflicts)
            for control in controls
        }

        for control_id, dependency_ids in dependencies.items():
            unknown = set(dependency_ids) - control_ids
            if unknown:
                raise BenchmarkError(
                    f"Control {control_id} depends on unknown controls: "
                    f"{sorted(unknown)}"
                )

        for control_id, conflict_ids in conflicts.items():
            unknown = set(conflict_ids) - control_ids
            if unknown:
                raise BenchmarkError(
                    f"Control {control_id} conflicts with unknown controls: "
                    f"{sorted(unknown)}"
                )

        return cls(
            controls=controls,
            dependencies=dependencies,
            conflicts=conflicts,
        )

    def control_ids(self) -> tuple[str, ...]:
        return tuple(control.control_id for control in self.controls)

    def dependencies_for(self, control_id: str) -> tuple[str, ...]:
        if control_id not in self.dependencies:
            raise KeyError(control_id)

        return self.dependencies[control_id]

    def conflicts_for(self, control_id: str) -> tuple[str, ...]:
        if control_id not in self.conflicts:
            raise KeyError(control_id)

        return self.conflicts[control_id]

    def has_dependency(self, control_id: str, dependency_id: str) -> bool:
        return dependency_id in self.dependencies_for(control_id)

    def has_conflict(self, control_id: str, conflict_id: str) -> bool:
        return conflict_id in self.conflicts_for(control_id)

    def transitive_dependencies(self, control_id: str) -> tuple[str, ...]:
        """
        Return all dependencies required by a control.

        The result is deterministic and excludes the requested control itself.
        Cycles are rejected rather than silently truncated.
        """
        if control_id not in self.dependencies:
            raise KeyError(control_id)

        resolved: list[str] = []
        resolved_set: set[str] = set()
        visiting: set[str] = set()

        def visit(current_id: str) -> None:
            if current_id in visiting:
                cycle = " -> ".join((*visiting, current_id))
                raise BenchmarkError(
                    f"Dependency cycle detected: {cycle}"
                )

            if current_id in resolved_set:
                return

            visiting.add(current_id)

            for dependency_id in self.dependencies_for(current_id):
                visit(dependency_id)

                if dependency_id not in resolved_set:
                    resolved.append(dependency_id)
                    resolved_set.add(dependency_id)

            visiting.remove(current_id)

        visit(control_id)

        return tuple(resolved)

    def conflicting_controls(self, control_ids: Iterable[str]) -> tuple[str, ...]:
        """
        Return conflicts involving any control in the supplied collection.

        Results are deterministic and contain each conflicting control once.
        """
        requested = tuple(control_ids)

        for control_id in requested:
            if control_id not in self.dependencies:
                raise KeyError(control_id)

        conflicts: list[str] = []
        seen: set[str] = set()

        for control_id in requested:
            for conflict_id in self.conflicts_for(control_id):
                if conflict_id not in seen:
                    conflicts.append(conflict_id)
                    seen.add(conflict_id)

        return tuple(conflicts)