from __future__ import annotations

from dataclasses import dataclass

from securebench.core.control import Control
from securebench.core.control_graph import ControlGraph
from securebench.core.exceptions import PlanningError


@dataclass(frozen=True, slots=True)
class DependencyResolution:
    """
    Resolved execution order for a requested set of controls.

    `controls` contains the requested controls and all of their transitive
    dependencies, ordered so dependencies execute before dependants.
    """

    controls: tuple[Control, ...]


class DependencyResolver:
    """
    Resolve control dependencies without performing any execution.

    This component belongs to planning, not remediation execution. Its job is
    to turn a requested control set into a deterministic, dependency-safe
    sequence.
    """

    def __init__(self, graph: ControlGraph) -> None:
        self._graph = graph
        self._controls = {
            control.control_id: control
            for control in graph.controls
        }

    def resolve(
        self,
        control_ids: tuple[str, ...],
    ) -> DependencyResolution:
        if len(set(control_ids)) != len(control_ids):
            raise PlanningError(
                "Duplicate control IDs were supplied for dependency resolution."
            )

        for control_id in control_ids:
            if control_id not in self._controls:
                raise PlanningError(
                    f"Cannot resolve unknown control: {control_id}"
                )

        ordered_ids: list[str] = []
        resolved: set[str] = set()
        visiting: set[str] = set()

        def visit(control_id: str) -> None:
            if control_id in resolved:
                return

            if control_id in visiting:
                raise PlanningError(
                    f"Dependency cycle detected while resolving {control_id}."
                )

            visiting.add(control_id)

            for dependency_id in self._graph.dependencies_for(control_id):
                visit(dependency_id)

            visiting.remove(control_id)

            if control_id not in resolved:
                resolved.add(control_id)
                ordered_ids.append(control_id)

        for control_id in control_ids:
            visit(control_id)

        return DependencyResolution(
            controls=tuple(
                self._controls[control_id]
                for control_id in ordered_ids
            )
        )