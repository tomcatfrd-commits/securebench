from __future__ import annotations

from dataclasses import dataclass

from securebench.core.control import Control
from securebench.core.control_graph import ControlGraph
from securebench.core.exceptions import PlanningError


@dataclass(frozen=True, slots=True)
class Conflict:
    """A detected conflict between two controls."""

    control_id: str
    conflicting_control_id: str


@dataclass(frozen=True, slots=True)
class ConflictResolution:
    """
    Result of validating a requested control set against conflicts.

    An empty `conflicts` tuple means the requested set is conflict-free.
    """

    conflicts: tuple[Conflict, ...]

    @property
    def is_conflict_free(self) -> bool:
        return not self.conflicts


class ConflictResolver:
    """
    Detect conflicting controls before remediation execution.

    Conflict detection is deliberately separate from remediation. A conflict
    must be discovered during planning so that no remediation task is started
    before the complete requested set has been evaluated.
    """

    def __init__(self, graph: ControlGraph) -> None:
        self._graph = graph
        self._control_ids = {
            control.control_id
            for control in graph.controls
        }

    def validate(
        self,
        control_ids: tuple[str, ...],
    ) -> ConflictResolution:
        if len(set(control_ids)) != len(control_ids):
            raise PlanningError(
                "Duplicate control IDs were supplied for conflict validation."
            )

        unknown = [
            control_id
            for control_id in control_ids
            if control_id not in self._control_ids
        ]

        if unknown:
            raise PlanningError(
                "Cannot validate conflicts for unknown controls: "
                + ", ".join(unknown)
            )

        requested = set(control_ids)
        conflicts: list[Conflict] = []
        seen: set[tuple[str, str]] = set()

        for control_id in control_ids:
            for conflicting_id in self._graph.conflicts_for(control_id):
                if conflicting_id not in requested:
                    continue

                pair = tuple(
                    sorted((control_id, conflicting_id))
                )

                if pair in seen:
                    continue

                seen.add(pair)

                conflicts.append(
                    Conflict(
                        control_id=pair[0],
                        conflicting_control_id=pair[1],
                    )
                )

        return ConflictResolution(
            conflicts=tuple(conflicts)
        )

    def validate_or_raise(
        self,
        control_ids: tuple[str, ...],
    ) -> None:
        resolution = self.validate(control_ids)

        if resolution.is_conflict_free:
            return

        descriptions = ", ".join(
            f"{conflict.control_id} <-> "
            f"{conflict.conflicting_control_id}"
            for conflict in resolution.conflicts
        )

        raise PlanningError(
            f"Conflicting controls cannot be remediated together: "
            f"{descriptions}"
        )