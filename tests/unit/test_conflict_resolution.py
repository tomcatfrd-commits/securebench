from __future__ import annotations

import pytest

from securebench.core.benchmark import Benchmark
from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.control_graph import ControlGraph
from securebench.core.exceptions import PlanningError
from securebench.remediation.conflict import (
    Conflict,
    ConflictResolver,
)


def make_control(
    control_id: str,
    *,
    conflicts: tuple[str, ...] = (),
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title=f"Control {control_id}",
        description="Test control.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit=f"audit.{control_id}",
        remediation=f"remediation.{control_id}",
        rollback=f"rollback.{control_id}",
        verification=f"verification.{control_id}",
        rollback_capability=RollbackCapability.GUARANTEED,
        conflicts=conflicts,
    )


def make_resolver(*controls: Control) -> ConflictResolver:
    benchmark = Benchmark(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0.0",
        platform="ubuntu-24.04",
        description="Test benchmark.",
        controls=tuple(controls),
    )

    return ConflictResolver(
        ControlGraph.from_benchmark(benchmark)
    )


def test_conflict_free_set_is_accepted() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B"),
    )

    result = resolver.validate(("A", "B"))

    assert result.is_conflict_free is True
    assert result.conflicts == ()


def test_direct_conflict_is_detected() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B", conflicts=("A",)),
    )

    result = resolver.validate(("A", "B"))

    assert result.is_conflict_free is False
    assert result.conflicts == (
        Conflict(
            control_id="A",
            conflicting_control_id="B",
        ),
    )


def test_conflict_outside_requested_set_is_ignored() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B", conflicts=("A",)),
        make_control("C"),
    )

    result = resolver.validate(("B", "C"))

    assert result.is_conflict_free is True
    assert result.conflicts == ()


def test_conflict_is_reported_only_once() -> None:
    resolver = make_resolver(
        make_control("A", conflicts=("B",)),
        make_control("B", conflicts=("A",)),
    )

    result = resolver.validate(("A", "B"))

    assert result.conflicts == (
        Conflict(
            control_id="A",
            conflicting_control_id="B",
        ),
    )


def test_multiple_conflicts_are_reported_deterministically() -> None:
    resolver = make_resolver(
        make_control(
            "A",
            conflicts=("B", "C"),
        ),
        make_control("B"),
        make_control("C"),
    )

    result = resolver.validate(("A", "B", "C"))

    assert result.conflicts == (
        Conflict(
            control_id="A",
            conflicting_control_id="B",
        ),
        Conflict(
            control_id="A",
            conflicting_control_id="C",
        ),
    )


def test_conflict_detection_is_independent_of_input_order() -> None:
    resolver = make_resolver(
        make_control("A", conflicts=("B",)),
        make_control("B"),
    )

    first = resolver.validate(("A", "B"))
    second = resolver.validate(("B", "A"))

    assert first.conflicts == second.conflicts


def test_duplicate_control_ids_fail_closed() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    with pytest.raises(
        PlanningError,
        match="Duplicate control IDs",
    ):
        resolver.validate(("A", "A"))


def test_unknown_control_fails_closed() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    with pytest.raises(
        PlanningError,
        match="unknown controls",
    ):
        resolver.validate(("A", "MISSING"))


def test_empty_request_is_conflict_free() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    result = resolver.validate(())

    assert result.is_conflict_free is True
    assert result.conflicts == ()


def test_validate_or_raise_allows_conflict_free_set() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B"),
    )

    resolver.validate_or_raise(("A", "B"))


def test_validate_or_raise_rejects_conflicting_set() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B", conflicts=("A",)),
    )

    with pytest.raises(
        PlanningError,
        match="Conflicting controls cannot be remediated together",
    ):
        resolver.validate_or_raise(("A", "B"))


def test_conflict_result_is_immutable() -> None:
    conflict = Conflict(
        control_id="A",
        conflicting_control_id="B",
    )

    try:
        conflict.control_id = "C"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "Conflict must be immutable."
        )


def test_conflict_resolution_is_immutable() -> None:
    resolution = ConflictResolver(
        make_graph := ControlGraph.from_benchmark(
            Benchmark(
                benchmark_id="test-benchmark",
                name="Test Benchmark",
                version="1.0.0",
                platform="ubuntu-24.04",
                description="Test benchmark.",
                controls=(
                    make_control("A"),
                ),
            )
        )
    ).validate(("A",))

    assert resolution.is_conflict_free is True

    try:
        resolution.conflicts = ()  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "ConflictResolution must be immutable."
        )

    assert make_graph.control_ids() == ("A",)