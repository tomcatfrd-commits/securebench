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
from securebench.remediation.dependency import DependencyResolver


def make_control(
    control_id: str,
    *,
    dependencies: tuple[str, ...] = (),
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
        dependencies=dependencies,
    )


def make_resolver(*controls: Control) -> DependencyResolver:
    benchmark = Benchmark(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0.0",
        platform="ubuntu-24.04",
        description="Test benchmark.",
        controls=tuple(controls),
    )

    return DependencyResolver(
        ControlGraph.from_benchmark(benchmark)
    )


def test_resolver_includes_requested_control() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    result = resolver.resolve(("A",))

    assert [control.control_id for control in result.controls] == ["A"]


def test_resolver_includes_transitive_dependencies() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B", dependencies=("A",)),
        make_control("C", dependencies=("B",)),
    )

    result = resolver.resolve(("C",))

    assert [control.control_id for control in result.controls] == [
        "A",
        "B",
        "C",
    ]


def test_dependencies_are_before_dependants() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B", dependencies=("A",)),
        make_control("C", dependencies=("B",)),
    )

    result = resolver.resolve(("C",))

    ids = [control.control_id for control in result.controls]

    assert ids.index("A") < ids.index("B")
    assert ids.index("B") < ids.index("C")


def test_multiple_dependencies_are_resolved_deterministically() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B"),
        make_control(
            "C",
            dependencies=("A", "B"),
        ),
    )

    result = resolver.resolve(("C",))

    assert [control.control_id for control in result.controls] == [
        "A",
        "B",
        "C",
    ]


def test_shared_dependency_is_only_returned_once() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B", dependencies=("A",)),
        make_control("C", dependencies=("A",)),
    )

    result = resolver.resolve(("B", "C"))

    assert [control.control_id for control in result.controls] == [
        "A",
        "B",
        "C",
    ]


def test_requested_controls_preserve_dependency_safe_order() -> None:
    resolver = make_resolver(
        make_control("A"),
        make_control("B"),
        make_control("C", dependencies=("A",)),
    )

    result = resolver.resolve(("C", "B"))

    assert [control.control_id for control in result.controls] == [
        "A",
        "C",
        "B",
    ]


def test_duplicate_requested_control_ids_fail() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    with pytest.raises(
        PlanningError,
        match="Duplicate control IDs",
    ):
        resolver.resolve(("A", "A"))


def test_unknown_requested_control_fails_closed() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    with pytest.raises(
        PlanningError,
        match="unknown control",
    ):
        resolver.resolve(("MISSING",))


def test_dependency_cycle_fails_closed() -> None:
    # Construct the graph directly because the Benchmark model currently
    # permits a multi-control dependency cycle.
    controls = (
        make_control("A", dependencies=("B",)),
        make_control("B", dependencies=("C",)),
        make_control("C", dependencies=("A",)),
    )

    benchmark = Benchmark(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0.0",
        platform="ubuntu-24.04",
        description="Test benchmark.",
        controls=controls,
    )

    resolver = DependencyResolver(
        ControlGraph.from_benchmark(benchmark)
    )

    with pytest.raises(
        PlanningError,
        match="Dependency cycle detected",
    ):
        resolver.resolve(("A",))


def test_empty_request_produces_empty_resolution() -> None:
    resolver = make_resolver(
        make_control("A"),
    )

    result = resolver.resolve(())

    assert result.controls == ()


def test_resolution_does_not_modify_control_objects() -> None:
    control_a = make_control("A")
    control_b = make_control(
        "B",
        dependencies=("A",),
    )

    resolver = make_resolver(
        control_a,
        control_b,
    )

    original_a = control_a.dependencies
    original_b = control_b.dependencies

    resolver.resolve(("B",))

    assert control_a.dependencies == original_a
    assert control_b.dependencies == original_b


def test_resolution_returns_original_control_objects() -> None:
    control_a = make_control("A")
    control_b = make_control(
        "B",
        dependencies=("A",),
    )

    resolver = make_resolver(
        control_a,
        control_b,
    )

    result = resolver.resolve(("B",))

    assert result.controls[0] is control_a
    assert result.controls[1] is control_b