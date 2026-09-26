from __future__ import annotations

import pytest

from securebench.core.benchmark import Benchmark
from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)


def make_control(
    control_id: str,
    *,
    dependencies: tuple[str, ...] = (),
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
        dependencies=dependencies,
        conflicts=conflicts,
    )


def make_benchmark(*controls: Control) -> Benchmark:
    return Benchmark(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0",
        platform="ubuntu-24.04",
        description="Test benchmark.",
        controls=controls,
    )


def test_valid_dependency_is_accepted() -> None:
    dependency = make_control("TEST-1")
    dependent = make_control(
        "TEST-2",
        dependencies=("TEST-1",),
    )

    benchmark = make_benchmark(
        dependency,
        dependent,
    )

    assert benchmark.get_control("TEST-2").dependencies == ("TEST-1",)


def test_multiple_dependencies_are_accepted() -> None:
    first = make_control("TEST-1")
    second = make_control("TEST-2")
    dependent = make_control(
        "TEST-3",
        dependencies=("TEST-1", "TEST-2"),
    )

    benchmark = make_benchmark(
        first,
        second,
        dependent,
    )

    assert benchmark.get_control("TEST-3").dependencies == (
        "TEST-1",
        "TEST-2",
    )


def test_dependency_chain_is_accepted() -> None:
    first = make_control("TEST-1")
    second = make_control(
        "TEST-2",
        dependencies=("TEST-1",),
    )
    third = make_control(
        "TEST-3",
        dependencies=("TEST-2",),
    )

    benchmark = make_benchmark(
        first,
        second,
        third,
    )

    assert benchmark.get_control("TEST-3").dependencies == ("TEST-2",)


def test_missing_dependency_is_rejected() -> None:
    dependent = make_control(
        "TEST-2",
        dependencies=("DOES-NOT-EXIST",),
    )

    with pytest.raises(ValueError, match="unknown dependency"):
        make_benchmark(dependent)


def test_self_dependency_is_rejected() -> None:
    with pytest.raises(ValueError):
        make_control(
            "TEST-1",
            dependencies=("TEST-1",),
        )


def test_duplicate_dependency_is_rejected() -> None:
    with pytest.raises(ValueError):
        make_control(
            "TEST-1",
            dependencies=("TEST-2", "TEST-2"),
        )


def test_valid_conflict_is_accepted() -> None:
    first = make_control("TEST-1")
    second = make_control(
        "TEST-2",
        conflicts=("TEST-1",),
    )

    benchmark = make_benchmark(
        first,
        second,
    )

    assert benchmark.get_control("TEST-2").conflicts == ("TEST-1",)


def test_missing_conflict_is_rejected() -> None:
    control = make_control(
        "TEST-1",
        conflicts=("DOES-NOT-EXIST",),
    )

    with pytest.raises(ValueError, match="unknown conflict"):
        make_benchmark(control)


def test_self_conflict_is_rejected() -> None:
    with pytest.raises(ValueError):
        make_control(
            "TEST-1",
            conflicts=("TEST-1",),
        )


def test_duplicate_conflict_is_rejected() -> None:
    with pytest.raises(ValueError):
        make_control(
            "TEST-1",
            conflicts=("TEST-2", "TEST-2"),
        )


def test_one_sided_conflict_is_currently_valid() -> None:
    first = make_control("TEST-1")
    second = make_control(
        "TEST-2",
        conflicts=("TEST-1",),
    )

    benchmark = make_benchmark(
        first,
        second,
    )

    assert benchmark.has_control("TEST-1")
    assert benchmark.has_control("TEST-2")


def test_dependency_and_conflict_can_reference_different_controls() -> None:
    dependency = make_control("TEST-1")
    conflict = make_control("TEST-2")
    control = make_control(
        "TEST-3",
        dependencies=("TEST-1",),
        conflicts=("TEST-2",),
    )

    benchmark = make_benchmark(
        dependency,
        conflict,
        control,
    )

    loaded = benchmark.get_control("TEST-3")

    assert loaded.dependencies == ("TEST-1",)
    assert loaded.conflicts == ("TEST-2",)


def test_dependency_relationships_are_preserved_in_order() -> None:
    first = make_control("TEST-1")
    second = make_control("TEST-2")
    third = make_control(
        "TEST-3",
        dependencies=("TEST-1", "TEST-2"),
    )

    benchmark = make_benchmark(
        first,
        second,
        third,
    )

    assert benchmark.get_control("TEST-3").dependencies == (
        "TEST-1",
        "TEST-2",
    )