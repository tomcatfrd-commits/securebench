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
    benchmark_id: str = "test-benchmark",
    dependencies: tuple[str, ...] = (),
    conflicts: tuple[str, ...] = (),
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id=benchmark_id,
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


def test_benchmark_rejects_duplicate_control_ids() -> None:
    first = make_control("TEST-1")
    second = make_control("TEST-1")

    with pytest.raises(ValueError, match="duplicate"):
        make_benchmark(first, second)


def test_benchmark_rejects_control_from_different_benchmark() -> None:
    control = make_control(
        "TEST-1",
        benchmark_id="different-benchmark",
    )

    with pytest.raises(ValueError, match="benchmark_id"):
        make_benchmark(control)


def test_benchmark_rejects_unknown_dependency() -> None:
    control = make_control(
        "TEST-1",
        dependencies=("MISSING-1",),
    )

    with pytest.raises(ValueError, match="unknown dependency"):
        make_benchmark(control)


def test_benchmark_rejects_unknown_conflict() -> None:
    control = make_control(
        "TEST-1",
        conflicts=("MISSING-1",),
    )

    with pytest.raises(ValueError, match="unknown conflict"):
        make_benchmark(control)


def test_benchmark_accepts_valid_control_graph() -> None:
    first = make_control("TEST-1")
    second = make_control(
        "TEST-2",
        dependencies=("TEST-1",),
    )
    third = make_control(
        "TEST-3",
        dependencies=("TEST-2",),
        conflicts=("TEST-1",),
    )

    benchmark = make_benchmark(first, second, third)

    assert benchmark.control_count == 3
    assert benchmark.has_control("TEST-1")
    assert benchmark.has_control("TEST-2")
    assert benchmark.has_control("TEST-3")


def test_benchmark_preserves_control_order() -> None:
    controls = (
        make_control("TEST-1"),
        make_control("TEST-2"),
        make_control("TEST-3"),
    )

    benchmark = make_benchmark(*controls)

    assert tuple(
        control.control_id
        for control in benchmark.controls
    ) == (
        "TEST-1",
        "TEST-2",
        "TEST-3",
    )


def test_benchmark_controls_are_read_only_tuple() -> None:
    benchmark = make_benchmark(
        make_control("TEST-1"),
    )

    assert isinstance(benchmark.controls, tuple)

    with pytest.raises(AttributeError):
        benchmark.controls.append(  # type: ignore[attr-defined]
            make_control("TEST-2")
        )


def test_benchmark_get_control_returns_exact_control() -> None:
    control = make_control("TEST-1")
    benchmark = make_benchmark(control)

    assert benchmark.get_control("TEST-1") is control


def test_benchmark_get_control_rejects_unknown_control() -> None:
    benchmark = make_benchmark(
        make_control("TEST-1"),
    )

    with pytest.raises(KeyError):
        benchmark.get_control("DOES-NOT-EXIST")


def test_benchmark_get_control_rejects_empty_id() -> None:
    benchmark = make_benchmark(
        make_control("TEST-1"),
    )

    with pytest.raises(ValueError):
        benchmark.get_control("")


def test_benchmark_has_control_is_false_for_unknown_id() -> None:
    benchmark = make_benchmark(
        make_control("TEST-1"),
    )

    assert benchmark.has_control("DOES-NOT-EXIST") is False


def test_benchmark_identity_is_immutable() -> None:
    benchmark = make_benchmark(
        make_control("TEST-1"),
    )

    with pytest.raises(AttributeError):
        benchmark.benchmark_id = "changed"  # type: ignore[misc]

    with pytest.raises(AttributeError):
        benchmark.version = "2.0"  # type: ignore[misc]


def test_empty_benchmark_is_allowed() -> None:
    benchmark = Benchmark(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0",
        platform="ubuntu-24.04",
        description="Empty benchmark.",
        controls=(),
    )

    assert benchmark.control_count == 0
    assert benchmark.controls == ()


def test_benchmark_from_controls_preserves_controls() -> None:
    controls = [
        make_control("TEST-1"),
        make_control("TEST-2"),
    ]

    benchmark = Benchmark.from_controls(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0",
        platform="ubuntu-24.04",
        description="Test benchmark.",
        controls=controls,
    )

    assert benchmark.controls == tuple(controls)


def test_dependency_cycle_is_detected_by_graph_validation_boundary() -> None:
    first = make_control(
        "TEST-1",
        dependencies=("TEST-2",),
    )
    second = make_control(
        "TEST-2",
        dependencies=("TEST-1",),
    )

    benchmark = make_benchmark(first, second)

    assert benchmark.get_control("TEST-1").dependencies == ("TEST-2",)
    assert benchmark.get_control("TEST-2").dependencies == ("TEST-1",)


def test_one_sided_conflict_does_not_corrupt_benchmark() -> None:
    first = make_control("TEST-1")
    second = make_control(
        "TEST-2",
        conflicts=("TEST-1",),
    )

    benchmark = make_benchmark(first, second)

    assert benchmark.get_control("TEST-2").conflicts == ("TEST-1",)
    assert benchmark.get_control("TEST-1").conflicts == ()


def test_control_objects_are_not_rewritten_by_benchmark() -> None:
    control = make_control(
        "TEST-1",
        dependencies=(),
        conflicts=(),
    )

    benchmark = make_benchmark(control)
    loaded = benchmark.get_control("TEST-1")

    assert loaded is control
    assert loaded.dependencies == ()
    assert loaded.conflicts == ()