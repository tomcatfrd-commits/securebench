from __future__ import annotations

from types import MappingProxyType

import pytest

from securebench.core import (
    Benchmark,
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)


def make_control(
    *,
    control_id: str = "TEST-001",
    benchmark_id: str = "test-benchmark",
    title: str = "Test control",
    description: str = "Test description",
    platform: str = "ubuntu-24.04",
    severity: ControlSeverity = ControlSeverity.MEDIUM,
    audit: str = "test.audit",
    remediation: str = "test.remediate",
    rollback: str = "test.rollback",
    verification: str = "test.verify",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
    dependencies: tuple[str, ...] = (),
    conflicts: tuple[str, ...] = (),
    metadata: dict[str, object] | None = None,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id=benchmark_id,
        title=title,
        description=description,
        platform=platform,
        severity=severity,
        audit=audit,
        remediation=remediation,
        rollback=rollback,
        verification=verification,
        rollback_capability=rollback_capability,
        dependencies=dependencies,
        conflicts=conflicts,
        metadata=metadata or {},
    )


class TestControl:
    def test_control_is_immutable(self) -> None:
        control = make_control()

        with pytest.raises(AttributeError):
            control.title = "Modified"  # type: ignore[misc]

    def test_control_uses_slots(self) -> None:
        control = make_control()

        assert not hasattr(control, "__dict__")

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("control_id", ""),
            ("control_id", "   "),
            ("benchmark_id", ""),
            ("benchmark_id", "   "),
            ("title", ""),
            ("title", "   "),
            ("description", ""),
            ("description", "   "),
            ("platform", ""),
            ("platform", "   "),
            ("audit", ""),
            ("audit", "   "),
            ("remediation", ""),
            ("remediation", "   "),
            ("rollback", ""),
            ("rollback", "   "),
            ("verification", ""),
            ("verification", "   "),
        ],
    )
    def test_control_rejects_empty_required_fields(
        self,
        field: str,
        value: str,
    ) -> None:
        kwargs = {field: value}

        with pytest.raises(ValueError):
            make_control(**kwargs)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("severity", "medium"),
            ("rollback_capability", "guaranteed"),
        ],
    )
    def test_control_rejects_invalid_enum_types(
        self,
        field: str,
        value: str,
    ) -> None:
        with pytest.raises(TypeError):
            make_control(**{field: value})  # type: ignore[arg-type]

    def test_control_rejects_invalid_dependencies_type(self) -> None:
        with pytest.raises(TypeError):
            make_control(dependencies=["A"])  # type: ignore[arg-type]

    def test_control_rejects_invalid_conflicts_type(self) -> None:
        with pytest.raises(TypeError):
            make_control(conflicts=["A"])  # type: ignore[arg-type]

    def test_control_rejects_duplicate_dependencies(self) -> None:
        with pytest.raises(ValueError, match="duplicate dependency"):
            make_control(dependencies=("A", "A"))

    def test_control_rejects_duplicate_conflicts(self) -> None:
        with pytest.raises(ValueError, match="duplicate conflict"):
            make_control(conflicts=("A", "A"))

    def test_control_rejects_self_dependency(self) -> None:
        with pytest.raises(ValueError, match="cannot depend on itself"):
            make_control(control_id="A", dependencies=("A",))

    def test_control_rejects_self_conflict(self) -> None:
        with pytest.raises(ValueError, match="cannot conflict with itself"):
            make_control(control_id="A", conflicts=("A",))

    def test_control_preserves_dependencies_and_conflicts_as_tuples(self) -> None:
        control = make_control(
            dependencies=("A", "B"),
            conflicts=("C", "D"),
        )

        assert control.dependencies == ("A", "B")
        assert control.conflicts == ("C", "D")
        assert isinstance(control.dependencies, tuple)
        assert isinstance(control.conflicts, tuple)

    def test_control_metadata_is_recursively_immutable(self) -> None:
        control = make_control(
            metadata={
                "level": "L1",
                "references": ["CIS", "NIST"],
                "requirements": {
                    "module": "cramfs",
                    "expected": {
                        "loaded": False,
                    },
                },
            }
        )

        assert isinstance(control.metadata, MappingProxyType)
        assert control.metadata["level"] == "L1"
        assert control.metadata["references"] == ("CIS", "NIST")

        requirements = control.metadata["requirements"]
        assert isinstance(requirements, MappingProxyType)

        expected = requirements["expected"]
        assert isinstance(expected, MappingProxyType)
        assert expected["loaded"] is False

        with pytest.raises(TypeError):
            control.metadata["level"] = "L2"  # type: ignore[index]

        with pytest.raises(TypeError):
            requirements["module"] = "other"  # type: ignore[index]

    def test_control_metadata_is_not_affected_by_original_mapping(self) -> None:
        metadata = {
            "level": "L1",
            "references": ["CIS"],
        }

        control = make_control(metadata=metadata)

        metadata["level"] = "L2"
        metadata["references"].append("NIST")

        assert control.metadata["level"] == "L1"
        assert control.metadata["references"] == ("CIS",)

    def test_safety_metadata_defaults_to_empty_mapping(self) -> None:
        control = make_control()

        assert control.safety_metadata == {}

    def test_requirements_metadata_defaults_to_empty_mapping(self) -> None:
        control = make_control()

        assert control.requirements_metadata == {}

    def test_safety_metadata_returns_nested_mapping(self) -> None:
        control = make_control(
            metadata={
                "safety": {
                    "default_classification": "safe_with_precheck",
                    "prechecks": [
                        "verify_filesystem_not_in_use",
                    ],
                }
            }
        )

        safety = control.safety_metadata

        assert safety["default_classification"] == "safe_with_precheck"
        assert safety["prechecks"] == ("verify_filesystem_not_in_use",)

    def test_requirements_metadata_returns_nested_mapping(self) -> None:
        control = make_control(
            metadata={
                "requirements": {
                    "module": "cramfs",
                    "expected": {
                        "module_loaded": False,
                        "module_loadable": False,
                    },
                }
            }
        )

        requirements = control.requirements_metadata

        assert requirements["module"] == "cramfs"

        expected = requirements["expected"]
        assert expected["module_loaded"] is False
        assert expected["module_loadable"] is False

    def test_invalid_safety_metadata_raises(self) -> None:
        control = make_control(metadata={"safety": "invalid"})

        with pytest.raises(TypeError, match="safety metadata"):
            _ = control.safety_metadata

    def test_invalid_requirements_metadata_raises(self) -> None:
        control = make_control(metadata={"requirements": "invalid"})

        with pytest.raises(TypeError, match="requirements metadata"):
            _ = control.requirements_metadata


class TestBenchmark:
    def test_benchmark_is_immutable(self) -> None:
        benchmark = Benchmark(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=(make_control(),),
        )

        with pytest.raises(AttributeError):
            benchmark.name = "Modified"  # type: ignore[misc]

    def test_benchmark_uses_slots(self) -> None:
        benchmark = Benchmark(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=(make_control(),),
        )

        assert not hasattr(benchmark, "__dict__")

    def test_benchmark_controls_are_tuple(self) -> None:
        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=[make_control()],
        )

        assert isinstance(benchmark.controls, tuple)
        assert benchmark.control_count == 1

    def test_benchmark_rejects_control_from_different_benchmark(self) -> None:
        control = make_control(benchmark_id="other-benchmark")

        with pytest.raises(ValueError, match="belongs to benchmark"):
            Benchmark.from_controls(
                benchmark_id="test-benchmark",
                name="Test Benchmark",
                version="1.0.0",
                platform="ubuntu-24.04",
                description="Test benchmark",
                controls=[control],
            )

    def test_benchmark_rejects_duplicate_control_ids(self) -> None:
        controls = [
            make_control(control_id="A"),
            make_control(control_id="A"),
        ]

        with pytest.raises(ValueError, match="duplicate control ID"):
            Benchmark.from_controls(
                benchmark_id="test-benchmark",
                name="Test Benchmark",
                version="1.0.0",
                platform="ubuntu-24.04",
                description="Test benchmark",
                controls=controls,
            )

    def test_benchmark_validates_dependencies(self) -> None:
        controls = [
            make_control(control_id="A"),
            make_control(control_id="B", dependencies=("A",)),
        ]

        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=controls,
        )

        assert benchmark.get_control("B").dependencies == ("A",)

    def test_benchmark_validates_conflicts(self) -> None:
        controls = [
            make_control(control_id="A", conflicts=("B",)),
            make_control(control_id="B"),
        ]

        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=controls,
        )

        assert benchmark.get_control("A").conflicts == ("B",)

    def test_benchmark_rejects_missing_dependency(self) -> None:
        controls = [
            make_control(control_id="A", dependencies=("MISSING",)),
        ]

        with pytest.raises(ValueError, match="unknown dependency"):
            Benchmark.from_controls(
                benchmark_id="test-benchmark",
                name="Test Benchmark",
                version="1.0.0",
                platform="ubuntu-24.04",
                description="Test benchmark",
                controls=controls,
            )

    def test_benchmark_rejects_missing_conflict(self) -> None:
        controls = [
            make_control(control_id="A", conflicts=("MISSING",)),
        ]

        with pytest.raises(ValueError, match="unknown conflict"):
            Benchmark.from_controls(
                benchmark_id="test-benchmark",
                name="Test Benchmark",
                version="1.0.0",
                platform="ubuntu-24.04",
                description="Test benchmark",
                controls=controls,
            )

    def test_benchmark_get_control_returns_control(self) -> None:
        control = make_control(control_id="A")

        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=[control],
        )

        assert benchmark.get_control("A") is control

    def test_benchmark_get_control_rejects_blank_id(self) -> None:
        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=[make_control(control_id="A")],
        )

        with pytest.raises(ValueError, match="control_id"):
            benchmark.get_control("   ")

    def test_benchmark_get_control_rejects_unknown_id(self) -> None:
        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=[make_control(control_id="A")],
        )

        with pytest.raises(KeyError):
            benchmark.get_control("UNKNOWN")

    def test_benchmark_has_control(self) -> None:
        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=[make_control(control_id="A")],
        )

        assert benchmark.has_control("A") is True
        assert benchmark.has_control("UNKNOWN") is False

    def test_benchmark_control_count(self) -> None:
        benchmark = Benchmark.from_controls(
            benchmark_id="test-benchmark",
            name="Test Benchmark",
            version="1.0.0",
            platform="ubuntu-24.04",
            description="Test benchmark",
            controls=[
                make_control(control_id="A"),
                make_control(control_id="B"),
            ],
        )

        assert benchmark.control_count == 2


class TestEnums:
    def test_safety_classification_values_are_stable(self) -> None:
        assert SafetyClassification.SAFE.value == "safe"
        assert SafetyClassification.SAFE_WITH_PRECHECK.value == "safe_with_precheck"
        assert SafetyClassification.INVESTIGATE.value == "investigate"
        assert SafetyClassification.APPROVAL_REQUIRED.value == "approval_required"
        assert SafetyClassification.PROHIBITED.value == "prohibited"

    def test_rollback_capability_values_are_stable(self) -> None:
        assert RollbackCapability.GUARANTEED.value == "guaranteed"
        assert RollbackCapability.BEST_EFFORT.value == "best_effort"
        assert RollbackCapability.UNSUPPORTED.value == "unsupported"

    def test_control_severity_values_are_stable(self) -> None:
        assert ControlSeverity.LOW.value == "low"
        assert ControlSeverity.MEDIUM.value == "medium"
        assert ControlSeverity.HIGH.value == "high"
        assert ControlSeverity.CRITICAL.value == "critical"