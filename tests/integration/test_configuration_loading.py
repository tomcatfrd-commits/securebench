from __future__ import annotations

from pathlib import Path

import pytest

from securebench.core.benchmark import Benchmark
from securebench.core.control import SafetyClassification
from securebench.core.loader import ConfigurationLoader
from securebench.core.profile import Profile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_PATH = (
    PROJECT_ROOT
    / "benchmarks"
    / "cis"
    / "ubuntu"
    / "24.04"
    / "benchmark.yml"
)
PROFILE_PATH = (
    PROJECT_ROOT
    / "profiles"
    / "production-safe.yml"
)


@pytest.fixture
def loader() -> ConfigurationLoader:
    return ConfigurationLoader()


def test_real_cis_benchmark_loads(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    assert isinstance(benchmark, Benchmark)
    assert benchmark.benchmark_id == "cis-ubuntu-24.04"
    assert benchmark.name == "CIS Ubuntu Linux 24.04 LTS Benchmark"
    assert benchmark.version == "2.0.0"
    assert benchmark.platform == "ubuntu-24.04"
    assert benchmark.control_count == 332


def test_real_cis_benchmark_contains_cramfs_control(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    assert control.control_id == "CIS-1.1.1.1"
    assert control.benchmark_id == benchmark.benchmark_id
    assert control.title == "Ensure cramfs kernel module is not available"


def test_real_cis_control_metadata_is_loaded(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    assert control.metadata["safety"]["default"] == (
        SafetyClassification.SAFE_WITH_PRECHECK.value
    )

    assert control.metadata["safety"]["prechecks"] == (
        "verify_filesystem_not_in_use",
        "verify_module_not_required",
        "verify_modprobe_configuration_can_be_changed",
    )


def test_real_cis_control_requirements_are_loaded(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    requirements = control.requirements_metadata

    assert requirements["module"] == "cramfs"
    assert requirements["expected"]["module_loaded"] is False
    assert requirements["expected"]["module_loadable"] is False


def test_real_cis_control_rollback_capability_is_loaded(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    assert control.rollback_capability.value == "guaranteed"


def test_real_production_safe_profile_loads(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert isinstance(profile, Profile)
    assert profile.profile_id == "production-safe"
    assert profile.name == "Production Safe"
    assert profile.allow_best_effort_rollback is False
    assert profile.require_approval_for_unknown is True


def test_real_production_safe_profile_explicitly_allows_cramfs(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    rule = profile.rule_for("CIS-1.1.1.1")

    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert rule.enabled is True
    assert rule.require_approval is False


def test_real_production_safe_profile_fails_closed_for_unknown_control(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    rule = profile.rule_for("CIS-UNKNOWN")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True


def test_real_benchmark_and_profile_can_be_loaded_together(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")
    rule = profile.rule_for(control.control_id)

    assert control.control_id == "CIS-1.1.1.1"
    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert rule.enabled is True


def test_real_benchmark_contains_no_duplicate_control_ids(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control_ids = [
        control.control_id
        for control in benchmark.controls
    ]

    assert len(control_ids) == len(set(control_ids))


def test_real_benchmark_control_references_are_valid(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control_ids = {
        control.control_id
        for control in benchmark.controls
    }

    for control in benchmark.controls:
        assert set(control.dependencies).issubset(control_ids)
        assert set(control.conflicts).issubset(control_ids)


def test_real_benchmark_controls_are_immutable(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    with pytest.raises(AttributeError):
        control.title = "Modified"  # type: ignore[misc]


def test_real_profile_rules_are_immutable(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    with pytest.raises(TypeError):
        profile.rules["CIS-1.1.1.1"] = profile.rule_for(
            "CIS-1.1.1.1"
        )  # type: ignore[index]
