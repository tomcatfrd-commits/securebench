from __future__ import annotations

from pathlib import Path

import pytest

from securebench.core.control import RollbackCapability, SafetyClassification
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
PROFILE_PATH = PROJECT_ROOT / "profiles" / "production-safe.yml"


@pytest.fixture()
def loader() -> ConfigurationLoader:
    return ConfigurationLoader()


def test_production_safe_profile_loads(loader: ConfigurationLoader) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert isinstance(profile, Profile)
    assert profile.profile_id == "production-safe"


def test_production_safe_profile_requires_approval_by_default(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    rule = profile.rule_for("CONTROL-NOT-EXPLICITLY-ENABLED")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True


def test_production_safe_profile_explicitly_allows_only_known_control(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    rule = profile.rule_for("CIS-1.1.1.1")

    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert rule.enabled is True
    assert rule.require_approval is False


def test_production_safe_profile_does_not_allow_unknown_controls_automatically(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert (
        profile.allows_automatic_remediation(
            "UNKNOWN-CONTROL"
        )
        is False
    )


def test_production_safe_profile_disables_best_effort_rollback(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert profile.allow_best_effort_rollback is False


def test_benchmark_loads_successfully(loader: ConfigurationLoader) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    assert benchmark.benchmark_id == "cis-ubuntu-24.04"
    assert benchmark.platform == "ubuntu-24.04"
    assert benchmark.control_count == 332


def test_only_reviewed_control_claims_rollback_support(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    supported = [
        control.control_id
        for control in benchmark.controls
        if control.rollback_capability is not RollbackCapability.UNSUPPORTED
    ]

    assert supported == ["CIS-1.1.1.1"]


def test_imported_guidance_controls_fail_closed(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    for control in benchmark.controls:
        assert control.metadata["source"]["benchmark_version"] == "v2.0.0"
        if control.control_id != "CIS-1.1.1.1":
            assert control.rollback_capability is RollbackCapability.UNSUPPORTED
            assert control.safety_metadata["default"] == "investigate"
            assert control.safety_metadata["implementation_status"] == "guidance_only"


def test_production_safe_control_belongs_to_expected_benchmark(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    assert control.benchmark_id == "cis-ubuntu-24.04"
    assert control.platform == "ubuntu-24.04"


def test_production_safe_control_is_not_classified_as_unconditionally_safe(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")
    rule = profile.rule_for(control.control_id)

    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert rule.classification is not SafetyClassification.SAFE


def test_production_safe_control_requires_precheck(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")
    rule = profile.rule_for(control.control_id)

    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert profile.allows_automatic_remediation(control.control_id)


def test_production_safe_profile_contains_no_enabled_investigate_rule(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    for rule in profile.rules.values():
        if rule.classification is SafetyClassification.INVESTIGATE:
            assert rule.enabled is False


def test_production_safe_profile_contains_no_enabled_prohibited_rule(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    for rule in profile.rules.values():
        if rule.classification is SafetyClassification.PROHIBITED:
            assert rule.enabled is False
            assert rule.require_approval is False


def test_production_safe_profile_requires_approval_for_unknown_controls(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert profile.require_approval_for_unknown is True


def test_production_safe_profile_does_not_expand_benchmark_scope(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    configured_control_ids = set(profile.rules)

    assert configured_control_ids <= {
        control.control_id
        for control in benchmark.controls
    }


def test_production_safe_control_has_required_safety_metadata(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    safety = control.safety_metadata

    assert safety["default"] == "safe_with_precheck"
    assert safety["prechecks"]


def test_production_safe_control_declares_rollback_capability(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    assert control.rollback_capability.value == "guaranteed"


def test_production_safe_profile_file_exists() -> None:
    assert PROFILE_PATH.is_file()


def test_production_benchmark_file_exists() -> None:
    assert BENCHMARK_PATH.is_file()
