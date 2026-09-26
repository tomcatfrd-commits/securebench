from __future__ import annotations

import pytest

from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.exceptions import (
    BenchmarkError,
    ConfigurationError,
    ProfileError,
)
from securebench.core.loader import ConfigurationLoader
from securebench.core.profile import Profile, ProfileRule


def make_control(
    *,
    control_id: str = "TEST-1",
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
    metadata: dict | None = None,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="audit.test",
        remediation="remediation.test",
        rollback="rollback.test",
        verification="verification.test",
        rollback_capability=rollback_capability,
        metadata={} if metadata is None else metadata,
    )


def test_invalid_safety_classification_fails_closed() -> None:
    with pytest.raises(ProfileError):
        ProfileRule(
            classification="not-a-real-classification",  # type: ignore[arg-type]
        )


def test_enabled_investigate_rule_is_rejected() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.INVESTIGATE,
            enabled=True,
        )


def test_enabled_prohibited_rule_is_rejected() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=True,
        )


def test_prohibited_rule_cannot_request_approval() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.PROHIBITED,
            enabled=False,
            require_approval=True,
        )


def test_approval_required_rule_must_require_approval() -> None:
    with pytest.raises(ValueError):
        ProfileRule(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            enabled=False,
            require_approval=False,
        )


def test_unknown_profile_control_fails_closed() -> None:
    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        default_classification=SafetyClassification.INVESTIGATE,
        require_approval_for_unknown=True,
    )

    rule = profile.rule_for("UNKNOWN-CONTROL")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True
    assert profile.allows_automatic_remediation("UNKNOWN-CONTROL") is False


def test_investigate_default_is_not_automatically_remediable() -> None:
    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        default_classification=SafetyClassification.INVESTIGATE,
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN-CONTROL")

    assert rule.classification is SafetyClassification.INVESTIGATE
    assert rule.enabled is False
    assert profile.allows_automatic_remediation("UNKNOWN-CONTROL") is False


def test_prohibited_default_is_not_automatically_remediable() -> None:
    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        default_classification=SafetyClassification.PROHIBITED,
        require_approval_for_unknown=False,
    )

    rule = profile.rule_for("UNKNOWN-CONTROL")

    assert rule.classification is SafetyClassification.PROHIBITED
    assert rule.enabled is False
    assert rule.require_approval is False
    assert profile.allows_automatic_remediation("UNKNOWN-CONTROL") is False


def test_control_with_invalid_required_field_is_rejected() -> None:
    with pytest.raises(ValueError):
        make_control(control_id="")


def test_control_with_invalid_rollback_capability_is_rejected() -> None:
    with pytest.raises(ValueError):
        make_control(
            rollback_capability="invalid"  # type: ignore[arg-type]
        )


def test_control_metadata_must_be_mapping() -> None:
    with pytest.raises(TypeError):
        make_control(metadata=["invalid"])  # type: ignore[arg-type]


def test_missing_benchmark_file_fails_closed(tmp_path) -> None:
    loader = ConfigurationLoader()

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(tmp_path / "missing-benchmark.yml")


def test_missing_profile_file_fails_closed(tmp_path) -> None:
    loader = ConfigurationLoader()

    with pytest.raises(ProfileError):
        loader.load_profile(tmp_path / "missing-profile.yml")


def test_missing_controls_directory_fails_closed(tmp_path) -> None:
    benchmark_file = tmp_path / "benchmark.yml"

    benchmark_file.write_text(
        """
benchmark:
  id: test-benchmark
  name: Test Benchmark
  version: "1.0"
  platform: ubuntu-24.04
  description: Test benchmark.

controls:
  path: controls
""".strip(),
        encoding="utf-8",
    )

    loader = ConfigurationLoader()

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(benchmark_file)


def test_empty_controls_directory_fails_closed(tmp_path) -> None:
    controls_dir = tmp_path / "controls"
    controls_dir.mkdir()

    benchmark_file = tmp_path / "benchmark.yml"

    benchmark_file.write_text(
        """
benchmark:
  id: test-benchmark
  name: Test Benchmark
  version: "1.0"
  platform: ubuntu-24.04
  description: Test benchmark.

controls:
  path: controls
""".strip(),
        encoding="utf-8",
    )

    loader = ConfigurationLoader()

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(benchmark_file)


def test_malformed_yaml_fails_closed(tmp_path) -> None:
    benchmark_file = tmp_path / "benchmark.yml"

    benchmark_file.write_text(
        """
benchmark:
  id: [invalid
""".strip(),
        encoding="utf-8",
    )

    loader = ConfigurationLoader()

    with pytest.raises((BenchmarkError, ConfigurationError)):
        loader.load_benchmark(benchmark_file)