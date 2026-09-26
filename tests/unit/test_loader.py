from __future__ import annotations

from pathlib import Path

import pytest

from securebench.core import ConfigurationLoader
from securebench.core.exceptions import BenchmarkError, ProfileError


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


class TestConfigurationLoader:
    def test_loads_real_cis_benchmark(self) -> None:
        loader = ConfigurationLoader()

        benchmark = loader.load_benchmark(BENCHMARK_PATH)

        assert benchmark.benchmark_id == "cis-ubuntu-24.04"
        assert benchmark.name == "CIS Ubuntu Linux 24.04 LTS Benchmark"
        assert benchmark.version == "2.0.0"
        assert benchmark.platform == "ubuntu-24.04"
        assert benchmark.control_count >= 1

    def test_loads_real_cis_control_metadata(self) -> None:
        loader = ConfigurationLoader()

        benchmark = loader.load_benchmark(BENCHMARK_PATH)
        control = benchmark.get_control("CIS-1.1.1.1")

        assert control.metadata["level"] == "L1"
        assert control.metadata["server"] is True
        assert control.metadata["workstation"] is True
        assert control.metadata["automated"] is True

        assert control.safety_metadata["default_classification"] == (
            "safe_with_precheck"
        )

        assert control.safety_metadata["prechecks"] == (
            "verify_filesystem_not_in_use",
            "verify_module_not_required",
            "verify_modprobe_configuration_can_be_changed",
        )

        assert control.requirements_metadata["module"] == "cramfs"

        expected = control.requirements_metadata["expected"]

        assert expected["module_loaded"] is False
        assert expected["module_loadable"] is False

    def test_loads_control_rollback_capability(self) -> None:
        loader = ConfigurationLoader()

        benchmark = loader.load_benchmark(BENCHMARK_PATH)
        control = benchmark.get_control("CIS-1.1.1.1")

        assert control.rollback_capability.value == "guaranteed"

    def test_loads_empty_dependencies_and_conflicts(self) -> None:
        loader = ConfigurationLoader()

        benchmark = loader.load_benchmark(BENCHMARK_PATH)
        control = benchmark.get_control("CIS-1.1.1.1")

        assert control.dependencies == ()
        assert control.conflicts == ()

    def test_loads_production_safe_profile(self) -> None:
        loader = ConfigurationLoader()

        profile = loader.load_profile(PROFILE_PATH)

        assert profile.profile_id == "production-safe"
        assert profile.default_classification.value == "investigate"
        assert profile.require_approval_for_unknown is True
        assert profile.allow_best_effort_rollback is False

        rule = profile.rule_for("CIS-1.1.1.1")

        assert rule.classification.value == "safe_with_precheck"
        assert rule.enabled is True
        assert rule.require_approval is False

    def test_unknown_control_fails_closed(self) -> None:
        loader = ConfigurationLoader()

        profile = loader.load_profile(PROFILE_PATH)
        rule = profile.rule_for("UNKNOWN-CONTROL")

        assert rule.classification.value == "approval_required"
        assert rule.enabled is True
        assert rule.require_approval is True
        assert profile.allows_automatic_remediation("UNKNOWN-CONTROL") is False

    def test_metadata_is_immutable_after_loading(self) -> None:
        loader = ConfigurationLoader()

        benchmark = loader.load_benchmark(BENCHMARK_PATH)
        control = benchmark.get_control("CIS-1.1.1.1")

        with pytest.raises(TypeError):
            control.metadata["level"] = "L2"  # type: ignore[index]

        with pytest.raises(TypeError):
            control.safety_metadata["default_classification"] = "safe"  # type: ignore[index]

    def test_missing_benchmark_file_fails_closed(self, tmp_path: Path) -> None:
        loader = ConfigurationLoader()

        missing_path = tmp_path / "missing.yml"

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(missing_path)

    def test_missing_profile_file_fails_closed(self, tmp_path: Path) -> None:
        loader = ConfigurationLoader()

        missing_path = tmp_path / "missing.yml"

        with pytest.raises(ProfileError):
            loader.load_profile(missing_path)

    def test_missing_controls_directory_fails_closed(self, tmp_path: Path) -> None:
        benchmark_path = tmp_path / "benchmark.yml"

        benchmark_path.write_text(
            """
benchmark:
  id: test-benchmark
  name: Test Benchmark
  version: "1.0.0"
  platform: ubuntu-24.04
  description: Test benchmark

controls:
  path: controls
""".strip(),
            encoding="utf-8",
        )

        loader = ConfigurationLoader()

        with pytest.raises(BenchmarkError, match="controls"):
            loader.load_benchmark(benchmark_path)

    def test_invalid_profile_classification_fails_closed(
        self,
        tmp_path: Path,
    ) -> None:
        profile_path = tmp_path / "invalid-profile.yml"

        profile_path.write_text(
            """
profile:
  id: invalid-profile
  name: Invalid Profile
  description: Invalid profile
  defaults:
    classification: definitely_not_a_valid_classification
""".strip(),
            encoding="utf-8",
        )

        loader = ConfigurationLoader()

        with pytest.raises(ProfileError, match="invalid classification"):
            loader.load_profile(profile_path)

    def test_dangling_dependency_fails_closed(self, tmp_path: Path) -> None:
        benchmark_dir = tmp_path / "benchmark"
        controls_dir = benchmark_dir / "controls"
        controls_dir.mkdir(parents=True)

        benchmark_path = benchmark_dir / "benchmark.yml"

        benchmark_path.write_text(
            """
benchmark:
  id: test-benchmark
  name: Test Benchmark
  version: "1.0.0"
  platform: ubuntu-24.04
  description: Test benchmark

controls:
  path: controls
""".strip(),
            encoding="utf-8",
        )

        (controls_dir / "control.yml").write_text(
            """
control:
  id: TEST-001
  benchmark_id: test-benchmark
  title: Test control
  description: Test control
  platform: ubuntu-24.04
  severity: medium
  audit: test.audit
  remediation: test.remediate
  rollback: test.rollback
  verification: test.verify
  rollback_capability: guaranteed
  dependencies:
    - MISSING-CONTROL
""".strip(),
            encoding="utf-8",
        )

        loader = ConfigurationLoader()

        with pytest.raises(BenchmarkError, match="unknown dependency"):
            loader.load_benchmark(benchmark_path)

    def test_control_metadata_with_nested_structures_is_preserved(
        self,
        tmp_path: Path,
    ) -> None:
        benchmark_dir = tmp_path / "benchmark"
        controls_dir = benchmark_dir / "controls"
        controls_dir.mkdir(parents=True)

        benchmark_path = benchmark_dir / "benchmark.yml"

        benchmark_path.write_text(
            """
benchmark:
  id: test-benchmark
  name: Test Benchmark
  version: "1.0.0"
  platform: ubuntu-24.04
  description: Test benchmark

controls:
  path: controls
""".strip(),
            encoding="utf-8",
        )

        (controls_dir / "control.yml").write_text(
            """
control:
  id: TEST-001
  benchmark_id: test-benchmark
  title: Test control
  description: Test control
  platform: ubuntu-24.04
  severity: medium
  audit: test.audit
  remediation: test.remediate
  rollback: test.rollback
  verification: test.verify
  rollback_capability: guaranteed

  metadata:
    level: L1
    references:
      - CIS
      - NIST
    safety:
      default_classification: safe_with_precheck
      prechecks:
        - verify_something
    requirements:
      module: test-module
      expected:
        loaded: false
""".strip(),
            encoding="utf-8",
        )

        loader = ConfigurationLoader()

        benchmark = loader.load_benchmark(benchmark_path)
        control = benchmark.get_control("TEST-001")

        assert control.metadata["level"] == "L1"
        assert control.metadata["references"] == ("CIS", "NIST")
        assert control.safety_metadata["prechecks"] == (
            "verify_something",
        )
        assert control.requirements_metadata["module"] == "test-module"
        assert control.requirements_metadata["expected"]["loaded"] is False