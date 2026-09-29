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
    @pytest.fixture()
    def loader(self) -> ConfigurationLoader:
        return ConfigurationLoader()

    def test_load_benchmark_from_repository(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        benchmark = loader.load_benchmark(BENCHMARK_PATH)

        assert benchmark is not None
        assert benchmark.controls
        assert benchmark.benchmark_id
        assert benchmark.name

    def test_load_profile_from_repository(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        profile = loader.load_profile(PROFILE_PATH)

        assert profile is not None
        assert profile.profile_id
        assert profile.name

    def test_benchmark_contains_unique_control_ids(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        benchmark = loader.load_benchmark(BENCHMARK_PATH)

        control_ids = [
            control.control_id
            for control in benchmark.controls
        ]

        assert len(control_ids) == len(set(control_ids))

    def test_profile_contains_valid_rules(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        profile = loader.load_profile(PROFILE_PATH)

        for control_id, rule in profile.rules.items():
            assert control_id
            assert rule.classification is not None

    def test_missing_benchmark_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "missing.yml"

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)

    def test_missing_profile_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "missing.yml"

        with pytest.raises(ProfileError):
            loader.load_profile(path)

    def test_invalid_benchmark_yaml_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "invalid.yml"
        path.write_text(
            "benchmark:\n"
            "  [invalid yaml\n",
            encoding="utf-8",
        )

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)

    def test_invalid_profile_yaml_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "invalid.yml"
        path.write_text(
            "profile:\n"
            "  [invalid yaml\n",
            encoding="utf-8",
        )

        with pytest.raises(ProfileError):
            loader.load_profile(path)

    def test_empty_benchmark_file_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "empty.yml"
        path.write_text("", encoding="utf-8")

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)

    def test_empty_profile_file_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "empty.yml"
        path.write_text("", encoding="utf-8")

        with pytest.raises(ProfileError):
            loader.load_profile(path)

    def test_benchmark_path_must_be_a_file(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(BenchmarkError):
            loader.load_benchmark(tmp_path)

    def test_profile_path_must_be_a_file(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(ProfileError):
            loader.load_profile(tmp_path)

    def test_loading_same_benchmark_is_deterministic(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        first = loader.load_benchmark(BENCHMARK_PATH)
        second = loader.load_benchmark(BENCHMARK_PATH)

        assert first == second

    def test_loading_same_profile_is_deterministic(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        first = loader.load_profile(PROFILE_PATH)
        second = loader.load_profile(PROFILE_PATH)

        assert first == second

    def test_loader_does_not_modify_benchmark_file(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        before = BENCHMARK_PATH.read_bytes()

        loader.load_benchmark(BENCHMARK_PATH)

        after = BENCHMARK_PATH.read_bytes()

        assert after == before

    def test_loader_does_not_modify_profile_file(
        self,
        loader: ConfigurationLoader,
    ) -> None:
        before = PROFILE_PATH.read_bytes()

        loader.load_profile(PROFILE_PATH)

        after = PROFILE_PATH.read_bytes()

        assert after == before


class TestBenchmarkValidation:
    @pytest.fixture()
    def loader(self) -> ConfigurationLoader:
        return ConfigurationLoader()

    def _write(
        self,
        tmp_path: Path,
        content: str,
    ) -> Path:
        path = tmp_path / "benchmark.yml"
        path.write_text(content, encoding="utf-8")
        return path

    @pytest.mark.parametrize(
        "content",
        [
            "[]\n",
            "null\n",
            "42\n",
            "true\n",
            "benchmark: []\n",
        ],
    )
    def test_invalid_root_structure_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
        content: str,
    ) -> None:
        path = self._write(tmp_path, content)

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)

    def test_missing_required_benchmark_identity_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = self._write(
            tmp_path,
            """
controls: []
""".lstrip(),
        )

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)

    def test_invalid_controls_collection_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = self._write(
            tmp_path,
            """
id: test
name: Test Benchmark
controls: invalid
""".lstrip(),
        )

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)

    def test_duplicate_control_ids_are_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = self._write(
            tmp_path,
            """
id: test
name: Test Benchmark
controls:
  - id: TEST-001
  - id: TEST-001
""".lstrip(),
        )

        with pytest.raises(BenchmarkError):
            loader.load_benchmark(path)


class TestProfileValidation:
    @pytest.fixture()
    def loader(self) -> ConfigurationLoader:
        return ConfigurationLoader()

    def _write(
        self,
        tmp_path: Path,
        content: str,
    ) -> Path:
        path = tmp_path / "profile.yml"
        path.write_text(content, encoding="utf-8")
        return path

    @pytest.mark.parametrize(
        "content",
        [
            "[]\n",
            "null\n",
            "42\n",
            "true\n",
        ],
    )
    def test_invalid_root_structure_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
        content: str,
    ) -> None:
        path = self._write(tmp_path, content)

        with pytest.raises(ProfileError):
            loader.load_profile(path)

    def test_missing_required_profile_identity_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = self._write(
            tmp_path,
            """
rules: {}
""".lstrip(),
        )

        with pytest.raises(ProfileError):
            loader.load_profile(path)

    def test_invalid_rules_collection_is_rejected(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = self._write(
            tmp_path,
            """
id: test
name: Test Profile
rules: invalid
""".lstrip(),
        )

        with pytest.raises(ProfileError):
            loader.load_profile(path)

    def test_duplicate_yaml_keys_are_not_silently_accepted(
        self,
        loader: ConfigurationLoader,
        tmp_path: Path,
    ) -> None:
        path = self._write(
            tmp_path,
            """
id: test
id: duplicate
name: Test Profile
rules: {}
""".lstrip(),
        )

        with pytest.raises(ProfileError):
            loader.load_profile(path)
