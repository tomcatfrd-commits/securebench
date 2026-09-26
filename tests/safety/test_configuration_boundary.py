from __future__ import annotations

from pathlib import Path

import pytest

from securebench.core.exceptions import BenchmarkError, ProfileError
from securebench.core.loader import ConfigurationLoader


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


def test_loader_accepts_known_benchmark(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    assert benchmark.benchmark_id == "cis-ubuntu-24.04"


def test_loader_accepts_known_profile(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert profile.profile_id == "production-safe"


def test_missing_benchmark_fails_closed(
    loader: ConfigurationLoader,
) -> None:
    missing = PROJECT_ROOT / "does-not-exist" / "benchmark.yml"

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(missing)


def test_missing_profile_fails_closed(
    loader: ConfigurationLoader,
) -> None:
    missing = PROJECT_ROOT / "does-not-exist" / "profile.yml"

    with pytest.raises(ProfileError):
        loader.load_profile(missing)


def test_loader_does_not_create_missing_benchmark(
    loader: ConfigurationLoader,
) -> None:
    missing = PROJECT_ROOT / "does-not-exist" / "benchmark.yml"

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(missing)

    assert not missing.exists()


def test_loader_does_not_create_missing_profile(
    loader: ConfigurationLoader,
) -> None:
    missing = PROJECT_ROOT / "does-not-exist" / "profile.yml"

    with pytest.raises(ProfileError):
        loader.load_profile(missing)

    assert not missing.exists()


def test_invalid_benchmark_yaml_fails_closed(
    loader: ConfigurationLoader,
    tmp_path: Path,
) -> None:
    benchmark_path = tmp_path / "benchmark.yml"
    benchmark_path.write_text(
        "benchmark: [invalid",
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(benchmark_path)


def test_invalid_profile_yaml_fails_closed(
    loader: ConfigurationLoader,
    tmp_path: Path,
) -> None:
    profile_path = tmp_path / "profile.yml"
    profile_path.write_text(
        "profile: [invalid",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError):
        loader.load_profile(profile_path)


def test_empty_benchmark_file_fails_closed(
    loader: ConfigurationLoader,
    tmp_path: Path,
) -> None:
    benchmark_path = tmp_path / "benchmark.yml"
    benchmark_path.write_text(
        "",
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(benchmark_path)


def test_empty_profile_file_fails_closed(
    loader: ConfigurationLoader,
    tmp_path: Path,
) -> None:
    profile_path = tmp_path / "profile.yml"
    profile_path.write_text(
        "",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError):
        loader.load_profile(profile_path)


def test_benchmark_path_must_be_a_file(
    loader: ConfigurationLoader,
    tmp_path: Path,
) -> None:
    benchmark_directory = tmp_path / "benchmark.yml"
    benchmark_directory.mkdir()

    with pytest.raises(BenchmarkError):
        loader.load_benchmark(benchmark_directory)


def test_profile_path_must_be_a_file(
    loader: ConfigurationLoader,
    tmp_path: Path,
) -> None:
    profile_directory = tmp_path / "profile.yml"
    profile_directory.mkdir()

    with pytest.raises(ProfileError):
        loader.load_profile(profile_directory)


def test_real_benchmark_contains_controls(
    loader: ConfigurationLoader,
) -> None:
    benchmark = loader.load_benchmark(BENCHMARK_PATH)

    assert benchmark.control_count > 0


def test_real_profile_has_conservative_defaults(
    loader: ConfigurationLoader,
) -> None:
    profile = loader.load_profile(PROFILE_PATH)

    assert profile.require_approval_for_unknown is True
    assert profile.allow_best_effort_rollback is False