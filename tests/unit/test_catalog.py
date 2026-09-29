from __future__ import annotations

from pathlib import Path

import pytest

from securebench.core import BenchmarkCatalog, BenchmarkError, ProfileError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INDEX_PATH = PROJECT_ROOT / "benchmarks" / "index.yml"
PROFILE_PATH = PROJECT_ROOT / "profiles" / "production-safe.yml"


def test_catalog_loads_exact_cis_version() -> None:
    catalog = BenchmarkCatalog(INDEX_PATH)

    benchmark = catalog.load("cis-ubuntu-24.04", "2.0.0")

    assert benchmark.version == "2.0.0"
    assert benchmark.control_count == 332
    assert all(control.benchmark_version == "2.0.0" for control in benchmark.controls)
    assert all(len(control.definition_digest) == 64 for control in benchmark.controls)


def test_catalog_rejects_unregistered_version() -> None:
    catalog = BenchmarkCatalog(INDEX_PATH)

    with pytest.raises(BenchmarkError, match="not registered"):
        catalog.load("cis-ubuntu-24.04", "1.0.0")


def test_catalog_loads_matching_version_bound_profile() -> None:
    catalog = BenchmarkCatalog(INDEX_PATH)

    benchmark, profile = catalog.load_with_profile(
        "cis-ubuntu-24.04",
        "2.0.0",
        PROFILE_PATH,
    )

    assert profile.benchmark_id == benchmark.benchmark_id
    assert profile.benchmark_version == benchmark.version


def test_catalog_rejects_profile_for_different_version(tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.yml"
    profile_path.write_text(
        """
profile:
  id: wrong-version
  name: Wrong Version
  description: Version mismatch test.
  applies_to:
    benchmark_id: cis-ubuntu-24.04
    benchmark_version: "1.0.0"
  defaults:
    classification: investigate
    require_approval_for_unknown: true
    allow_best_effort_rollback: false
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="version"):
        BenchmarkCatalog(INDEX_PATH).load_with_profile(
            "cis-ubuntu-24.04",
            "2.0.0",
            profile_path,
        )
