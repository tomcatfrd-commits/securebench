"""Exact-version benchmark discovery and selection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .benchmark import Benchmark
from .exceptions import BenchmarkError, ProfileError
from .loader import ConfigurationLoader
from .profile import Profile


@dataclass(frozen=True, slots=True)
class BenchmarkReference:
    benchmark_id: str
    version: str
    platform: str
    path: Path


class BenchmarkCatalog:
    """Load benchmarks only through an explicit, versioned index."""

    def __init__(
        self,
        index_file: str | Path,
        *,
        loader: ConfigurationLoader | None = None,
    ) -> None:
        self._index_file = Path(index_file).resolve()
        self._root = self._index_file.parent
        self._loader = loader or ConfigurationLoader()
        self._references = self._load_references()

    @property
    def references(self) -> tuple[BenchmarkReference, ...]:
        return self._references

    def load(self, benchmark_id: str, version: str) -> Benchmark:
        matches = [
            reference
            for reference in self._references
            if reference.benchmark_id == benchmark_id and reference.version == version
        ]
        if not matches:
            raise BenchmarkError(
                f"benchmark '{benchmark_id}' version '{version}' is not registered"
            )

        reference = matches[0]
        benchmark = self._loader.load_benchmark(reference.path)
        if benchmark.benchmark_id != reference.benchmark_id:
            raise BenchmarkError("benchmark index ID does not match its manifest")
        if benchmark.version != reference.version:
            raise BenchmarkError("benchmark index version does not match its manifest")
        if benchmark.platform != reference.platform:
            raise BenchmarkError("benchmark index platform does not match its manifest")
        return benchmark

    def load_with_profile(
        self,
        benchmark_id: str,
        version: str,
        profile_file: str | Path,
    ) -> tuple[Benchmark, Profile]:
        benchmark = self.load(benchmark_id, version)
        profile = self._loader.load_profile(profile_file)

        if profile.benchmark_id not in {None, benchmark.benchmark_id}:
            raise ProfileError(
                f"profile targets benchmark '{profile.benchmark_id}', "
                f"not '{benchmark.benchmark_id}'"
            )
        if profile.benchmark_version not in {None, benchmark.version}:
            raise ProfileError(
                f"profile targets benchmark version '{profile.benchmark_version}', "
                f"not '{benchmark.version}'"
            )
        return benchmark, profile

    def _load_references(self) -> tuple[BenchmarkReference, ...]:
        if not self._index_file.is_file():
            raise BenchmarkError(f"benchmark index does not exist: {self._index_file}")

        try:
            data = yaml.safe_load(self._index_file.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise BenchmarkError(f"unable to load benchmark index: {exc}") from exc

        entries = data.get("benchmarks") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise BenchmarkError("benchmark index must contain a 'benchmarks' list")

        references: list[BenchmarkReference] = []
        identities: set[tuple[str, str]] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise BenchmarkError("benchmark index entries must be mappings")

            values: dict[str, str] = {}
            for field_name in ("id", "version", "platform", "path"):
                value = entry.get(field_name)
                if not isinstance(value, str) or not value.strip():
                    raise BenchmarkError(
                        f"benchmark index field '{field_name}' must be a non-empty string"
                    )
                values[field_name] = value.strip()

            identity = (values["id"], values["version"])
            if identity in identities:
                raise BenchmarkError(
                    f"duplicate benchmark index identity: {identity[0]} {identity[1]}"
                )
            identities.add(identity)

            manifest = (self._root / values["path"]).resolve()
            if not manifest.is_relative_to(self._root):
                raise BenchmarkError("benchmark manifest escapes the catalog directory")

            references.append(
                BenchmarkReference(
                    benchmark_id=values["id"],
                    version=values["version"],
                    platform=values["platform"],
                    path=manifest,
                )
            )

        return tuple(
            sorted(
                references,
                key=lambda reference: (
                    reference.benchmark_id,
                    reference.version,
                ),
            )
        )
