"""
Configuration loading for benchmarks and remediation profiles.

The loader converts YAML configuration into validated SecureBench domain
objects. It is deliberately responsible for parsing and structural
validation, not for making remediation decisions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .benchmark import Benchmark
from .control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from .exceptions import BenchmarkError, ProfileError
from .profile import Profile, ProfileRule


class ConfigurationLoader:
    """Load benchmark and profile definitions from YAML files."""

    def load_benchmark(
        self,
        benchmark_file: str | Path,
    ) -> Benchmark:
        """
        Load a benchmark definition and all referenced controls.

        ``benchmark.yml`` contains benchmark metadata and the directory
        containing individual control definitions.
        """

        path = Path(benchmark_file)

        data = self._load_yaml(
            path,
            error_type=BenchmarkError,
        )

        benchmark_data = self._mapping(
            data,
            "benchmark",
            BenchmarkError,
        )

        benchmark_id = self._required_string(
            benchmark_data,
            "id",
            BenchmarkError,
        )

        name = self._required_string(
            benchmark_data,
            "name",
            BenchmarkError,
        )

        version = self._required_string(
            benchmark_data,
            "version",
            BenchmarkError,
        )

        platform = self._required_string(
            benchmark_data,
            "platform",
            BenchmarkError,
        )

        description = self._required_string(
            benchmark_data,
            "description",
            BenchmarkError,
        )

        controls_config = self._mapping(
            data,
            "controls",
            BenchmarkError,
        )

        controls_path_value = self._required_string(
            controls_config,
            "path",
            BenchmarkError,
        )

        controls_path = path.parent / controls_path_value

        if not controls_path.is_dir():
            raise BenchmarkError(
                f"control directory does not exist: {controls_path}"
            )

        control_files = sorted(
            controls_path.glob("*.yml"),
        )

        if not control_files:
            raise BenchmarkError(
                f"no control definitions found in: {controls_path}"
            )

        controls = [
            self._load_control(
                control_file,
                expected_benchmark_id=benchmark_id,
            )
            for control_file in control_files
        ]

        try:
            return Benchmark.from_controls(
                benchmark_id=benchmark_id,
                name=name,
                version=version,
                platform=platform,
                description=description,
                controls=controls,
            )
        except ValueError as exc:
            raise BenchmarkError(
                f"invalid benchmark '{benchmark_id}': {exc}"
            ) from exc

    def load_profile(
        self,
        profile_file: str | Path,
    ) -> Profile:
        """Load a remediation profile from YAML."""

        path = Path(profile_file)

        data = self._load_yaml(
            path,
            error_type=ProfileError,
        )

        profile_data = self._mapping(
            data,
            "profile",
            ProfileError,
        )

        profile_id = self._required_string(
            profile_data,
            "id",
            ProfileError,
        )

        name = self._required_string(
            profile_data,
            "name",
            ProfileError,
        )

        description = self._required_string(
            profile_data,
            "description",
            ProfileError,
        )

        defaults = profile_data.get(
            "defaults",
            {},
        )

        if defaults is None:
            defaults = {}

        if not isinstance(defaults, dict):
            raise ProfileError(
                "'profile.defaults' must be a mapping"
            )

        default_classification = self._classification(
            defaults.get(
                "classification",
                SafetyClassification.INVESTIGATE.value,
            ),
            ProfileError,
        )

        require_approval_for_unknown = self._boolean(
            defaults.get(
                "require_approval_for_unknown",
                True,
            ),
            "require_approval_for_unknown",
            ProfileError,
        )

        allow_best_effort_rollback = self._boolean(
            defaults.get(
                "allow_best_effort_rollback",
                False,
            ),
            "allow_best_effort_rollback",
            ProfileError,
        )

        raw_rules = profile_data.get(
            "rules",
            {},
        )

        if raw_rules is None:
            raw_rules = {}

        if not isinstance(raw_rules, dict):
            raise ProfileError(
                "'profile.rules' must be a mapping"
            )

        rules: dict[str, ProfileRule] = {}

        for control_id, raw_rule in raw_rules.items():
            if not isinstance(control_id, str) or not control_id.strip():
                raise ProfileError(
                    "profile rule IDs must be non-empty strings"
                )

            if not isinstance(raw_rule, dict):
                raise ProfileError(
                    f"profile rule '{control_id}' must be a mapping"
                )

            classification = self._classification(
                raw_rule.get(
                    "classification",
                    default_classification.value,
                ),
                ProfileError,
            )

            enabled = self._boolean(
                raw_rule.get(
                    "enabled",
                    True,
                ),
                f"{control_id}.enabled",
                ProfileError,
            )

            require_approval = self._boolean(
                raw_rule.get(
                    "require_approval",
                    False,
                ),
                f"{control_id}.require_approval",
                ProfileError,
            )

            try:
                rules[control_id] = ProfileRule(
                    classification=classification,
                    enabled=enabled,
                    require_approval=require_approval,
                )
            except ValueError as exc:
                raise ProfileError(
                    f"invalid profile rule '{control_id}': {exc}"
                ) from exc

        try:
            return Profile(
                profile_id=profile_id,
                name=name,
                description=description,
                default_classification=default_classification,
                rules=rules,
                allow_best_effort_rollback=allow_best_effort_rollback,
                require_approval_for_unknown=require_approval_for_unknown,
            )
        except ValueError as exc:
            raise ProfileError(
                f"invalid profile '{profile_id}': {exc}"
            ) from exc

    def _load_control(
        self,
        control_file: Path,
        *,
        expected_benchmark_id: str,
    ) -> Control:
        """Load one control definition from YAML."""

        data = self._load_yaml(
            control_file,
            error_type=BenchmarkError,
        )

        control_data = self._mapping(
            data,
            "control",
            BenchmarkError,
        )

        control_id = self._required_string(
            control_data,
            "id",
            BenchmarkError,
        )

        benchmark_id = self._required_string(
            control_data,
            "benchmark_id",
            BenchmarkError,
        )

        if benchmark_id != expected_benchmark_id:
            raise BenchmarkError(
                f"control '{control_id}' belongs to benchmark "
                f"'{benchmark_id}', expected '{expected_benchmark_id}'"
            )

        title = self._required_string(
            control_data,
            "title",
            BenchmarkError,
        )

        description = self._required_string(
            control_data,
            "description",
            BenchmarkError,
        )

        platform = self._required_string(
            control_data,
            "platform",
            BenchmarkError,
        )

        severity = self._enum_value(
            control_data,
            "severity",
            ControlSeverity,
            BenchmarkError,
        )

        audit = self._required_string(
            control_data,
            "audit",
            BenchmarkError,
        )

        remediation = self._required_string(
            control_data,
            "remediation",
            BenchmarkError,
        )

        rollback = self._required_string(
            control_data,
            "rollback",
            BenchmarkError,
        )

        verification = self._required_string(
            control_data,
            "verification",
            BenchmarkError,
        )

        rollback_capability = self._enum_value(
            control_data,
            "rollback_capability",
            RollbackCapability,
            BenchmarkError,
        )

        dependencies = self._string_list(
            control_data.get(
                "dependencies",
                [],
            ),
            "dependencies",
            BenchmarkError,
        )

        conflicts = self._string_list(
            control_data.get(
                "conflicts",
                [],
            ),
            "conflicts",
            BenchmarkError,
        )

        metadata = self._mapping_value(
            control_data.get(
                "metadata",
                {},
            ),
            "metadata",
            BenchmarkError,
        )

        try:
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
                metadata=metadata,
            )
        except ValueError as exc:
            raise BenchmarkError(
                f"invalid control '{control_id}' in "
                f"{control_file}: {exc}"
            ) from exc

    @staticmethod
    def _load_yaml(
        path: Path,
        *,
        error_type: type[Exception],
    ) -> dict[str, Any]:
        """Load one YAML document and require a mapping at its root."""

        if not path.is_file():
            raise error_type(
                f"configuration file does not exist: {path}"
            )

        try:
            with path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise error_type(
                f"invalid YAML in {path}: {exc}"
            ) from exc
        except OSError as exc:
            raise error_type(
                f"unable to read configuration file {path}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise error_type(
                f"configuration root must be a mapping: {path}"
            )

        return data

    @staticmethod
    def _mapping(
        data: dict[str, Any],
        key: str,
        error_type: type[Exception],
    ) -> dict[str, Any]:
        """Return a required mapping field."""

        value = data.get(key)

        if not isinstance(value, dict):
            raise error_type(
                f"'{key}' must be a mapping"
            )

        return value

    @staticmethod
    def _mapping_value(
        value: object,
        name: str,
        error_type: type[Exception],
    ) -> dict[str, Any]:
        """Validate an arbitrary mapping value."""

        if not isinstance(value, dict):
            raise error_type(
                f"'{name}' must be a mapping"
            )

        return value

    @staticmethod
    def _required_string(
        data: dict[str, Any],
        key: str,
        error_type: type[Exception],
    ) -> str:
        """Return a required non-empty string field."""

        value = data.get(key)

        if not isinstance(value, str) or not value.strip():
            raise error_type(
                f"'{key}' must be a non-empty string"
            )

        return value.strip()

    @staticmethod
    def _boolean(
        value: object,
        name: str,
        error_type: type[Exception],
    ) -> bool:
        """Validate a boolean configuration value."""

        if not isinstance(value, bool):
            raise error_type(
                f"'{name}' must be boolean"
            )

        return value

    @staticmethod
    def _classification(
        value: object,
        error_type: type[Exception],
    ) -> SafetyClassification:
        """Convert a YAML classification value into its enum."""

        if not isinstance(value, str):
            raise error_type(
                "classification must be a string"
            )

        try:
            return SafetyClassification(value)
        except ValueError as exc:
            valid_values = ", ".join(
                classification.value
                for classification in SafetyClassification
            )

            raise error_type(
                f"invalid classification '{value}'. "
                f"Expected one of: {valid_values}"
            ) from exc

    @staticmethod
    def _enum_value(
        data: dict[str, Any],
        key: str,
        enum_type: type[Any],
        error_type: type[Exception],
    ) -> Any:
        """Read and validate a string-backed enum field."""

        value = data.get(key)

        if not isinstance(value, str):
            raise error_type(
                f"'{key}' must be a string"
            )

        try:
            return enum_type(value)
        except ValueError as exc:
            valid_values = ", ".join(
                member.value
                for member in enum_type
            )

            raise error_type(
                f"invalid '{key}' value '{value}'. "
                f"Expected one of: {valid_values}"
            ) from exc

    @staticmethod
    def _string_list(
        value: object,
        name: str,
        error_type: type[Exception],
    ) -> tuple[str, ...]:
        """Validate a list of non-empty strings and return it as a tuple."""

        if not isinstance(value, list):
            raise error_type(
                f"'{name}' must be a list"
            )

        result: list[str] = []

        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise error_type(
                    f"'{name}' must contain only non-empty strings"
                )

            result.append(item.strip())

        return tuple(result)