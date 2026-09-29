"""Import the user-supplied CIS Ubuntu 24.04 v2.0.0 CSV catalog.

The importer deliberately does not translate CIS remediation prose into
executable automation. Imported controls fail closed until a reviewed
implementation declares its safety and rollback behavior.
"""

from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT_ROOT / "CIS Ubuntu Linux 24.04 LTS Benchmark (v2.0.0).csv"
VERSION_ROOT = PROJECT_ROOT / "benchmarks" / "cis" / "ubuntu" / "24.04" / "2.0.0"
CONTROL_ROOT = VERSION_ROOT / "controls"
COMPATIBILITY_MANIFEST = VERSION_ROOT.parent / "benchmark.yml"
INDEX_PATH = PROJECT_ROOT / "benchmarks" / "index.yml"

BENCHMARK_ID = "cis-ubuntu-24.04"
BENCHMARK_VERSION = "2.0.0"
PLATFORM = "ubuntu-24.04"


class LiteralString(str):
    """String emitted by PyYAML using a literal block scalar."""


class Dumper(yaml.SafeDumper):
    pass


def _represent_literal(dumper: Dumper, value: LiteralString) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")


Dumper.add_representer(LiteralString, _represent_literal)


def _multiline(value: str) -> str:
    value = value.strip()
    return LiteralString(value) if "\n" in value else value


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _comma_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _handler_id(ref: str, operation: str) -> str:
    normalized = ref.replace(".", "_")
    return f"cis.ubuntu.24.04.v2_0_0.{normalized}.{operation}"


def _control_document(row: dict[str, str]) -> dict[str, Any]:
    ref = row["ref"].strip()
    control_id = f"CIS-{ref}"
    is_cramfs = ref == "1.1.1.1"

    safety: dict[str, Any] = {
        "default": "investigate",
        "implementation_status": "guidance_only",
        "reason": (
            "Imported CIS guidance has not yet been promoted to a reviewed "
            "SecureBench implementation."
        ),
    }
    requirements: dict[str, Any] = {}
    rollback_capability = "unsupported"
    severity = "unspecified"

    if is_cramfs:
        severity = "low"
        rollback_capability = "guaranteed"
        requirements = {
            "module": "cramfs",
            "expected": {
                "module_loaded": False,
                "module_loadable": False,
            },
        }
        safety = {
            "default": "safe_with_precheck",
            "implementation_status": "implemented",
            "prechecks": [
                "verify_filesystem_not_in_use",
                "verify_module_not_required",
                "verify_modprobe_configuration_can_be_changed",
            ],
        }

    metadata: dict[str, Any] = {
        "source": {
            "benchmark_id": row["benchmark_id"].strip(),
            "benchmark_version": row["benchmark_version"].strip(),
            "reference": ref,
            "url": row["url"].strip(),
        },
        "assessment_status": row["assessment_status"].strip().lower(),
        "profiles": _lines(row["profiles"]),
        "mappings": {
            "nist": _comma_values(row["nist_controls"]),
            "cis_v8": _comma_values(row["cis_controls_v8"]),
            "cis_v7": _comma_values(row["cis_controls_v7"]),
            "mitre_techniques": _comma_values(row["mitre_techniques"]),
            "mitre_tactics": _comma_values(row["mitre_tactics"]),
            "mitre_mitigations": _comma_values(row["mitre_mitigations"]),
        },
        "parent": row["parent"].strip(),
        "rationale": _multiline(row["rationale"]),
        "impact": _multiline(row["impact"]),
        "audit_guidance": _multiline(row["audit"]),
        "remediation_guidance": _multiline(row["remediation"]),
        "additional_information": _multiline(row["additional_info"]),
        "default_value": _multiline(row["default_value"]),
        "artifacts_count": int(row["artifacts_count"] or 0),
        "requirements": requirements,
        "safety": safety,
    }

    return {
        "control": {
            "id": control_id,
            "benchmark_id": BENCHMARK_ID,
            "title": row["title"].strip(),
            "description": _multiline(row["description"]),
            "platform": PLATFORM,
            "severity": severity,
            "audit": _handler_id(ref, "audit"),
            "remediation": _handler_id(ref, "remediate"),
            "rollback": _handler_id(ref, "rollback"),
            "verification": _handler_id(ref, "verify"),
            "rollback_capability": rollback_capability,
            "metadata": metadata,
            "dependencies": [],
            "conflicts": [],
        }
    }


def _write_yaml(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.dump(
            document,
            Dumper=Dumper,
            allow_unicode=True,
            sort_keys=False,
            width=100,
        ),
        encoding="utf-8",
    )


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"CIS CSV source not found: {SOURCE}")

    source_bytes = SOURCE.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()

    with SOURCE.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))

    if len(rows) != 332:
        raise SystemExit(f"Expected 332 CIS controls, found {len(rows)}")

    refs = [row["ref"].strip() for row in rows]
    if len(refs) != len(set(refs)):
        raise SystemExit("CIS CSV contains duplicate control references")

    CONTROL_ROOT.mkdir(parents=True, exist_ok=True)
    expected_files: set[Path] = set()

    for row in rows:
        ref = row["ref"].strip()
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", ref):
            raise SystemExit(f"Unsafe CIS reference: {ref!r}")
        destination = CONTROL_ROOT / f"{ref}.yml"
        expected_files.add(destination)
        _write_yaml(destination, _control_document(row))

    for stale in CONTROL_ROOT.glob("*.yml"):
        if stale not in expected_files:
            stale.unlink()

    benchmark_document = {
        "benchmark": {
            "id": BENCHMARK_ID,
            "name": "CIS Ubuntu Linux 24.04 LTS Benchmark",
            "version": BENCHMARK_VERSION,
            "platform": PLATFORM,
            "description": (
                "CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0. Imported from "
                "the project-local CIS WorkBench CSV export."
            ),
            "source": {
                "type": "cis-workbench-csv",
                "benchmark_id": "26891",
                "file": SOURCE.name,
                "sha256": source_sha256,
                "control_count": len(rows),
            },
        },
        "controls": {"path": "controls"},
    }
    _write_yaml(VERSION_ROOT / "benchmark.yml", benchmark_document)

    compatibility_document = {
        **benchmark_document,
        "controls": {"path": "2.0.0/controls"},
    }
    _write_yaml(COMPATIBILITY_MANIFEST, compatibility_document)

    _write_yaml(
        INDEX_PATH,
        {
            "benchmarks": [
                {
                    "id": BENCHMARK_ID,
                    "version": BENCHMARK_VERSION,
                    "platform": PLATFORM,
                    "path": "cis/ubuntu/24.04/2.0.0/benchmark.yml",
                }
            ]
        },
    )

    print(f"Imported {len(rows)} controls into {VERSION_ROOT}")
    print(f"Source SHA-256: {source_sha256}")


if __name__ == "__main__":
    main()
