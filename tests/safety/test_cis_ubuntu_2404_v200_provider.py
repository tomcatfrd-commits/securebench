from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from securebench.core import (
    ComplianceStatus,
    ConfigurationLoader,
    ExecutionError,
    ExecutionResult,
    ExecutionStatus,
)
from securebench.core.transaction import ChangeRecord
from securebench.execution.cis_ubuntu_2404 import CISUbuntu2404V200Provider

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_PATH = (
    PROJECT_ROOT
    / "benchmarks"
    / "cis"
    / "ubuntu"
    / "24.04"
    / "2.0.0"
    / "benchmark.yml"
)
PLAYBOOK_ROOT = (
    PROJECT_ROOT
    / "ansible"
    / "playbooks"
    / "cis_ubuntu_24_04_v2_0_0"
)


class RecordingBackend:
    def __init__(self) -> None:
        self.operations: list[str] = []

    def _result(self, operation, control, host):
        self.operations.append(operation)
        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=operation in {"prepare_rollback", "remediate", "rollback"},
            message=f"{operation} completed",
            details={"return_code": 0},
        )

    def audit(self, control, host, context):
        return self._result("audit", control, host)

    def precheck(self, control, host, context):
        return self._result("precheck", control, host)

    def prepare_rollback(self, control, host, context):
        return self._result("prepare_rollback", control, host)

    def remediate(self, control, host, context):
        return self._result("remediate", control, host)

    def verify(self, control, host, context):
        return self._result("verify", control, host)

    def rollback(self, control, host, change, context):
        assert change.rollback_data
        return self._result("rollback", control, host)


@pytest.fixture(scope="module")
def benchmark():
    return ConfigurationLoader().load_benchmark(BENCHMARK_PATH)


def make_provider(backend: RecordingBackend) -> CISUbuntu2404V200Provider:
    return CISUbuntu2404V200Provider(
        inventory="inventory.ini",
        transaction_id="tx-001",
        playbook_root=PLAYBOOK_ROOT,
        backend=backend,  # type: ignore[arg-type]
    )


def test_reviewed_cramfs_provider_supports_complete_lifecycle(benchmark) -> None:
    control = benchmark.get_control("CIS-1.1.1.1")
    backend = RecordingBackend()
    provider = make_provider(backend)

    assert provider.audit(control, "server01").status is ComplianceStatus.PASS
    assert provider.precheck(control, "server01").succeeded
    preparation = provider.prepare_rollback(control, "server01")
    assert preparation.rollback_data["transaction_id"] == "tx-001"
    assert provider.remediate(control, "server01").succeeded
    assert provider.verify(control, "server01").status is ComplianceStatus.PASS

    change = ChangeRecord(
        change_id="change-001",
        control_id=control.control_id,
        host="server01",
        rollback_data=preparation.rollback_data,
    )
    assert provider.rollback(control, "server01", change).success
    assert backend.operations == [
        "audit",
        "precheck",
        "prepare_rollback",
        "remediate",
        "verify",
        "rollback",
    ]


def test_unreviewed_control_is_never_executed(benchmark) -> None:
    control = benchmark.get_control("CIS-1.1.1.2")
    backend = RecordingBackend()

    with pytest.raises(ExecutionError, match="no reviewed implementation"):
        make_provider(backend).audit(control, "server01")

    assert backend.operations == []


def test_all_cis_playbooks_are_valid_yaml_documents() -> None:
    playbooks = sorted(PLAYBOOK_ROOT.glob("*.yml"))
    assert len(playbooks) == 6

    for playbook in playbooks:
        document = yaml.safe_load(playbook.read_text(encoding="utf-8"))
        assert isinstance(document, list)
        assert document
