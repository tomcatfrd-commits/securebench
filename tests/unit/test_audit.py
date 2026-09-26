from __future__ import annotations

from datetime import UTC, datetime

import pytest

from securebench.audit.engine import (
    AuditEngine,
    AuditRequest,
    UnsupportedAuditProvider,
)
from securebench.audit.evidence import EvidenceStore
from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
    SafetyClassification,
)
from securebench.core.result import AuditResult, ComplianceStatus


def make_control(control_id: str = "TEST-1") -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test control description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=RollbackCapability.GUARANTEED,
        metadata={
            "safety": {
                "default": SafetyClassification.SAFE.value,
                "prechecks": (),
            },
            "requirements": {
                "setting": "expected",
            },
        },
    )


class FakeAuditProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def audit(self, control: Control, host: str) -> AuditResult:
        self.calls.append((control.control_id, host))

        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.PASS,
            evidence=(),
            message="Control is compliant.",
        )


class FailingAuditProvider:
    def audit(self, control: Control, host: str) -> AuditResult:
        raise RuntimeError(f"Audit failed for {control.control_id} on {host}")


class StatusAuditProvider:
    def __init__(self, status: ComplianceStatus) -> None:
        self.status = status

    def audit(self, control: Control, host: str) -> AuditResult:
        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=self.status,
            evidence=(),
            message=f"Audit returned {self.status.value}.",
        )


def test_audit_engine_delegates_to_provider() -> None:
    provider = FakeAuditProvider()
    store = EvidenceStore()
    engine = AuditEngine(provider=provider, evidence_store=store)

    control = make_control()
    result = engine.audit(control, "server01")

    assert result.control_id == "TEST-1"
    assert result.host == "server01"
    assert result.status is ComplianceStatus.PASS
    assert provider.calls == [("TEST-1", "server01")]


def test_audit_engine_does_not_modify_control() -> None:
    provider = FakeAuditProvider()
    engine = AuditEngine(provider=provider)

    control = make_control()

    before = control

    result = engine.audit(control, "server01")

    assert result.status is ComplianceStatus.PASS
    assert control is before
    assert control.control_id == "TEST-1"


def test_audit_engine_stores_evidence() -> None:
    provider = FakeAuditProvider()
    store = EvidenceStore()
    engine = AuditEngine(provider=provider, evidence_store=store)

    control = make_control()

    result = engine.audit(control, "server01")

    assert result.status is ComplianceStatus.PASS

    evidence = store.for_control("TEST-1")

    assert len(evidence) == 1
    assert evidence[0].control_id == "TEST-1"
    assert evidence[0].host == "server01"


@pytest.mark.parametrize(
    "status",
    [
        ComplianceStatus.FAIL,
        ComplianceStatus.UNKNOWN,
        ComplianceStatus.ERROR,
    ],
)
def test_audit_engine_preserves_non_pass_status(
    status: ComplianceStatus,
) -> None:
    provider = StatusAuditProvider(status)
    engine = AuditEngine(provider=provider)

    result = engine.audit(make_control(), "server01")

    assert result.status is status


def test_audit_result_compliant_is_true_only_for_pass() -> None:
    for status in ComplianceStatus:
        result = AuditResult(
            control_id="TEST-1",
            host="server01",
            status=status,
            evidence=(),
        )

        assert result.compliant is (status is ComplianceStatus.PASS)


def test_audit_many_preserves_input_order() -> None:
    provider = FakeAuditProvider()
    engine = AuditEngine(provider=provider)

    controls = [
        make_control("TEST-1"),
        make_control("TEST-2"),
        make_control("TEST-3"),
    ]

    requests = [
        AuditRequest(control=controls[0], host="server01"),
        AuditRequest(control=controls[1], host="server02"),
        AuditRequest(control=controls[2], host="server03"),
    ]

    results = engine.audit_many(requests)

    assert [result.control_id for result in results] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]

    assert [result.host for result in results] == [
        "server01",
        "server02",
        "server03",
    ]


def test_audit_many_uses_provider_for_each_request() -> None:
    provider = FakeAuditProvider()
    engine = AuditEngine(provider=provider)

    controls = [
        make_control("TEST-1"),
        make_control("TEST-2"),
    ]

    requests = [
        AuditRequest(control=controls[0], host="server01"),
        AuditRequest(control=controls[1], host="server01"),
        AuditRequest(control=controls[0], host="server02"),
    ]

    engine.audit_many(requests)

    assert provider.calls == [
        ("TEST-1", "server01"),
        ("TEST-2", "server01"),
        ("TEST-1", "server02"),
    ]


def test_audit_many_empty_input_returns_empty_tuple() -> None:
    provider = FakeAuditProvider()
    engine = AuditEngine(provider=provider)

    assert engine.audit_many([]) == ()


def test_unsupported_provider_returns_unknown() -> None:
    provider = UnsupportedAuditProvider()
    engine = AuditEngine(provider=provider)

    result = engine.audit(make_control(), "server01")

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.compliant is False
    assert result.evidence
    assert result.evidence[0].source == "unsupported-audit-provider"


def test_unsupported_provider_does_not_claim_compliance() -> None:
    provider = UnsupportedAuditProvider()
    engine = AuditEngine(provider=provider)

    result = engine.audit(make_control(), "server01")

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.compliant is False


def test_audit_engine_propagates_provider_failure() -> None:
    provider = FailingAuditProvider()
    engine = AuditEngine(provider=provider)

    with pytest.raises(RuntimeError, match="Audit failed"):
        engine.audit(make_control(), "server01")


def test_audit_request_is_immutable() -> None:
    request = AuditRequest(
        control=make_control(),
        host="server01",
    )

    with pytest.raises(AttributeError):
        request.host = "server02"  # type: ignore[misc]


def test_audit_result_is_immutable() -> None:
    result = AuditResult(
        control_id="TEST-1",
        host="server01",
        status=ComplianceStatus.PASS,
        evidence=(),
        collected_at=datetime.now(UTC),
    )

    with pytest.raises(AttributeError):
        result.host = "server02"  # type: ignore[misc]