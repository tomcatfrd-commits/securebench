from __future__ import annotations

from securebench.audit.engine import AuditEngine, AuditRequest
from securebench.audit.evidence import EvidenceStore
from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    Evidence,
)


def make_control(
    *,
    control_id: str = "TEST-1",
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
        rollback_capability=RollbackCapability.GUARANTEED,
    )


class RecordingAuditProvider:
    def __init__(
        self,
        *,
        status: ComplianceStatus = ComplianceStatus.PASS,
    ) -> None:
        self.status = status
        self.calls: list[tuple[str, str]] = []

    def audit(self, control, host: str) -> AuditResult:
        self.calls.append((control.control_id, host))

        evidence = Evidence(
            control_id=control.control_id,
            host=host,
            source="recording-audit-provider",
            observed={"compliant": self.status is ComplianceStatus.PASS},
            expected={"compliant": True},
        )

        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=self.status,
            evidence=(evidence,),
        )


def test_audit_calls_only_audit_provider() -> None:
    control = make_control()
    provider = RecordingAuditProvider()
    store = EvidenceStore()
    engine = AuditEngine(
        provider=provider,
        evidence_store=store,
    )

    result = engine.audit(
        AuditRequest(
            control=control,
            host="production-01",
        )
    )

    assert result.status is ComplianceStatus.PASS
    assert result.compliant is True
    assert provider.calls == [
        (control.control_id, "production-01")
    ]


def test_audit_does_not_modify_control() -> None:
    control = make_control()
    provider = RecordingAuditProvider()
    engine = AuditEngine(
        provider=provider,
        evidence_store=EvidenceStore(),
    )

    original_title = control.title
    original_dependencies = control.dependencies
    original_conflicts = control.conflicts

    engine.audit(
        AuditRequest(
            control=control,
            host="production-01",
        )
    )

    assert control.title == original_title
    assert control.dependencies == original_dependencies
    assert control.conflicts == original_conflicts


def test_audit_stores_evidence() -> None:
    control = make_control()
    store = EvidenceStore()
    engine = AuditEngine(
        provider=RecordingAuditProvider(),
        evidence_store=store,
    )

    result = engine.audit(
        AuditRequest(
            control=control,
            host="production-01",
        )
    )

    evidence = store.for_control(
        control.control_id,
        host="production-01",
    )

    assert len(evidence) == 1
    assert evidence[0] is result.evidence[0]
    assert evidence[0].source == "recording-audit-provider"


def test_failed_audit_result_is_preserved() -> None:
    control = make_control()
    provider = RecordingAuditProvider(
        status=ComplianceStatus.FAIL,
    )
    engine = AuditEngine(
        provider=provider,
        evidence_store=EvidenceStore(),
    )

    result = engine.audit(
        AuditRequest(
            control=control,
            host="production-01",
        )
    )

    assert result.status is ComplianceStatus.FAIL
    assert result.compliant is False


def test_unknown_audit_result_is_preserved() -> None:
    control = make_control()
    provider = RecordingAuditProvider(
        status=ComplianceStatus.UNKNOWN,
    )
    engine = AuditEngine(
        provider=provider,
        evidence_store=EvidenceStore(),
    )

    result = engine.audit(
        AuditRequest(
            control=control,
            host="production-01",
        )
    )

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.compliant is False


def test_audit_many_preserves_request_order() -> None:
    controls = (
        make_control(control_id="TEST-1"),
        make_control(control_id="TEST-2"),
        make_control(control_id="TEST-3"),
    )

    provider = RecordingAuditProvider()
    engine = AuditEngine(
        provider=provider,
        evidence_store=EvidenceStore(),
    )

    requests = tuple(
        AuditRequest(
            control=control,
            host="production-01",
        )
        for control in controls
    )

    results = engine.audit_many(requests)

    assert [result.control_id for result in results] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]

    assert provider.calls == [
        ("TEST-1", "production-01"),
        ("TEST-2", "production-01"),
        ("TEST-3", "production-01"),
    ]


def test_empty_audit_batch_has_no_side_effects() -> None:
    provider = RecordingAuditProvider()
    store = EvidenceStore()
    engine = AuditEngine(
        provider=provider,
        evidence_store=store,
    )

    results = engine.audit_many(())

    assert results == ()
    assert provider.calls == []
    assert store.all() == ()


def test_audit_provider_failure_is_not_converted_to_pass() -> None:
    control = make_control()

    class FailingProvider:
        def audit(self, control, host: str) -> AuditResult:
            raise RuntimeError("audit backend failed")

    engine = AuditEngine(
        provider=FailingProvider(),
        evidence_store=EvidenceStore(),
    )

    try:
        engine.audit(
            AuditRequest(
                control=control,
                host="production-01",
            )
        )
    except RuntimeError as exc:
        assert str(exc) == "audit backend failed"
    else:
        raise AssertionError("Audit failure was silently converted to success.")


def test_audit_request_is_immutable() -> None:
    control = make_control()

    request = AuditRequest(
        control=control,
        host="production-01",
    )

    try:
        request.host = "production-02"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("AuditRequest must be immutable.")