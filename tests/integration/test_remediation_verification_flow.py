from __future__ import annotations

from pathlib import Path

from securebench.audit.engine import AuditEngine, AuditRequest
from securebench.audit.evidence import EvidenceStore
from securebench.core.loader import ConfigurationLoader
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    Evidence,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from securebench.core.transaction import Transaction
from securebench.policy.engine import PolicyEngine
from securebench.remediation.engine import RemediationEngine
from securebench.remediation.planner import RemediationPlanner
from securebench.verification.engine import VerificationEngine, VerificationRequest


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


class FakeAuditProvider:
    def audit(self, control, host: str) -> AuditResult:
        evidence = Evidence(
            control_id=control.control_id,
            host=host,
            source="fake-audit",
            observed={
                "module_loaded": True,
                "module_loadable": True,
            },
            expected={
                "module_loaded": False,
                "module_loadable": False,
            },
        )

        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.FAIL,
            evidence=(evidence,),
        )


class FakeRemediationProvider:
    def __init__(self) -> None:
        self.precheck_calls: list[tuple[str, str]] = []
        self.remediation_calls: list[tuple[str, str]] = []

    def precheck(self, control, host: str) -> ExecutionResult:
        self.precheck_calls.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=False,
            message="Precheck passed.",
        )

    def remediate(self, control, host: str) -> ExecutionResult:
        self.remediation_calls.append((control.control_id, host))

        return ExecutionResult(
            control_id=control.control_id,
            host=host,
            status=ExecutionStatus.SUCCESS,
            changed=True,
            message="Remediation completed.",
        )


class FakeVerificationProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def verify(self, control, host: str) -> VerificationResult:
        self.calls.append((control.control_id, host))

        evidence = Evidence(
            control_id=control.control_id,
            host=host,
            source="fake-verification",
            observed={
                "module_loaded": False,
                "module_loadable": False,
            },
            expected={
                "module_loaded": False,
                "module_loadable": False,
            },
        )

        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=ComplianceStatus.PASS,
            evidence=(evidence,),
        )


def _load_production_control():
    loader = ConfigurationLoader()

    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)
    control = benchmark.get_control("CIS-1.1.1.1")

    return control, profile


def test_failed_audit_flows_through_precheck_remediation_and_verification() -> None:
    control, profile = _load_production_control()
    host = "ubuntu-production-01"

    audit_engine = AuditEngine(
        provider=FakeAuditProvider(),
        evidence_store=EvidenceStore(),
    )

    audit_result = audit_engine.audit(
        AuditRequest(
            control=control,
            host=host,
        )
    )

    planner = RemediationPlanner(PolicyEngine())

    plan = planner.create_plan(
        controls=[control],
        audit_results=[audit_result],
        profile=profile,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action.value == "precheck"

    remediation_provider = FakeRemediationProvider()
    remediation_engine = RemediationEngine(remediation_provider)

    transaction = Transaction(
        transaction_id="txn-integration-001",
        host=host,
    )

    remediation_result = remediation_engine.execute(
        plan=plan,
        transaction=transaction,
    )

    assert remediation_result
    assert remediation_provider.precheck_calls == [
        (control.control_id, host)
    ]
    assert remediation_provider.remediation_calls == [
        (control.control_id, host)
    ]

    verification_provider = FakeVerificationProvider()
    verification_engine = VerificationEngine(verification_provider)

    verification_result = verification_engine.verify(
        VerificationRequest(
            control=control,
            host=host,
        )
    )

    assert verification_result.status is ComplianceStatus.PASS
    assert verification_result.verified is True
    assert verification_provider.calls == [
        (control.control_id, host)
    ]


def test_verification_is_independent_of_remediation_provider() -> None:
    control, _ = _load_production_control()
    host = "ubuntu-production-01"

    remediation_provider = FakeRemediationProvider()
    remediation_engine = RemediationEngine(remediation_provider)

    verification_provider = FakeVerificationProvider()
    verification_engine = VerificationEngine(verification_provider)

    assert remediation_engine is not verification_engine
    assert remediation_provider is not verification_provider

    result = verification_engine.verify(
        VerificationRequest(
            control=control,
            host=host,
        )
    )

    assert result.status is ComplianceStatus.PASS
    assert verification_provider.calls == [
        (control.control_id, host)
    ]
    assert remediation_provider.precheck_calls == []
    assert remediation_provider.remediation_calls == []


def test_failed_verification_does_not_report_compliance() -> None:
    control, _ = _load_production_control()
    host = "ubuntu-production-01"

    class FailedVerificationProvider:
        def verify(self, control, host: str) -> VerificationResult:
            evidence = Evidence(
                control_id=control.control_id,
                host=host,
                source="failed-verification",
                observed={"module_loaded": True},
                expected={"module_loaded": False},
            )

            return VerificationResult(
                control_id=control.control_id,
                host=host,
                status=ComplianceStatus.FAIL,
                evidence=(evidence,),
            )

    engine = VerificationEngine(FailedVerificationProvider())

    result = engine.verify(
        VerificationRequest(
            control=control,
            host=host,
        )
    )

    assert result.status is ComplianceStatus.FAIL
    assert result.verified is False


def test_verification_unknown_result_fails_closed() -> None:
    control, _ = _load_production_control()
    host = "ubuntu-production-01"

    class UnknownVerificationProvider:
        def verify(self, control, host: str) -> VerificationResult:
            return VerificationResult(
                control_id=control.control_id,
                host=host,
                status=ComplianceStatus.UNKNOWN,
            )

    engine = VerificationEngine(UnknownVerificationProvider())

    result = engine.verify(
        VerificationRequest(
            control=control,
            host=host,
        )
    )

    assert result.status is ComplianceStatus.UNKNOWN
    assert result.verified is False