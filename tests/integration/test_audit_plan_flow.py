from __future__ import annotations

from pathlib import Path

from securebench.audit.engine import AuditEngine, AuditRequest
from securebench.audit.evidence import EvidenceStore
from securebench.core.loader import ConfigurationLoader
from securebench.core.result import AuditResult, ComplianceStatus, Evidence
from securebench.policy.engine import PolicyEngine
from securebench.remediation.planner import PlanAction, RemediationPlanner


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
    def audit(
        self,
        control,
        host: str,
    ) -> AuditResult:
        if control.control_id == "CIS-1.1.1.1":
            status = ComplianceStatus.FAIL
            observed = {
                "module_loaded": True,
                "module_loadable": True,
            }
            expected = {
                "module_loaded": False,
                "module_loadable": False,
            }
        else:
            status = ComplianceStatus.UNKNOWN
            observed = None
            expected = None

        evidence = Evidence(
            control_id=control.control_id,
            host=host,
            source="fake-audit-provider",
            observed=observed,
            expected=expected,
        )

        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=status,
            evidence=(evidence,),
        )


def test_audit_to_plan_flow_loads_real_configuration() -> None:
    loader = ConfigurationLoader()

    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    evidence_store = EvidenceStore()
    audit_engine = AuditEngine(
        provider=FakeAuditProvider(),
        evidence_store=evidence_store,
    )

    audit_result = audit_engine.audit(
        AuditRequest(
            control=control,
            host="ubuntu-production-01",
        )
    )

    assert audit_result.status is ComplianceStatus.FAIL
    assert audit_result.compliant is False

    policy_engine = PolicyEngine()
    planner = RemediationPlanner(policy_engine)

    plan = planner.create_plan(
        controls=[control],
        audit_results=[audit_result],
        profile=profile,
    )

    assert len(plan.items) == 1

    item = plan.items[0]

    assert item.control_id == control.control_id
    assert item.host == "ubuntu-production-01"
    assert item.action is PlanAction.PRECHECK
    assert item.audit_result.status is ComplianceStatus.FAIL
    assert item.policy_evaluation.requires_precheck is True
    assert item.policy_evaluation.allowed is True


def test_compliant_control_is_not_added_to_remediation_workflow() -> None:
    loader = ConfigurationLoader()

    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    class CompliantProvider:
        def audit(self, control, host: str) -> AuditResult:
            evidence = Evidence(
                control_id=control.control_id,
                host=host,
                source="compliant-provider",
                observed={
                    "module_loaded": False,
                    "module_loadable": False,
                },
                expected={
                    "module_loaded": False,
                    "module_loadable": False,
                },
            )

            return AuditResult(
                control_id=control.control_id,
                host=host,
                status=ComplianceStatus.PASS,
                evidence=(evidence,),
            )

    audit_engine = AuditEngine(
        provider=CompliantProvider(),
        evidence_store=EvidenceStore(),
    )

    audit_result = audit_engine.audit(
        AuditRequest(
            control=control,
            host="ubuntu-production-01",
        )
    )

    planner = RemediationPlanner(PolicyEngine())

    plan = planner.create_plan(
        controls=[control],
        audit_results=[audit_result],
        profile=profile,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action is PlanAction.SKIP
    assert plan.items[0].audit_result.compliant is True


def test_unknown_audit_result_fails_closed_into_investigation() -> None:
    loader = ConfigurationLoader()

    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    profile = loader.load_profile(PROFILE_PATH)

    control = benchmark.get_control("CIS-1.1.1.1")

    class UnknownProvider:
        def audit(self, control, host: str) -> AuditResult:
            return AuditResult(
                control_id=control.control_id,
                host=host,
                status=ComplianceStatus.UNKNOWN,
            )

    audit_engine = AuditEngine(
        provider=UnknownProvider(),
        evidence_store=EvidenceStore(),
    )

    audit_result = audit_engine.audit(
        AuditRequest(
            control=control,
            host="ubuntu-production-01",
        )
    )

    planner = RemediationPlanner(PolicyEngine())

    plan = planner.create_plan(
        controls=[control],
        audit_results=[audit_result],
        profile=profile,
    )

    assert len(plan.items) == 1
    assert plan.items[0].action is PlanAction.INVESTIGATE


def test_audit_evidence_is_available_before_planning() -> None:
    loader = ConfigurationLoader()

    benchmark = loader.load_benchmark(BENCHMARK_PATH)
    control = benchmark.get_control("CIS-1.1.1.1")

    evidence_store = EvidenceStore()
    audit_engine = AuditEngine(
        provider=FakeAuditProvider(),
        evidence_store=evidence_store,
    )

    audit_engine.audit(
        AuditRequest(
            control=control,
            host="ubuntu-production-01",
        )
    )

    evidence = evidence_store.for_control(
        control.control_id,
        host="ubuntu-production-01",
    )

    assert len(evidence) == 1
    assert evidence[0].control_id == control.control_id
    assert evidence[0].host == "ubuntu-production-01"
    assert evidence[0].source == "fake-audit-provider"