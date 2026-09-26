from __future__ import annotations

from securebench.core.benchmark import Benchmark
from securebench.core.control import (
    Control,
    ControlSeverity,
    RollbackCapability,
)
from securebench.core.control_graph import ControlGraph
from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
)
from securebench.core.exceptions import PlanningError
from securebench.policy.engine import (
    PolicyEvaluation,
    PolicyEngine,
)
from securebench.policy.rules import (
    ClassificationPolicyRule,
    RollbackPolicyRule,
)
from securebench.core.profile import Profile, ProfileRule
from securebench.remediation.planner import (
    RemediationPlanner,
    PlanAction,
)


def make_control(
    control_id: str,
    *,
    dependencies: tuple[str, ...] = (),
    conflicts: tuple[str, ...] = (),
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title=f"Control {control_id}",
        description="Test control.",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit=f"audit.{control_id}",
        remediation=f"remediation.{control_id}",
        rollback=f"rollback.{control_id}",
        verification=f"verification.{control_id}",
        rollback_capability=RollbackCapability.GUARANTEED,
        dependencies=dependencies,
        conflicts=conflicts,
    )


def make_benchmark(*controls: Control) -> Benchmark:
    return Benchmark(
        benchmark_id="test-benchmark",
        name="Test Benchmark",
        version="1.0.0",
        platform="ubuntu-24.04",
        description="Test benchmark.",
        controls=controls,
    )


def make_audit(control: Control) -> AuditResult:
    return AuditResult(
        control_id=control.control_id,
        host="production-01",
        status=ComplianceStatus.FAIL,
    )


def make_policy_evaluation(
    control: Control,
) -> PolicyEvaluation:
    profile = Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile.",
        rules={
            control.control_id: ProfileRule(
                classification=control_metadata_classification(control),
                enabled=True,
            )
        },
    )

    policy_engine = PolicyEngine(
        classification_rule=ClassificationPolicyRule(),
        rollback_rule=RollbackPolicyRule(),
    )

    return policy_engine.evaluate(
        control=control,
        profile=profile,
    )


def control_metadata_classification(control: Control):
    from securebench.core.control import SafetyClassification

    return SafetyClassification.SAFE


def test_planner_rejects_conflicting_requested_controls() -> None:
    control_a = make_control(
        "A",
        conflicts=("B",),
    )
    control_b = make_control("B")

    benchmark = make_benchmark(
        control_a,
        control_b,
    )

    graph = ControlGraph.from_benchmark(benchmark)

    planner = RemediationPlanner(
        policy_engine=PolicyEngine(
            classification_rule=ClassificationPolicyRule(),
            rollback_rule=RollbackPolicyRule(),
        ),
        graph=graph,
    )

    audits = (
        make_audit(control_a),
        make_audit(control_b),
    )

    evaluations = (
        make_policy_evaluation(control_a),
        make_policy_evaluation(control_b),
    )

    try:
        planner.plan(audits, evaluations)
    except PlanningError as exc:
        assert "Conflicting controls" in str(exc)
    else:
        raise AssertionError(
            "Planner allowed conflicting controls into remediation."
        )


def test_planner_includes_dependencies_before_requested_control() -> None:
    dependency = make_control("A")
    requested = make_control(
        "B",
        dependencies=("A",),
    )

    benchmark = make_benchmark(
        dependency,
        requested,
    )

    graph = ControlGraph.from_benchmark(benchmark)

    planner = RemediationPlanner(
        policy_engine=PolicyEngine(
            classification_rule=ClassificationPolicyRule(),
            rollback_rule=RollbackPolicyRule(),
        ),
        graph=graph,
    )

    audits = (
        make_audit(requested),
    )

    evaluations = (
        make_policy_evaluation(requested),
    )

    plan = planner.plan(
        audits,
        evaluations,
    )

    assert [
        item.control.control_id
        for item in plan.items
    ] == [
        "A",
        "B",
    ]


def test_planner_does_not_execute_remediation() -> None:
    control = make_control("A")

    benchmark = make_benchmark(control)

    graph = ControlGraph.from_benchmark(benchmark)

    planner = RemediationPlanner(
        policy_engine=PolicyEngine(
            classification_rule=ClassificationPolicyRule(),
            rollback_rule=RollbackPolicyRule(),
        ),
        graph=graph,
    )

    plan = planner.plan(
        (make_audit(control),),
        (make_policy_evaluation(control),),
    )

    assert len(plan.items) == 1
    assert plan.items[0].action in {
        PlanAction.REMEDIATE,
        PlanAction.PRECHECK,
        PlanAction.APPROVAL_REQUIRED,
        PlanAction.INVESTIGATE,
    }


def test_planner_empty_audit_set_has_no_actions() -> None:
    planner = RemediationPlanner(
        policy_engine=PolicyEngine(
            classification_rule=ClassificationPolicyRule(),
            rollback_rule=RollbackPolicyRule(),
        ),
    )

    plan = planner.plan(
        (),
        (),
    )

    assert plan.items == ()