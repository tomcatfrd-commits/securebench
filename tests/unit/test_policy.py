from __future__ import annotations

from securebench.core import (
    Control,
    ControlSeverity,
    Profile,
    ProfileRule,
    RollbackCapability,
    SafetyClassification,
)
from securebench.policy import (
    ClassificationPolicyRule,
    ControlClassifier,
    PolicyDecision,
    PolicyEngine,
    RollbackPolicyRule,
)


def make_control(
    *,
    control_id: str = "TEST-001",
    classification: SafetyClassification = SafetyClassification.SAFE,
    rollback_capability: RollbackCapability = RollbackCapability.GUARANTEED,
) -> Control:
    return Control(
        control_id=control_id,
        benchmark_id="test-benchmark",
        title="Test control",
        description="Test description",
        platform="ubuntu-24.04",
        severity=ControlSeverity.MEDIUM,
        audit="test.audit",
        remediation="test.remediate",
        rollback="test.rollback",
        verification="test.verify",
        rollback_capability=rollback_capability,
        metadata={
            "safety": {
                "default_classification": classification.value,
            }
        },
    )


def make_profile(
    *,
    classification: SafetyClassification = SafetyClassification.SAFE,
    enabled: bool = True,
    require_approval: bool = False,
    allow_best_effort_rollback: bool = False,
) -> Profile:
    return Profile(
        profile_id="test-profile",
        name="Test Profile",
        description="Test profile",
        default_classification=SafetyClassification.INVESTIGATE,
        rules={
            "TEST-001": ProfileRule(
                classification=classification,
                enabled=enabled,
                require_approval=require_approval,
            )
        },
        allow_best_effort_rollback=allow_best_effort_rollback,
    )


class TestControlClassifier:
    def test_safe_control_is_automatically_remediable(self) -> None:
        control = make_control()
        profile = make_profile(
            classification=SafetyClassification.SAFE,
        )

        result = ControlClassifier().classify(control, profile)

        assert result.control_id == "TEST-001"
        assert result.classification is SafetyClassification.SAFE
        assert result.requires_precheck is False
        assert result.requires_approval is False
        assert result.automatically_remediable is True

    def test_safe_with_precheck_requires_precheck(self) -> None:
        control = make_control()
        profile = make_profile(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
        )

        result = ControlClassifier().classify(control, profile)

        assert result.classification is SafetyClassification.SAFE_WITH_PRECHECK
        assert result.requires_precheck is True
        assert result.requires_approval is False
        assert result.automatically_remediable is True

    def test_investigate_is_not_automatically_remediable(self) -> None:
        control = make_control()
        profile = make_profile(
            classification=SafetyClassification.INVESTIGATE,
        )

        result = ControlClassifier().classify(control, profile)

        assert result.classification is SafetyClassification.INVESTIGATE
        assert result.requires_precheck is False
        assert result.requires_approval is False
        assert result.automatically_remediable is False

    def test_approval_required_is_not_automatically_remediable(self) -> None:
        control = make_control()
        profile = make_profile(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            require_approval=True,
        )

        result = ControlClassifier().classify(control, profile)

        assert result.classification is SafetyClassification.APPROVAL_REQUIRED
        assert result.requires_approval is True
        assert result.automatically_remediable is False

    def test_prohibited_is_not_automatically_remediable(self) -> None:
        control = make_control()
        profile = make_profile(
            classification=SafetyClassification.PROHIBITED,
            enabled=False,
        )

        result = ControlClassifier().classify(control, profile)

        assert result.classification is SafetyClassification.PROHIBITED
        assert result.requires_approval is False
        assert result.automatically_remediable is False

    def test_disabled_safe_control_is_not_automatically_remediable(self) -> None:
        control = make_control()
        profile = make_profile(
            classification=SafetyClassification.SAFE,
            enabled=False,
        )

        result = ControlClassifier().classify(control, profile)

        assert result.classification is SafetyClassification.SAFE
        assert result.automatically_remediable is False
        assert "disabled" in result.reason.lower()


class TestClassificationPolicyRule:
    def test_safe_allows_remediation(self) -> None:
        result = ClassificationPolicyRule().evaluate(
            make_control(),
            make_profile(
                classification=SafetyClassification.SAFE,
            ),
        )

        assert result.decision is PolicyDecision.ALLOW
        assert result.allowed is True
        assert result.requires_precheck is False
        assert result.requires_approval is False

    def test_safe_with_precheck_requires_precheck(self) -> None:
        result = ClassificationPolicyRule().evaluate(
            make_control(),
            make_profile(
                classification=SafetyClassification.SAFE_WITH_PRECHECK,
            ),
        )

        assert result.decision is PolicyDecision.REQUIRE_PRECHECK
        assert result.allowed is True
        assert result.requires_precheck is True
        assert result.requires_approval is False

    def test_approval_required_requires_approval(self) -> None:
        result = ClassificationPolicyRule().evaluate(
            make_control(),
            make_profile(
                classification=SafetyClassification.APPROVAL_REQUIRED,
                require_approval=True,
            ),
        )

        assert result.decision is PolicyDecision.REQUIRE_APPROVAL
        assert result.allowed is True
        assert result.requires_approval is True

    def test_investigate_denies(self) -> None:
        result = ClassificationPolicyRule().evaluate(
            make_control(),
            make_profile(
                classification=SafetyClassification.INVESTIGATE,
            ),
        )

        assert result.decision is PolicyDecision.DENY
        assert result.allowed is False

    def test_prohibited_denies(self) -> None:
        result = ClassificationPolicyRule().evaluate(
            make_control(),
            make_profile(
                classification=SafetyClassification.PROHIBITED,
                enabled=False,
            ),
        )

        assert result.decision is PolicyDecision.DENY
        assert result.allowed is False


class TestRollbackPolicyRule:
    def test_guaranteed_rollback_is_always_allowed(self) -> None:
        rule = RollbackPolicyRule()

        result = rule.evaluate(
            make_control(
                rollback_capability=RollbackCapability.GUARANTEED,
            ),
            make_profile(),
        )

        assert result.decision is PolicyDecision.ALLOW
        assert result.allowed is True

    def test_best_effort_rollback_is_denied_by_default(self) -> None:
        rule = RollbackPolicyRule()

        result = rule.evaluate(
            make_control(
                rollback_capability=RollbackCapability.BEST_EFFORT,
            ),
            make_profile(
                allow_best_effort_rollback=False,
            ),
        )

        assert result.decision is PolicyDecision.DENY
        assert result.allowed is False

    def test_best_effort_rollback_can_be_allowed_by_profile(self) -> None:
        rule = RollbackPolicyRule()

        result = rule.evaluate(
            make_control(
                rollback_capability=RollbackCapability.BEST_EFFORT,
            ),
            make_profile(
                allow_best_effort_rollback=True,
            ),
        )

        assert result.decision is PolicyDecision.ALLOW
        assert result.allowed is True

    def test_unsupported_rollback_is_always_denied(self) -> None:
        rule = RollbackPolicyRule()

        result = rule.evaluate(
            make_control(
                rollback_capability=RollbackCapability.UNSUPPORTED,
            ),
            make_profile(
                allow_best_effort_rollback=True,
            ),
        )

        assert result.decision is PolicyDecision.DENY
        assert result.allowed is False


class TestPolicyEngine:
    def test_safe_guaranteed_control_is_allowed(self) -> None:
        control = make_control(
            classification=SafetyClassification.SAFE,
            rollback_capability=RollbackCapability.GUARANTEED,
        )
        profile = make_profile(
            classification=SafetyClassification.SAFE,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.control_id == "TEST-001"
        assert evaluation.decision is PolicyDecision.ALLOW
        assert evaluation.allowed is True
        assert evaluation.requires_precheck is False
        assert evaluation.requires_approval is False
        assert evaluation.can_execute_without_approval is True

    def test_safe_with_precheck_requires_precheck(self) -> None:
        control = make_control(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
        )
        profile = make_profile(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.REQUIRE_PRECHECK
        assert evaluation.allowed is True
        assert evaluation.requires_precheck is True
        assert evaluation.requires_approval is False
        assert evaluation.can_execute_without_approval is True

    def test_approval_required_blocks_execution_without_approval(self) -> None:
        control = make_control(
            classification=SafetyClassification.APPROVAL_REQUIRED,
        )
        profile = make_profile(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            require_approval=True,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.REQUIRE_APPROVAL
        assert evaluation.allowed is True
        assert evaluation.requires_approval is True
        assert evaluation.can_execute_without_approval is False

    def test_investigate_is_denied(self) -> None:
        control = make_control(
            classification=SafetyClassification.INVESTIGATE,
        )
        profile = make_profile(
            classification=SafetyClassification.INVESTIGATE,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.DENY
        assert evaluation.allowed is False
        assert evaluation.can_execute_without_approval is False

    def test_prohibited_is_denied(self) -> None:
        control = make_control(
            classification=SafetyClassification.PROHIBITED,
        )
        profile = make_profile(
            classification=SafetyClassification.PROHIBITED,
            enabled=False,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.DENY
        assert evaluation.allowed is False

    def test_deny_takes_precedence_over_precheck(self) -> None:
        control = make_control(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
            rollback_capability=RollbackCapability.UNSUPPORTED,
        )
        profile = make_profile(
            classification=SafetyClassification.SAFE_WITH_PRECHECK,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.DENY
        assert evaluation.allowed is False

    def test_deny_takes_precedence_over_approval(self) -> None:
        control = make_control(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            rollback_capability=RollbackCapability.UNSUPPORTED,
        )
        profile = make_profile(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            require_approval=True,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.DENY
        assert evaluation.allowed is False

    def test_approval_takes_precedence_over_precheck(self) -> None:
        control = make_control(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            rollback_capability=RollbackCapability.GUARANTEED,
        )
        profile = make_profile(
            classification=SafetyClassification.APPROVAL_REQUIRED,
            require_approval=True,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.REQUIRE_APPROVAL
        assert evaluation.allowed is True
        assert evaluation.requires_approval is True

    def test_best_effort_rollback_can_turn_safe_control_into_denial(
        self,
    ) -> None:
        control = make_control(
            classification=SafetyClassification.SAFE,
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        profile = make_profile(
            classification=SafetyClassification.SAFE,
            allow_best_effort_rollback=False,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.DENY
        assert evaluation.allowed is False

    def test_best_effort_rollback_can_be_enabled_by_profile(
        self,
    ) -> None:
        control = make_control(
            classification=SafetyClassification.SAFE,
            rollback_capability=RollbackCapability.BEST_EFFORT,
        )
        profile = make_profile(
            classification=SafetyClassification.SAFE,
            allow_best_effort_rollback=True,
        )

        evaluation = PolicyEngine().evaluate(control, profile)

        assert evaluation.decision is PolicyDecision.ALLOW
        assert evaluation.allowed is True
        assert evaluation.can_execute_without_approval is True

    def test_policy_evaluation_contains_rule_results(self) -> None:
        control = make_control()
        profile = make_profile()

        evaluation = PolicyEngine().evaluate(control, profile)

        assert len(evaluation.rule_results) == 2
        assert all(result.rule_name for result in evaluation.rule_results)
        assert all(result.reason for result in evaluation.rule_results)