"""
SecureBench policy engine.

The policy engine is the safety gate between benchmark findings and
remediation planning.

It combines:

    Control
        +
    Profile classification
        +
    Policy rules
        =
    Remediation decision

It does not execute Ansible and does not modify target systems.
"""

from __future__ import annotations

from dataclasses import dataclass

from securebench.core import Control, Profile
from .classifier import ClassificationResult, ControlClassifier
from .rules import (
    ClassificationPolicyRule,
    PolicyDecision,
    RollbackPolicyRule,
    RuleResult,
)


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """
    Complete policy evaluation for one control.

    ``control`` is the exact immutable Control object that was evaluated.
    Keeping it here allows downstream planning stages to preserve the
    domain object rather than attempting to reconstruct a Control from
    its identifier.

    ``allowed`` means the control passed the policy gate sufficiently to
    continue through the planning workflow.

    It does NOT mean that remediation may immediately execute.

    For example:
        REQUIRE_PRECHECK -> allowed to continue, but precheck is mandatory
        REQUIRE_APPROVAL -> allowed into the approval workflow, but not
                            executable without approval
        DENY               -> blocked
    """

    control: Control
    control_id: str
    classification: ClassificationResult
    rule_results: tuple[RuleResult, ...]
    decision: PolicyDecision
    allowed: bool
    reason: str

    @property
    def requires_precheck(self) -> bool:
        """Return whether host-specific prechecks are mandatory."""

        return self.decision is PolicyDecision.REQUIRE_PRECHECK

    @property
    def requires_approval(self) -> bool:
        """Return whether explicit approval is mandatory."""

        return self.decision is PolicyDecision.REQUIRE_APPROVAL

    @property
    def can_execute_without_approval(self) -> bool:
        """
        Return whether the policy permits immediate execution.

        A precheck requirement is an execution gate, not permission to
        execute immediately. Therefore only an explicit ALLOW decision
        can execute without approval or an additional policy gate.
        """

        return self.decision is PolicyDecision.ALLOW


class PolicyEngine:
    """
    Evaluate whether a control may enter remediation planning.

    The engine is deliberately deterministic. Given the same control,
    profile, and policy configuration, it should produce the same decision.

    Policy rules are injected so the engine remains composable and
    testable. Profile-specific rollback permission is applied when the
    rollback rule is evaluated.
    """

    def __init__(
        self,
        *,
        classifier: ControlClassifier | None = None,
        classification_rule: ClassificationPolicyRule | None = None,
        rollback_rule: RollbackPolicyRule | None = None,
    ) -> None:
        self._classifier = classifier or ControlClassifier()
        self._classification_rule = (
            classification_rule or ClassificationPolicyRule()
        )
        self._rollback_rule = rollback_rule or RollbackPolicyRule()

    def evaluate(
        self,
        control: Control,
        profile: Profile,
    ) -> PolicyEvaluation:
        """
        Evaluate one control against one profile.

        No remote calls, Ansible execution, or system modifications occur.
        """

        classification = self._classifier.classify(
            control=control,
            profile=profile,
        )

        classification_result = self._classification_rule.evaluate(
            classification.classification
        )

        rollback_rule = RollbackPolicyRule(
            allow_best_effort=(
                self._rollback_rule.allow_best_effort
                or profile.allow_best_effort_rollback
            ),
        )

        rollback_result = rollback_rule.evaluate(control)

        rule_results = (
            classification_result,
            rollback_result,
        )

        decision = self._combine_decisions(
            classification_result,
            rollback_result,
        )

        return PolicyEvaluation(
            control=control,
            control_id=control.control_id,
            classification=classification,
            rule_results=rule_results,
            decision=decision,
            allowed=decision
            in {
                PolicyDecision.ALLOW,
                PolicyDecision.REQUIRE_PRECHECK,
                PolicyDecision.REQUIRE_APPROVAL,
            },
            reason=self._build_reason(
                decision,
                rule_results,
            ),
        )

    @staticmethod
    def _combine_decisions(
        classification_result: RuleResult,
        rollback_result: RuleResult,
    ) -> PolicyDecision:
        """
        Combine rule results using fail-closed precedence.

        Precedence:

            DENY
              |
              v
            REQUIRE_APPROVAL
              |
              v
            REQUIRE_PRECHECK
              |
              v
            ALLOW

        A stronger safety restriction always wins.
        """

        decisions = {
            classification_result.decision,
            rollback_result.decision,
        }

        if PolicyDecision.DENY in decisions:
            return PolicyDecision.DENY

        if PolicyDecision.REQUIRE_APPROVAL in decisions:
            return PolicyDecision.REQUIRE_APPROVAL

        if PolicyDecision.REQUIRE_PRECHECK in decisions:
            return PolicyDecision.REQUIRE_PRECHECK

        return PolicyDecision.ALLOW

    @staticmethod
    def _build_reason(
        decision: PolicyDecision,
        rule_results: tuple[RuleResult, ...],
    ) -> str:
        """
        Produce a deterministic human-readable explanation.
        """

        if decision is PolicyDecision.ALLOW:
            return "All applicable policy rules permit remediation."

        relevant = [
            result.reason
            for result in rule_results
            if result.decision is decision
        ]

        if relevant:
            return " ".join(relevant)

        return f"Policy decision is '{decision.value}'."