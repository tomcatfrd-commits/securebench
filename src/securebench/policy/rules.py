"""
Reusable policy rules.

A classifier answers what a profile says about a control.

These rules answer whether additional conditions allow that control to
proceed toward remediation.

Rules are deliberately small and composable so the policy engine can later
combine them without embedding all safety logic in one large conditional.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from securebench.core import (
    Control,
    RollbackCapability,
    SafetyClassification,
)


class PolicyDecision(StrEnum):
    """Possible outcomes of evaluating a policy rule."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_PRECHECK = "require_precheck"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class RuleResult:
    """Result returned by one policy rule."""

    rule_name: str
    decision: PolicyDecision
    reason: str


@dataclass(frozen=True, slots=True)
class RollbackPolicyRule:
    """
    Prevent remediation when the control's rollback capability conflicts
    with the selected policy.

    Production-safe profiles normally reject best-effort or unsupported
    rollback unless explicitly configured otherwise.
    """

    allow_best_effort: bool = False

    def evaluate(self, control: Control) -> RuleResult:
        if control.rollback_capability is RollbackCapability.GUARANTEED:
            return RuleResult(
                rule_name="rollback-capability",
                decision=PolicyDecision.ALLOW,
                reason="Control has guaranteed rollback capability.",
            )

        if control.rollback_capability is RollbackCapability.BEST_EFFORT:
            if self.allow_best_effort:
                return RuleResult(
                    rule_name="rollback-capability",
                    decision=PolicyDecision.ALLOW,
                    reason=(
                        "Control has best-effort rollback capability and "
                        "the selected policy permits it."
                    ),
                )

            return RuleResult(
                rule_name="rollback-capability",
                decision=PolicyDecision.DENY,
                reason=(
                    "Control has best-effort rollback capability, but the "
                    "selected policy does not permit it."
                ),
            )

        return RuleResult(
            rule_name="rollback-capability",
            decision=PolicyDecision.DENY,
            reason=(
                "Control does not provide rollback capability and the "
                "policy requires rollback support."
            ),
        )


@dataclass(frozen=True, slots=True)
class ClassificationPolicyRule:
    """
    Enforce the safety classification produced by a Profile.
    """

    def evaluate(
        self,
        classification: SafetyClassification,
    ) -> RuleResult:
        if classification is SafetyClassification.SAFE:
            return RuleResult(
                rule_name="safety-classification",
                decision=PolicyDecision.ALLOW,
                reason="Control is classified as safe.",
            )

        if classification is SafetyClassification.SAFE_WITH_PRECHECK:
            return RuleResult(
                rule_name="safety-classification",
                decision=PolicyDecision.REQUIRE_PRECHECK,
                reason=(
                    "Control is allowed only after required host-specific "
                    "prechecks succeed."
                ),
            )

        if classification is SafetyClassification.APPROVAL_REQUIRED:
            return RuleResult(
                rule_name="safety-classification",
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="Control requires explicit approval.",
            )

        return RuleResult(
            rule_name="safety-classification",
            decision=PolicyDecision.DENY,
            reason=(
                f"Control classification '{classification.value}' does not "
                "permit automatic remediation."
            ),
        )