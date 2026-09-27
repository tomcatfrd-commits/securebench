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
    Profile,
    RollbackCapability,
    SafetyClassification,
)
from securebench.policy.classifier import ControlClassifier


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

    @property
    def allowed(self) -> bool:
        """
        Return True when the rule does not hard-deny the control.

        REQUIRE_PRECHECK and REQUIRE_APPROVAL still allow the control into
        the planning workflow; only DENY blocks it.
        """

        return self.decision is not PolicyDecision.DENY


@dataclass(frozen=True, slots=True)
class RollbackPolicyRule:
    """
    Prevent remediation when the control's rollback capability conflicts
    with the selected policy.

    Production-safe profiles normally reject best-effort or unsupported
    rollback unless explicitly configured otherwise.
    """

    allow_best_effort: bool = False

    def evaluate(
        self,
        control: Control,
        profile: Profile | None = None,
    ) -> RuleResult:
        allow_best_effort = self.allow_best_effort
        if profile is not None:
            allow_best_effort = bool(
                getattr(profile, "allow_best_effort_rollback", allow_best_effort)
            )

        if control.rollback_capability is RollbackCapability.GUARANTEED:
            return RuleResult(
                rule_name="rollback-capability",
                decision=PolicyDecision.ALLOW,
                reason="Control has guaranteed rollback capability.",
            )

        if control.rollback_capability is RollbackCapability.BEST_EFFORT:
            if allow_best_effort:
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
        control_or_classification: Control | SafetyClassification,
        profile: Profile | None = None,
    ) -> RuleResult:
        """
        Evaluate classification policy.

        Accepts either:
          - (classification,) – legacy / internal
          - (control, profile) – unit-test / public API
        """
        if isinstance(control_or_classification, SafetyClassification):
            classification = control_or_classification
        else:
            if profile is None:
                raise TypeError(
                    "profile is required when evaluate() is called with a Control"
                )
            classification = ControlClassifier().classify(
                control_or_classification,
                profile,
            ).classification

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