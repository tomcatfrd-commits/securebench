"""
Remediation profile domain model.

A Profile defines what SecureBench is permitted to do with benchmark controls.

The benchmark answers:

    "What should the system look like?"

The profile answers:

    "What are we willing to do about it?"

This separation is fundamental to production-safe automation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .control import SafetyClassification


@dataclass(frozen=True, slots=True)
class ProfileRule:
    """
    Policy assigned to an individual control.

    A rule may override the default classification for a particular control.
    """

    classification: SafetyClassification
    enabled: bool = True
    require_approval: bool = False

    def __post_init__(self) -> None:
        if (
            self.classification is SafetyClassification.APPROVAL_REQUIRED
            and not self.require_approval
        ):
            raise ValueError(
                "approval_required controls must have require_approval=True"
            )

        if self.classification is SafetyClassification.PROHIBITED:
            if self.enabled:
                raise ValueError(
                    "prohibited controls cannot be enabled for remediation"
                )

            if self.require_approval:
                raise ValueError(
                    "prohibited controls cannot require approval because "
                    "they cannot be remediated"
                )

        if (
            self.classification
            in {
                SafetyClassification.INVESTIGATE,
                SafetyClassification.PROHIBITED,
            }
            and self.enabled
        ):
            raise ValueError(
                f"{self.classification.value} controls cannot be enabled "
                "for remediation"
            )


@dataclass(frozen=True, slots=True)
class Profile:
    """
    Immutable remediation policy.

    Parameters
    ----------
    profile_id:
        Stable identifier such as ``production-safe``.

    name:
        Human-readable profile name.

    description:
        Explanation of the profile's intended use.

    default_classification:
        Classification applied when a control has no explicit rule.

    rules:
        Per-control policy overrides.

    allow_best_effort_rollback:
        Whether the profile permits remediation of controls whose rollback
        capability is only ``best_effort``.

    require_approval_for_unknown:
        Whether controls without an explicit safe policy should require
        approval rather than being automatically remediated.
    """

    profile_id: str
    name: str
    description: str

    default_classification: SafetyClassification = (
        SafetyClassification.INVESTIGATE
    )

    rules: Mapping[str, ProfileRule] = field(
        default_factory=dict,
    )

    allow_best_effort_rollback: bool = False
    require_approval_for_unknown: bool = True

    def __post_init__(self) -> None:
        """Validate and freeze profile policy data."""

        if not self.profile_id.strip():
            raise ValueError("profile_id must not be empty")

        if not self.name.strip():
            raise ValueError("name must not be empty")

        if not self.description.strip():
            raise ValueError("description must not be empty")

        if not isinstance(
            self.default_classification,
            SafetyClassification,
        ):
            raise ValueError(
                "default_classification must be a SafetyClassification"
            )

        if not isinstance(
            self.allow_best_effort_rollback,
            bool,
        ):
            raise ValueError(
                "allow_best_effort_rollback must be boolean"
            )

        if not isinstance(
            self.require_approval_for_unknown,
            bool,
        ):
            raise ValueError(
                "require_approval_for_unknown must be boolean"
            )

        normalized_rules: dict[str, ProfileRule] = {}

        for control_id, rule in self.rules.items():
            if not isinstance(control_id, str) or not control_id.strip():
                raise ValueError(
                    "profile rule control IDs must be non-empty strings"
                )

            if not isinstance(rule, ProfileRule):
                raise ValueError(
                    f"profile rule for '{control_id}' must be a ProfileRule"
                )

            normalized_rules[control_id] = rule

        object.__setattr__(
            self,
            "rules",
            MappingProxyType(normalized_rules),
        )

    def rule_for(self, control_id: str) -> ProfileRule:
        """
        Return the effective rule for a control.

        Explicit control rules take precedence over profile defaults.

        When the profile is configured to require approval for unknown
        controls, an unlisted control becomes approval-required and disabled.
        """

        if not control_id.strip():
            raise ValueError("control_id must not be empty")

        rule = self.rules.get(control_id)

        if rule is not None:
            return rule

        classification = self.default_classification

        if (
            classification is SafetyClassification.INVESTIGATE
            and self.require_approval_for_unknown
        ):
            return ProfileRule(
                classification=SafetyClassification.APPROVAL_REQUIRED,
                enabled=False,
                require_approval=True,
            )

        if classification is SafetyClassification.PROHIBITED:
            return ProfileRule(
                classification=SafetyClassification.PROHIBITED,
                enabled=False,
                require_approval=False,
            )

        if classification is SafetyClassification.INVESTIGATE:
            return ProfileRule(
                classification=SafetyClassification.INVESTIGATE,
                enabled=False,
                require_approval=False,
            )

        return ProfileRule(
            classification=classification,
            enabled=True,
            require_approval=(
                classification
                is SafetyClassification.APPROVAL_REQUIRED
            ),
        )

    def allows_automatic_remediation(
        self,
        control_id: str,
    ) -> bool:
        """
        Return whether a control is eligible for automatic remediation.

        This method only evaluates profile policy.

        It does not perform host-specific safety checks, dependency checks,
        conflict checks, or rollback checks. Those belong to the policy
        engine.
        """

        rule = self.rule_for(control_id)

        return (
            rule.enabled
            and not rule.require_approval
            and rule.classification
            in {
                SafetyClassification.SAFE,
                SafetyClassification.SAFE_WITH_PRECHECK,
            }
        )