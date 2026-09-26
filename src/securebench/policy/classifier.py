"""
Policy classification logic.

This module converts a control + profile into a remediation classification.

It deliberately does not execute anything.

The classifier answers:

    "According to this profile, how should this control be treated?"

The policy engine will later combine this result with runtime facts,
prechecks, dependencies, conflicts, and other safety conditions.
"""

from __future__ import annotations

from dataclasses import dataclass

from securebench.core import (
    Control,
    Profile,
    ProfileRule,
    SafetyClassification,
)


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """
    Result of classifying one control under one profile.

    ``allowed`` means the profile permits the control to enter the
    remediation workflow. It does not mean that remediation is currently
    safe on a particular host.
    """

    control_id: str
    classification: SafetyClassification
    enabled: bool
    requires_precheck: bool
    requires_approval: bool
    reason: str

    @property
    def automatically_remediable(self) -> bool:
        """
        Return whether the profile permits automatic remediation before
        host-specific safety checks are considered.
        """

        return (
            self.enabled
            and not self.requires_approval
            and self.classification
            in {
                SafetyClassification.SAFE,
                SafetyClassification.SAFE_WITH_PRECHECK,
            }
        )


class ControlClassifier:
    """
    Classifies controls according to a remediation profile.

    This class contains no Ansible or operating-system-specific logic.
    """

    def classify(
        self,
        control: Control,
        profile: Profile,
    ) -> ClassificationResult:
        """
        Classify a control according to a profile.

        Parameters
        ----------
        control:
            Benchmark control being evaluated.

        profile:
            Remediation policy selected by the operator.

        Returns
        -------
        ClassificationResult
            Policy classification and the resulting high-level action.

        Raises
        ------
        ValueError
            If the control does not belong to a benchmark represented by
            the profile context. The current Profile intentionally does
            not contain a benchmark ID, so this method only validates
            the control identity and profile rule.
        """

        rule = profile.rule_for(control.control_id)

        return self._build_result(control, rule)

    @staticmethod
    def _build_result(
        control: Control,
        rule: ProfileRule,
    ) -> ClassificationResult:
        """
        Convert a ProfileRule into an explicit classification result.
        """

        classification = rule.classification

        if classification is SafetyClassification.SAFE:
            return ClassificationResult(
                control_id=control.control_id,
                classification=classification,
                enabled=rule.enabled,
                requires_precheck=False,
                requires_approval=rule.require_approval,
                reason="Control is classified as safe by the selected profile.",
            )

        if classification is SafetyClassification.SAFE_WITH_PRECHECK:
            return ClassificationResult(
                control_id=control.control_id,
                classification=classification,
                enabled=rule.enabled,
                requires_precheck=True,
                requires_approval=rule.require_approval,
                reason=(
                    "Control is permitted by the selected profile, but "
                    "host-specific prechecks are required before remediation."
                ),
            )

        if classification is SafetyClassification.INVESTIGATE:
            return ClassificationResult(
                control_id=control.control_id,
                classification=classification,
                enabled=False,
                requires_precheck=False,
                requires_approval=False,
                reason=(
                    "Control requires investigation before SecureBench "
                    "may consider remediation."
                ),
            )

        if classification is SafetyClassification.APPROVAL_REQUIRED:
            return ClassificationResult(
                control_id=control.control_id,
                classification=classification,
                enabled=False,
                requires_precheck=False,
                requires_approval=True,
                reason=(
                    "Control requires explicit approval before remediation."
                ),
            )

        if classification is SafetyClassification.PROHIBITED:
            return ClassificationResult(
                control_id=control.control_id,
                classification=classification,
                enabled=False,
                requires_precheck=False,
                requires_approval=False,
                reason=(
                    "Control is prohibited by the selected profile and "
                    "must not be automatically remediated."
                ),
            )

        # This should be unreachable because SafetyClassification is a StrEnum.
        raise ValueError(
            f"unsupported safety classification: {classification!r}"
        )