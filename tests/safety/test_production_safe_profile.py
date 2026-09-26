from __future__ import annotations

from pathlib import Path

from securebench.core.control import SafetyClassification
from securebench.core.loader import ConfigurationLoader
from securebench.core.profile import Profile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = PROJECT_ROOT / "profiles" / "production-safe.yml"


def test_production_safe_profile_loads_as_expected() -> None:
    loader = ConfigurationLoader()

    profile = loader.load_profile(PROFILE_PATH)

    assert isinstance(profile, Profile)
    assert profile.profile_id == "production-safe"
    assert profile.name == "Production Safe"
    assert profile.default_classification is SafetyClassification.INVESTIGATE
    assert profile.require_approval_for_unknown is True
    assert profile.allow_best_effort_rollback is False


def test_cramfs_is_explicitly_safe_with_precheck() -> None:
    loader = ConfigurationLoader()
    profile = loader.load_profile(PROFILE_PATH)

    rule = profile.rule_for("CIS-1.1.1.1")

    assert rule.classification is SafetyClassification.SAFE_WITH_PRECHECK
    assert rule.enabled is True
    assert rule.require_approval is False
    assert profile.allows_automatic_remediation("CIS-1.1.1.1") is True


def test_unknown_control_does_not_become_automatically_remediable() -> None:
    loader = ConfigurationLoader()
    profile = loader.load_profile(PROFILE_PATH)

    rule = profile.rule_for("CIS-DOES-NOT-EXIST")

    assert rule.classification is SafetyClassification.APPROVAL_REQUIRED
    assert rule.enabled is False
    assert rule.require_approval is True
    assert profile.allows_automatic_remediation("CIS-DOES-NOT-EXIST") is False


def test_production_safe_profile_has_no_best_effort_rollback_permission() -> None:
    loader = ConfigurationLoader()
    profile = loader.load_profile(PROFILE_PATH)

    assert profile.allow_best_effort_rollback is False


def test_only_explicit_safe_controls_are_automatic() -> None:
    loader = ConfigurationLoader()
    profile = loader.load_profile(PROFILE_PATH)

    assert profile.allows_automatic_remediation("CIS-1.1.1.1") is True
    assert profile.allows_automatic_remediation("CIS-UNKNOWN") is False