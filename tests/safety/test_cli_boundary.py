from __future__ import annotations

from securebench.cli.main import build_parser


def test_cli_exposes_expected_top_level_commands() -> None:
    parser = build_parser()

    help_text = parser.format_help()

    for command in (
        "inventory",
        "benchmark",
        "profile",
        "audit",
        "plan",
        "apply",
        "verify",
        "rollback",
    ):
        assert command in help_text


def test_audit_requires_benchmark_profile_and_inventory() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "audit",
            "--benchmark",
            "benchmark.yml",
            "--profile",
            "production-safe.yml",
            "--inventory",
            "inventory.ini",
        ]
    )

    assert args.command == "audit"
    assert args.benchmark == "benchmark.yml"
    assert args.profile == "production-safe.yml"
    assert args.inventory == "inventory.ini"


def test_plan_requires_benchmark_profile_and_inventory() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "plan",
            "--benchmark",
            "benchmark.yml",
            "--profile",
            "production-safe.yml",
            "--inventory",
            "inventory.ini",
        ]
    )

    assert args.command == "plan"
    assert args.benchmark == "benchmark.yml"
    assert args.profile == "production-safe.yml"
    assert args.inventory == "inventory.ini"


def test_apply_requires_plan() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "apply",
            "--plan",
            "plan.json",
        ]
    )

    assert args.command == "apply"
    assert args.plan == "plan.json"


def test_verify_requires_transaction() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "verify",
            "--transaction",
            "transaction.json",
        ]
    )

    assert args.command == "verify"
    assert args.transaction == "transaction.json"


def test_rollback_accepts_transaction() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "rollback",
            "--transaction",
            "transaction.json",
        ]
    )

    assert args.command == "rollback"
    assert args.transaction == "transaction.json"


def test_rollback_accepts_control_and_host() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "rollback",
            "--control",
            "CIS-1.1.1.1",
            "--host",
            "production-01",
        ]
    )

    assert args.command == "rollback"
    assert args.control == "CIS-1.1.1.1"
    assert args.host == "production-01"


def test_cli_defaults_do_not_enable_remediation_flags() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "audit",
            "--benchmark",
            "benchmark.yml",
            "--profile",
            "production-safe.yml",
            "--inventory",
            "inventory.ini",
        ]
    )

    namespace = vars(args)

    assert namespace.get("apply", False) is False
    assert namespace.get("remediate", False) is False
    assert namespace.get("force", False) is False


def test_cli_does_not_accept_unknown_arguments() -> None:
    parser = build_parser()

    try:
        parser.parse_args(
            [
                "audit",
                "--benchmark",
                "benchmark.yml",
                "--profile",
                "production-safe.yml",
                "--inventory",
                "inventory.ini",
                "--force-remediate",
            ]
        )
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError(
            "CLI accepted an unknown remediation-related argument."
        )