"""
SecureBench command-line entry point.

The CLI is intentionally thin.

It should translate user intent into calls to the SecureBench application
layers rather than contain benchmark, policy, remediation, or rollback logic.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from securebench import __version__


def build_parser() -> argparse.ArgumentParser:
    """
    Build the top-level SecureBench argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="securebench",
        description=(
            "Security benchmark auditing, remediation, verification, "
            "and rollback platform."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    _add_inventory_parser(subparsers)
    _add_benchmark_parser(subparsers)
    _add_profile_parser(subparsers)
    _add_audit_parser(subparsers)
    _add_plan_parser(subparsers)
    _add_apply_parser(subparsers)
    _add_verify_parser(subparsers)
    _add_rollback_parser(subparsers)

    return parser


def _add_inventory_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the inventory command."""

    parser = subparsers.add_parser(
        "inventory",
        help="Manage or inspect target inventory.",
    )

    parser.add_argument(
        "action",
        choices=("list",),
        help="Inventory operation.",
    )


def _add_benchmark_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the benchmark command."""

    parser = subparsers.add_parser(
        "benchmark",
        help="Inspect available security benchmarks.",
    )

    parser.add_argument(
        "action",
        choices=("list",),
        help="Benchmark operation.",
    )


def _add_profile_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the profile command."""

    parser = subparsers.add_parser(
        "profile",
        help="Inspect remediation profiles.",
    )

    parser.add_argument(
        "action",
        choices=("list",),
        help="Profile operation.",
    )


def _add_audit_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the audit command."""

    parser = subparsers.add_parser(
        "audit",
        help="Audit target systems without modifying them.",
    )

    _add_benchmark_and_profile_arguments(parser)


def _add_plan_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the plan command."""

    parser = subparsers.add_parser(
        "plan",
        help="Generate a remediation plan without applying changes.",
    )

    _add_benchmark_and_profile_arguments(parser)


def _add_apply_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the apply command."""

    parser = subparsers.add_parser(
        "apply",
        help="Apply an approved remediation plan.",
    )

    parser.add_argument(
        "--plan",
        required=True,
        help="Path to the remediation plan to execute.",
    )


def _add_verify_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the verify command."""

    parser = subparsers.add_parser(
        "verify",
        help="Independently verify remediation results.",
    )

    parser.add_argument(
        "--transaction",
        required=True,
        help="Transaction ID or transaction record to verify.",
    )


def _add_rollback_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the rollback command."""

    parser = subparsers.add_parser(
        "rollback",
        help="Roll back a remediation transaction or selected control.",
    )

    rollback_group = parser.add_mutually_exclusive_group(required=True)

    rollback_group.add_argument(
        "--transaction",
        help="Transaction ID to roll back.",
    )

    rollback_group.add_argument(
        "--control",
        help="Control ID to roll back.",
    )

    parser.add_argument(
        "--host",
        help="Target host when rolling back a single control.",
    )


def _add_benchmark_and_profile_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """
    Add common benchmark/profile arguments.

    Keeping these arguments consistent across commands makes the CLI easier
    to automate and reduces command-specific conventions.
    """

    parser.add_argument(
        "--benchmark",
        required=True,
        help="Benchmark identifier.",
    )

    parser.add_argument(
        "--profile",
        required=True,
        help="Remediation profile identifier.",
    )

    parser.add_argument(
        "--inventory",
        help="Path to the target inventory.",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """
    CLI entry point.

    Command implementations will be connected as the corresponding
    application services are added.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "inventory":
        return _not_implemented("inventory")

    if args.command == "benchmark":
        return _not_implemented("benchmark")

    if args.command == "profile":
        return _not_implemented("profile")

    if args.command == "audit":
        return _not_implemented("audit")

    if args.command == "plan":
        return _not_implemented("plan")

    if args.command == "apply":
        return _not_implemented("apply")

    if args.command == "verify":
        return _not_implemented("verify")

    if args.command == "rollback":
        return _not_implemented("rollback")

    parser.error("unknown command")
    return 2


def _not_implemented(command: str) -> int:
    """
    Temporarily report commands whose application services are not wired yet.

    Returning a non-zero status is important so shell scripts and CI systems
    do not interpret an unfinished command as successful.
    """

    print(
        f"securebench: command '{command}' is not implemented yet.",
        file=sys.stderr,
    )

    return 2


if __name__ == "__main__":
    raise SystemExit(main())