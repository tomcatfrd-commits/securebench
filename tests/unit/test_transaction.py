from __future__ import annotations

import pytest

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)


def make_transaction() -> Transaction:
    return Transaction(
        transaction_id="txn-001",
        profile_id="production-safe",
        benchmark_id="cis-ubuntu-24.04",
    )


def make_change(
    *,
    change_id: str = "change-001",
    control_id: str = "CIS-1.1.1.1",
    host: str = "server01",
    status: ChangeStatus = ChangeStatus.SUCCESS,
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id=control_id,
        host=host,
        status=status,
    )


class TestTransaction:
    def test_transaction_starts_pending(self) -> None:
        transaction = make_transaction()

        assert transaction.status is TransactionStatus.PENDING
        assert transaction.change_count == 0

    def test_transaction_has_required_identity(self) -> None:
        transaction = make_transaction()

        assert transaction.transaction_id == "txn-001"
        assert transaction.profile_id == "production-safe"
        assert transaction.benchmark_id == "cis-ubuntu-24.04"

    def test_add_change(self) -> None:
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        assert transaction.change_count == 1
        assert transaction.get_change("change-001") is change

    def test_add_multiple_changes(self) -> None:
        transaction = make_transaction()

        transaction.add_change(
            make_change(
                change_id="change-001",
                control_id="CIS-1.1.1.1",
            )
        )
        transaction.add_change(
            make_change(
                change_id="change-002",
                control_id="CIS-1.1.1.2",
            )
        )

        assert transaction.change_count == 2
        assert transaction.get_change("change-001").control_id == "CIS-1.1.1.1"
        assert transaction.get_change("change-002").control_id == "CIS-1.1.1.2"

    def test_duplicate_change_id_is_rejected(self) -> None:
        transaction = make_transaction()

        transaction.add_change(
            make_change(change_id="change-001")
        )

        with pytest.raises(ValueError, match="duplicate"):
            transaction.add_change(
                make_change(
                    change_id="change-001",
                    control_id="CIS-OTHER",
                )
            )

    def test_unknown_change_lookup_raises_key_error(self) -> None:
        transaction = make_transaction()

        with pytest.raises(KeyError):
            transaction.get_change("missing-change")

    def test_failed_changes_returns_only_failed_changes(self) -> None:
        transaction = make_transaction()

        successful = make_change(
            change_id="change-success",
            status=ChangeStatus.SUCCESS,
        )
        failed = make_change(
            change_id="change-failed",
            status=ChangeStatus.FAILED,
        )
        rollback_required = make_change(
            change_id="change-rollback",
            status=ChangeStatus.ROLLBACK_REQUIRED,
        )

        transaction.add_change(successful)
        transaction.add_change(failed)
        transaction.add_change(rollback_required)

        failed_changes = transaction.failed_changes

        assert failed_changes == (failed,)

    def test_successful_changes_returns_only_successful_changes(self) -> None:
        transaction = make_transaction()

        successful = make_change(
            change_id="change-success",
            status=ChangeStatus.SUCCESS,
        )
        failed = make_change(
            change_id="change-failed",
            status=ChangeStatus.FAILED,
        )
        rolled_back = make_change(
            change_id="change-rolled-back",
            status=ChangeStatus.ROLLED_BACK,
        )

        transaction.add_change(successful)
        transaction.add_change(failed)
        transaction.add_change(rolled_back)

        successful_changes = transaction.successful_changes

        assert successful_changes == (successful,)

    def test_mark_rollback_required(self) -> None:
        transaction = make_transaction()

        transaction.add_change(make_change())

        transaction.mark_rollback_required()

        assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED

    def test_mark_committed(self) -> None:
        transaction = make_transaction()

        transaction.add_change(make_change())

        transaction.mark_committed()

        assert transaction.status is TransactionStatus.COMMITTED

    def test_mark_rolled_back(self) -> None:
        transaction = make_transaction()

        transaction.add_change(
            make_change(status=ChangeStatus.ROLLED_BACK)
        )

        transaction.mark_rolled_back()

        assert transaction.status is TransactionStatus.ROLLED_BACK

    def test_change_status_is_independent_from_transaction_status(self) -> None:
        transaction = make_transaction()
        change = make_change()

        transaction.add_change(change)

        assert transaction.status is TransactionStatus.PENDING
        assert change.status is ChangeStatus.SUCCESS

        transaction.mark_rollback_required()

        assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED
        assert change.status is ChangeStatus.SUCCESS

    def test_changes_preserve_insertion_order(self) -> None:
        transaction = make_transaction()

        first = make_change(change_id="change-001")
        second = make_change(change_id="change-002")
        third = make_change(change_id="change-003")

        transaction.add_change(first)
        transaction.add_change(second)
        transaction.add_change(third)

        assert transaction.changes == (
            first,
            second,
            third,
        )

    def test_transaction_changes_are_read_only_view(self) -> None:
        transaction = make_transaction()

        change = make_change()
        transaction.add_change(change)

        changes = transaction.changes

        assert isinstance(changes, tuple)

    def test_empty_transaction_has_no_failed_changes(self) -> None:
        transaction = make_transaction()

        assert transaction.failed_changes == ()
        assert transaction.successful_changes == ()

    def test_empty_transaction_can_be_created(self) -> None:
        transaction = make_transaction()

        assert transaction.change_count == 0
        assert transaction.changes == ()

    def test_transaction_identity_fields_cannot_be_empty(self) -> None:
        with pytest.raises(ValueError):
            Transaction(
                transaction_id="",
                profile_id="production-safe",
                benchmark_id="cis-ubuntu-24.04",
            )

        with pytest.raises(ValueError):
            Transaction(
                transaction_id="txn-001",
                profile_id="",
                benchmark_id="cis-ubuntu-24.04",
            )

        with pytest.raises(ValueError):
            Transaction(
                transaction_id="txn-001",
                profile_id="production-safe",
                benchmark_id="",
            )

    def test_transaction_is_mutable_for_lifecycle_management(self) -> None:
        transaction = make_transaction()

        transaction.mark_rollback_required()

        assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED

        transaction.mark_rolled_back()

        assert transaction.status is TransactionStatus.ROLLED_BACK