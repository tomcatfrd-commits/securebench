from __future__ import annotations

from collections.abc import Mapping

import pytest

from securebench.core.transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)


def make_transaction(
    transaction_id: str = "tx-001",
) -> Transaction:
    return Transaction(
        transaction_id=transaction_id,
        profile_id="test-profile",
        benchmark_id="test-benchmark",
        host="production-01",
    )


def make_change(
    change_id: str = "change-001",
    *,
    status: ChangeStatus = ChangeStatus.PENDING,
) -> ChangeRecord:
    return ChangeRecord(
        change_id=change_id,
        control_id="TEST-1",
        host="production-01",
        status=status,
        before={"value": "old"},
        after={"value": "new"},
        details={"source": "test"},
        rollback_data={"value": "old"},
        message="Test change.",
    )


def test_new_transaction_starts_pending() -> None:
    transaction = make_transaction()

    assert transaction.status is TransactionStatus.PENDING
    assert transaction.change_count == 0
    assert transaction.changes == ()


def test_transaction_id_is_required() -> None:
    with pytest.raises(ValueError):
        Transaction(
            transaction_id="",
            profile_id="test-profile",
            benchmark_id="test-benchmark",
            host="production-01",
        )


def test_transaction_id_cannot_be_whitespace() -> None:
    with pytest.raises(ValueError):
        Transaction(
            transaction_id="   ",
            profile_id="test-profile",
            benchmark_id="test-benchmark",
            host="production-01",
        )


def test_change_ids_must_be_unique() -> None:
    transaction = make_transaction()

    transaction.add_change(make_change("change-001"))

    with pytest.raises(ValueError):
        transaction.add_change(make_change("change-001"))


def test_transaction_rejects_non_change_record() -> None:
    transaction = make_transaction()

    with pytest.raises(TypeError):
        transaction.add_change(object())  # type: ignore[arg-type]


def test_changes_are_exposed_as_immutable_tuple() -> None:
    transaction = make_transaction()
    transaction.add_change(make_change())

    changes = transaction.changes

    assert isinstance(changes, tuple)
    assert len(changes) == 1


def test_returned_change_collection_cannot_modify_transaction() -> None:
    transaction = make_transaction()
    transaction.add_change(make_change())

    changes = transaction.changes

    with pytest.raises(AttributeError):
        changes.append(make_change("change-002"))  # type: ignore[attr-defined]

    assert transaction.change_count == 1


def test_get_change_returns_requested_change() -> None:
    transaction = make_transaction()
    expected = make_change("change-001")

    transaction.add_change(expected)

    actual = transaction.get_change("change-001")

    assert actual is expected


def test_get_missing_change_raises_key_error() -> None:
    transaction = make_transaction()

    with pytest.raises(KeyError, match="missing"):
        transaction.get_change("missing")


def test_successful_change_is_reported() -> None:
    transaction = make_transaction()

    transaction.add_change(
        make_change(
            status=ChangeStatus.SUCCESS,
        )
    )

    assert transaction.successful_changes == (transaction.changes[0],)
    assert transaction.failed_changes == ()


def test_failed_change_is_reported() -> None:
    transaction = make_transaction()

    transaction.add_change(
        make_change(
            status=ChangeStatus.FAILED,
        )
    )

    assert transaction.failed_changes == (transaction.changes[0],)
    assert transaction.successful_changes == ()


def test_transaction_cannot_commit_with_failed_changes() -> None:
    transaction = make_transaction()

    transaction.add_change(
        make_change(
            status=ChangeStatus.FAILED,
        )
    )

    with pytest.raises(ValueError):
        transaction.mark_committed()

    assert transaction.status is TransactionStatus.PENDING


def test_transaction_can_commit_after_successful_changes() -> None:
    transaction = make_transaction()

    transaction.add_change(
        make_change(
            status=ChangeStatus.SUCCESS,
        )
    )

    transaction.mark_committed()

    assert transaction.status is TransactionStatus.COMMITTED


def test_empty_transaction_can_commit() -> None:
    transaction = make_transaction()

    transaction.mark_committed()

    assert transaction.status is TransactionStatus.COMMITTED


def test_rollback_required_state_is_explicit() -> None:
    transaction = make_transaction()

    transaction.mark_rollback_required()

    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_rollback_required_can_be_set_after_successful_change() -> None:
    transaction = make_transaction()

    transaction.add_change(
        make_change(
            status=ChangeStatus.SUCCESS,
        )
    )

    transaction.mark_rollback_required()

    assert transaction.status is TransactionStatus.ROLLBACK_REQUIRED


def test_transaction_can_be_marked_rolled_back() -> None:
    transaction = make_transaction()

    transaction.add_change(
        make_change(
            status=ChangeStatus.SUCCESS,
        )
    )

    transaction.mark_rollback_required()
    transaction.mark_rolled_back()

    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_rolled_back_transaction_cannot_be_committed() -> None:
    transaction = make_transaction()

    transaction.mark_rollback_required()
    transaction.mark_rolled_back()

    with pytest.raises(ValueError):
        transaction.mark_committed()

    assert transaction.status is TransactionStatus.ROLLED_BACK


def test_transaction_status_cannot_be_changed_by_mutating_returned_change() -> None:
    transaction = make_transaction()

    change = make_change(
        status=ChangeStatus.SUCCESS,
    )
    transaction.add_change(change)

    transaction.mark_committed()

    change.status = ChangeStatus.ROLLED_BACK

    assert transaction.status is TransactionStatus.COMMITTED


def test_change_record_rejects_empty_change_id() -> None:
    with pytest.raises(ValueError):
        ChangeRecord(
            change_id="",
            control_id="TEST-1",
            host="production-01",
        )


def test_change_record_rejects_empty_control_id() -> None:
    with pytest.raises(ValueError):
        ChangeRecord(
            change_id="change-001",
            control_id="",
            host="production-01",
        )


def test_change_record_rejects_empty_host() -> None:
    with pytest.raises(ValueError):
        ChangeRecord(
            change_id="change-001",
            control_id="TEST-1",
            host="",
        )


def test_change_record_rejects_invalid_status() -> None:
    with pytest.raises(TypeError):
        ChangeRecord(
            change_id="change-001",
            control_id="TEST-1",
            host="production-01",
            status="success",  # type: ignore[arg-type]
        )


def test_change_record_preserves_mapping_data() -> None:
    before: Mapping[str, object] = {"mode": "0644"}
    after: Mapping[str, object] = {"mode": "0600"}
    rollback_data: Mapping[str, object] = {"mode": "0644"}

    change = ChangeRecord(
        change_id="change-001",
        control_id="TEST-1",
        host="production-01",
        before=before,
        after=after,
        rollback_data=rollback_data,
    )

    assert change.before == before
    assert change.after == after
    assert change.rollback_data == rollback_data
