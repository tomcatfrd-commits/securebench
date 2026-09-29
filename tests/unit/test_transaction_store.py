from __future__ import annotations

from pathlib import Path

import pytest

from securebench.core import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionError,
    TransactionStore,
)


def make_transaction() -> Transaction:
    transaction = Transaction(
        transaction_id="tx-cis-001",
        profile_id="production-safe",
        benchmark_id="cis-ubuntu-24.04",
        benchmark_version="2.0.0",
        host="server01",
    )
    transaction.add_change(
        ChangeRecord(
            change_id="change-001",
            control_id="CIS-1.1.1.1",
            host="server01",
            benchmark_id="cis-ubuntu-24.04",
            benchmark_version="2.0.0",
            control_digest="a" * 64,
            status=ChangeStatus.SUCCESS,
            before={"loaded": False},
            rollback_data={"state_path": "/var/lib/securebench/tx-cis-001"},
        )
    )
    return transaction


def test_transaction_store_round_trips_rollback_identity(tmp_path: Path) -> None:
    store = TransactionStore(tmp_path)
    transaction = make_transaction()
    transaction.mark_committed()

    store.save(transaction)
    restored = store.load(transaction.transaction_id)

    assert restored.benchmark_version == "2.0.0"
    assert restored.status == transaction.status
    assert restored.changes[0].control_digest == "a" * 64
    assert restored.changes[0].rollback_data == transaction.changes[0].rollback_data


def test_transaction_store_rejects_path_traversal(tmp_path: Path) -> None:
    store = TransactionStore(tmp_path)

    with pytest.raises(TransactionError, match="unsafe"):
        store.load("../outside")


def test_transaction_store_lists_saved_transactions(tmp_path: Path) -> None:
    store = TransactionStore(tmp_path)
    store.save(make_transaction())

    assert store.list_ids() == ("tx-cis-001",)
