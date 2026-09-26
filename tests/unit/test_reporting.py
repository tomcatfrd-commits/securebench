from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from securebench.core.transaction import (
    ChangeRecord,
    ChangeStatus,
    Transaction,
    TransactionStatus,
)
from securebench.reporting.csv import CsvReporter
from securebench.reporting.html import HtmlReporter
from securebench.reporting.json import JsonReporter


def make_audit_result(
    control_id: str = "TEST-1",
    host: str = "server01",
    status: ComplianceStatus = ComplianceStatus.PASS,
) -> AuditResult:
    return AuditResult(
        control_id=control_id,
        host=host,
        status=status,
        evidence=(),
        message="Audit completed.",
    )


def make_execution_result(
    control_id: str = "TEST-1",
    host: str = "server01",
    status: ExecutionStatus = ExecutionStatus.SUCCESS,
) -> ExecutionResult:
    return ExecutionResult(
        control_id=control_id,
        host=host,
        status=status,
        changed=status is ExecutionStatus.SUCCESS,
        message="Execution completed.",
    )


def make_verification_result(
    control_id: str = "TEST-1",
    host: str = "server01",
    status: ComplianceStatus = ComplianceStatus.PASS,
) -> VerificationResult:
    return VerificationResult(
        control_id=control_id,
        host=host,
        status=status,
        evidence=(),
        message="Verification completed.",
    )


def make_transaction() -> Transaction:
    transaction = Transaction(transaction_id="tx-001")

    transaction.add_change(
        ChangeRecord(
            change_id="change-001",
            control_id="TEST-1",
            host="server01",
            status=ChangeStatus.SUCCESS,
            before=None,
            after=None,
            rollback_data=None,
        )
    )

    transaction.mark_committed()

    return transaction


def test_json_reporter_returns_valid_json() -> None:
    reporter = JsonReporter()

    output = reporter.render_audit(
        [make_audit_result()]
    )

    parsed = json.loads(output)

    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["control_id"] == "TEST-1"
    assert parsed[0]["host"] == "server01"
    assert parsed[0]["status"] == ComplianceStatus.PASS.value


def test_json_reporter_serializes_multiple_report_types() -> None:
    reporter = JsonReporter()

    output = reporter.render(
        audits=[make_audit_result()],
        executions=[make_execution_result()],
        verifications=[make_verification_result()],
        transaction=make_transaction(),
    )

    parsed = json.loads(output)

    assert set(parsed) == {
        "audits",
        "executions",
        "verifications",
        "transaction",
    }

    assert len(parsed["audits"]) == 1
    assert len(parsed["executions"]) == 1
    assert len(parsed["verifications"]) == 1
    assert parsed["transaction"]["transaction_id"] == "tx-001"


def test_json_reporter_preserves_failure_statuses() -> None:
    reporter = JsonReporter()

    output = reporter.render(
        audits=[
            make_audit_result(
                status=ComplianceStatus.FAIL
            )
        ],
        executions=[
            make_execution_result(
                status=ExecutionStatus.FAILED
            )
        ],
        verifications=[
            make_verification_result(
                status=ComplianceStatus.FAIL
            )
        ],
    )

    parsed = json.loads(output)

    assert parsed["audits"][0]["status"] == ComplianceStatus.FAIL.value
    assert parsed["executions"][0]["status"] == ExecutionStatus.FAILED.value
    assert (
        parsed["verifications"][0]["status"]
        == ComplianceStatus.FAIL.value
    )


def test_json_reporter_can_write_to_file(tmp_path: Path) -> None:
    reporter = JsonReporter()
    output_path = tmp_path / "report.json"

    reporter.write_audit(
        [make_audit_result()],
        output_path,
    )

    assert output_path.exists()

    parsed = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert parsed[0]["control_id"] == "TEST-1"


def test_csv_reporter_returns_valid_csv() -> None:
    reporter = CsvReporter()

    output = reporter.render_audit(
        [make_audit_result()]
    )

    rows = list(csv.DictReader(StringIO(output)))

    assert len(rows) == 1
    assert rows[0]["control_id"] == "TEST-1"
    assert rows[0]["host"] == "server01"
    assert rows[0]["status"] == ComplianceStatus.PASS.value


def test_csv_reporter_serializes_multiple_audit_results() -> None:
    reporter = CsvReporter()

    results = [
        make_audit_result("TEST-1", "server01"),
        make_audit_result("TEST-2", "server02"),
        make_audit_result(
            "TEST-3",
            "server03",
            ComplianceStatus.FAIL,
        ),
    ]

    output = reporter.render_audit(results)
    rows = list(csv.DictReader(StringIO(output)))

    assert len(rows) == 3

    assert [row["control_id"] for row in rows] == [
        "TEST-1",
        "TEST-2",
        "TEST-3",
    ]

    assert rows[2]["status"] == ComplianceStatus.FAIL.value


def test_csv_reporter_writes_to_file(tmp_path: Path) -> None:
    reporter = CsvReporter()
    output_path = tmp_path / "report.csv"

    reporter.write_audit(
        [make_audit_result()],
        output_path,
    )

    assert output_path.exists()

    rows = list(
        csv.DictReader(
            output_path.read_text(encoding="utf-8").splitlines()
        )
    )

    assert len(rows) == 1
    assert rows[0]["control_id"] == "TEST-1"


def test_csv_reporter_renders_execution_results() -> None:
    reporter = CsvReporter()

    output = reporter.render_execution(
        [
            make_execution_result(),
            make_execution_result(
                "TEST-2",
                "server02",
                ExecutionStatus.FAILED,
            ),
        ]
    )

    rows = list(csv.DictReader(StringIO(output)))

    assert len(rows) == 2
    assert rows[0]["control_id"] == "TEST-1"
    assert rows[0]["status"] == ExecutionStatus.SUCCESS.value
    assert rows[1]["status"] == ExecutionStatus.FAILED.value


def test_csv_reporter_renders_verification_results() -> None:
    reporter = CsvReporter()

    output = reporter.render_verification(
        [
            make_verification_result(),
            make_verification_result(
                "TEST-2",
                "server02",
                ComplianceStatus.FAIL,
            ),
        ]
    )

    rows = list(csv.DictReader(StringIO(output)))

    assert len(rows) == 2
    assert rows[0]["control_id"] == "TEST-1"
    assert rows[0]["status"] == ComplianceStatus.PASS.value
    assert rows[1]["status"] == ComplianceStatus.FAIL.value


def test_html_reporter_returns_standalone_document() -> None:
    reporter = HtmlReporter()

    output = reporter.render_audit(
        [make_audit_result()]
    )

    assert "<!DOCTYPE html>" in output
    assert "<html" in output
    assert "</html>" in output
    assert "TEST-1" in output
    assert "server01" in output


def test_html_reporter_contains_audit_status() -> None:
    reporter = HtmlReporter()

    output = reporter.render_audit(
        [
            make_audit_result(
                status=ComplianceStatus.FAIL
            )
        ]
    )

    assert ComplianceStatus.FAIL.value in output
    assert "TEST-1" in output


def test_html_reporter_escapes_control_data() -> None:
    reporter = HtmlReporter()

    result = AuditResult(
        control_id="<script>alert(1)</script>",
        host="server01",
        status=ComplianceStatus.FAIL,
        evidence=(),
        message="<img src=x onerror=alert(1)>",
    )

    output = reporter.render_audit([result])

    assert "<script>alert(1)</script>" not in output
    assert "<img src=x onerror=alert(1)>" not in output
    assert "&lt;script&gt;" in output


def test_html_reporter_renders_execution_results() -> None:
    reporter = HtmlReporter()

    output = reporter.render_execution(
        [make_execution_result()]
    )

    assert "<!DOCTYPE html>" in output
    assert "TEST-1" in output
    assert ExecutionStatus.SUCCESS.value in output


def test_html_reporter_renders_verification_results() -> None:
    reporter = HtmlReporter()

    output = reporter.render_verification(
        [make_verification_result()]
    )

    assert "<!DOCTYPE html>" in output
    assert "TEST-1" in output
    assert ComplianceStatus.PASS.value in output


def test_html_reporter_can_write_to_file(tmp_path: Path) -> None:
    reporter = HtmlReporter()
    output_path = tmp_path / "report.html"

    reporter.write_audit(
        [make_audit_result()],
        output_path,
    )

    assert output_path.exists()

    content = output_path.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in content
    assert "TEST-1" in content


def test_empty_audit_report_is_valid_json() -> None:
    reporter = JsonReporter()

    output = reporter.render_audit([])

    assert json.loads(output) == []


def test_empty_audit_report_is_valid_csv() -> None:
    reporter = CsvReporter()

    output = reporter.render_audit([])

    assert isinstance(output, str)


def test_empty_audit_report_is_valid_html() -> None:
    reporter = HtmlReporter()

    output = reporter.render_audit([])

    assert "<!DOCTYPE html>" in output
    assert "</html>" in output


def test_transaction_status_is_serialized() -> None:
    reporter = JsonReporter()

    output = reporter.render(
        transaction=make_transaction()
    )

    parsed = json.loads(output)

    assert (
        parsed["transaction"]["status"]
        == TransactionStatus.COMMITTED.value
    )


def test_transaction_change_status_is_serialized() -> None:
    reporter = JsonReporter()

    output = reporter.render(
        transaction=make_transaction()
    )

    parsed = json.loads(output)

    assert (
        parsed["transaction"]["changes"][0]["status"]
        == ChangeStatus.SUCCESS.value
    )