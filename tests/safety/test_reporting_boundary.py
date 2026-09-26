from __future__ import annotations

import json

from securebench.core.result import (
    AuditResult,
    ComplianceStatus,
    Evidence,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from securebench.reporting.csv import CsvReporter
from securebench.reporting.html import HtmlReporter
from securebench.reporting.json import JsonReporter


def make_evidence() -> Evidence:
    return Evidence(
        control_id="TEST-1",
        host="production-01",
        source="test-audit",
        observed={"value": "actual"},
        expected={"value": "expected"},
    )


def make_audit_result() -> AuditResult:
    return AuditResult(
        control_id="TEST-1",
        host="production-01",
        status=ComplianceStatus.FAIL,
        evidence=(make_evidence(),),
    )


def make_execution_result() -> ExecutionResult:
    return ExecutionResult(
        control_id="TEST-1",
        host="production-01",
        status=ExecutionStatus.SUCCESS,
        changed=True,
        message="Remediation completed.",
    )


def make_verification_result() -> VerificationResult:
    return VerificationResult(
        control_id="TEST-1",
        host="production-01",
        status=ComplianceStatus.PASS,
        evidence=(make_evidence(),),
    )


def test_json_reporter_preserves_audit_status() -> None:
    reporter = JsonReporter()

    rendered = reporter.render_audit(make_audit_result())
    document = json.loads(rendered)

    assert document["status"] == "fail"
    assert document["control_id"] == "TEST-1"
    assert document["host"] == "production-01"


def test_json_reporter_preserves_execution_status() -> None:
    reporter = JsonReporter()

    rendered = reporter.render_execution(make_execution_result())
    document = json.loads(rendered)

    assert document["status"] == "success"
    assert document["changed"] is True


def test_json_reporter_preserves_verification_status() -> None:
    reporter = JsonReporter()

    rendered = reporter.render_verification(
        make_verification_result()
    )
    document = json.loads(rendered)

    assert document["status"] == "pass"
    assert document["control_id"] == "TEST-1"


def test_json_reporter_preserves_evidence() -> None:
    reporter = JsonReporter()

    rendered = reporter.render_audit(make_audit_result())
    document = json.loads(rendered)

    assert len(document["evidence"]) == 1
    assert document["evidence"][0]["source"] == "test-audit"
    assert document["evidence"][0]["observed"] == {"value": "actual"}


def test_json_reporter_does_not_change_input_result() -> None:
    result = make_audit_result()
    original_status = result.status
    original_evidence = result.evidence

    JsonReporter().render_audit(result)

    assert result.status is original_status
    assert result.evidence == original_evidence


def test_csv_reporter_contains_audit_identity_and_status() -> None:
    reporter = CsvReporter()

    rendered = reporter.render_audit(make_audit_result())

    assert "TEST-1" in rendered
    assert "production-01" in rendered
    assert "fail" in rendered


def test_csv_reporter_contains_execution_status() -> None:
    reporter = CsvReporter()

    rendered = reporter.render_execution(
        make_execution_result()
    )

    assert "TEST-1" in rendered
    assert "production-01" in rendered
    assert "success" in rendered


def test_csv_reporter_contains_verification_status() -> None:
    reporter = CsvReporter()

    rendered = reporter.render_verification(
        make_verification_result()
    )

    assert "TEST-1" in rendered
    assert "production-01" in rendered
    assert "pass" in rendered


def test_html_reporter_escapes_untrusted_evidence() -> None:
    evidence = Evidence(
        control_id="TEST-1",
        host="production-01",
        source="<script>alert('x')</script>",
        observed={
            "value": "<img src=x onerror=alert(1)>",
        },
        expected={
            "value": "expected",
        },
    )

    result = AuditResult(
        control_id="TEST-1",
        host="production-01",
        status=ComplianceStatus.FAIL,
        evidence=(evidence,),
    )

    rendered = HtmlReporter().render_audit(result)

    assert "<script>alert('x')</script>" not in rendered
    assert "<img src=x onerror=alert(1)>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;img" in rendered


def test_html_reporter_contains_audit_status() -> None:
    rendered = HtmlReporter().render_audit(
        make_audit_result()
    )

    assert "TEST-1" in rendered
    assert "production-01" in rendered
    assert "fail" in rendered


def test_html_reporter_contains_verification_status() -> None:
    rendered = HtmlReporter().render_verification(
        make_verification_result()
    )

    assert "TEST-1" in rendered
    assert "production-01" in rendered
    assert "pass" in rendered


def test_reporting_unknown_or_failed_status_is_not_silently_converted() -> None:
    result = AuditResult(
        control_id="TEST-UNKNOWN",
        host="production-01",
        status=ComplianceStatus.UNKNOWN,
        evidence=(),
    )

    json_document = json.loads(
        JsonReporter().render_audit(result)
    )

    assert json_document["status"] == "unknown"

    csv_output = CsvReporter().render_audit(result)
    assert "unknown" in csv_output

    html_output = HtmlReporter().render_audit(result)
    assert "unknown" in html_output