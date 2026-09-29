"""Reviewed Ansible implementations for CIS Ubuntu 24.04 v2.0.0 controls."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from securebench.core import (
    AuditResult,
    ComplianceStatus,
    Control,
    Evidence,
    ExecutionError,
    ExecutionResult,
    ExecutionStatus,
    VerificationResult,
)
from securebench.core.transaction import ChangeRecord
from securebench.remediation.engine import RollbackPreparation
from securebench.rollback.engine import RollbackExecution

from .ansible import AnsibleExecutionBackend
from .base import ExecutionContext

_SAFE_TRANSACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SUPPORTED_CONTROL = "CIS-1.1.1.1"


class CISUbuntu2404V200Provider:
    """Fail-closed provider for reviewed CIS v2.0.0 implementations."""

    def __init__(
        self,
        *,
        inventory: str,
        transaction_id: str,
        playbook_root: str | Path,
        backend: AnsibleExecutionBackend | None = None,
    ) -> None:
        if not inventory.strip():
            raise ValueError("inventory must be a non-empty string")
        if not _SAFE_TRANSACTION_ID.fullmatch(transaction_id):
            raise ValueError("transaction_id contains unsafe characters")

        root = Path(playbook_root).resolve()
        names = {
            operation: root / f"cramfs_{operation}.yml"
            for operation in (
                "audit",
                "precheck",
                "prepare_rollback",
                "remediate",
                "verify",
                "rollback",
            )
        }
        missing = [str(path) for path in names.values() if not path.is_file()]
        if missing:
            raise ExecutionError(
                "required CIS playbooks are missing: " + ", ".join(missing)
            )

        self._backend = backend or AnsibleExecutionBackend()
        self._transaction_id = transaction_id
        self._context = ExecutionContext(
            inventory=inventory,
            variables={"securebench_transaction_id": transaction_id},
            extra={
                "playbooks": {
                    operation: str(path)
                    for operation, path in names.items()
                }
            },
        )

    def audit(self, control: Control, host: str) -> AuditResult:
        self._require_supported(control)
        raw = self._backend.audit(control, host, self._context)
        status = (
            ComplianceStatus.PASS
            if raw.status is ExecutionStatus.SUCCESS
            else ComplianceStatus.FAIL
        )
        return AuditResult(
            control_id=control.control_id,
            host=host,
            status=status,
            evidence=(self._evidence(control, host, raw, "audit"),),
            message=raw.message,
        )

    def precheck(self, control: Control, host: str) -> ExecutionResult:
        self._require_supported(control)
        return self._backend.precheck(control, host, self._context)

    def prepare_rollback(
        self,
        control: Control,
        host: str,
    ) -> RollbackPreparation:
        self._require_supported(control)
        result = self._backend.prepare_rollback(control, host, self._context)
        if result.status is not ExecutionStatus.SUCCESS:
            raise ExecutionError(result.message or "rollback state capture failed")

        state_path = (
            f"/var/lib/securebench/transactions/{self._transaction_id}/"
            f"{control.control_id}"
        )
        return RollbackPreparation(
            before={"remote_state_captured": True},
            rollback_data={
                "transaction_id": self._transaction_id,
                "state_path": state_path,
            },
        )

    def remediate(self, control: Control, host: str) -> ExecutionResult:
        self._require_supported(control)
        return self._backend.remediate(control, host, self._context)

    def verify(
        self,
        control: Control,
        host: str,
        context: Mapping[str, object] | None = None,
    ) -> VerificationResult:
        self._require_supported(control)
        raw = self._backend.verify(control, host, self._context)
        status = (
            ComplianceStatus.PASS
            if raw.status is ExecutionStatus.SUCCESS
            else ComplianceStatus.FAIL
        )
        return VerificationResult(
            control_id=control.control_id,
            host=host,
            status=status,
            evidence=(self._evidence(control, host, raw, "verification"),),
            message=raw.message,
        )

    def rollback(
        self,
        control: Control,
        host: str,
        change: ChangeRecord,
    ) -> RollbackExecution:
        self._require_supported(control)
        if not change.rollback_data:
            return RollbackExecution(
                control_id=control.control_id,
                host=host,
                success=False,
                message="Rollback data is missing.",
            )
        raw = self._backend.rollback(
            control,
            host,
            change,
            self._context,
        )
        return RollbackExecution(
            control_id=control.control_id,
            host=host,
            success=raw.status is ExecutionStatus.SUCCESS,
            message=raw.message or (
                "Rollback completed."
                if raw.status is ExecutionStatus.SUCCESS
                else "Rollback failed."
            ),
        )

    @staticmethod
    def _require_supported(control: Control) -> None:
        if control.benchmark_id != "cis-ubuntu-24.04":
            raise ExecutionError("control belongs to an unsupported benchmark")
        if control.benchmark_version != "2.0.0":
            raise ExecutionError("control belongs to an unsupported benchmark version")
        if control.control_id != _SUPPORTED_CONTROL:
            raise ExecutionError(
                f"control '{control.control_id}' has no reviewed implementation"
            )

    @staticmethod
    def _evidence(
        control: Control,
        host: str,
        result: ExecutionResult,
        operation: str,
    ) -> Evidence:
        return Evidence(
            control_id=control.control_id,
            host=host,
            source=f"ansible:{operation}",
            observed={
                "return_code": result.details.get("return_code"),
                "message": result.message,
            },
            expected={"return_code": 0},
            details={"operation": operation},
        )
