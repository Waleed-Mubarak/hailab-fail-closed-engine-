from dataclasses import dataclass, field
from typing import Any


REQUIRED_CHECKS: tuple[str, ...] = (
    "archive_extraction",
    "manifest_schema",
    "trusted_key",
    "signature",
    "artifacts_integrity",
    "archive_allowlist",
    "semantic_telemetry",
)


@dataclass(frozen=True)
class ReasonCode:
    OK: str = "OK"
    ERR_ARCHIVE_EXTRACT: str = "ERR_ARCHIVE_EXTRACT"
    ERR_MANIFEST_SCHEMA: str = "ERR_MANIFEST_SCHEMA"
    ERR_UNTRUSTED_KEY: str = "ERR_UNTRUSTED_KEY"
    ERR_SIGNATURE_INVALID: str = "ERR_SIGNATURE_INVALID"
    ERR_ARTIFACT_TAMPER: str = "ERR_ARTIFACT_TAMPER"
    ERR_ALLOWLIST_VIOLATION: str = "ERR_ALLOWLIST_VIOLATION"
    ERR_SEMANTIC_MISMATCH: str = "ERR_SEMANTIC_MISMATCH"
    ERR_LEDGER_INTEGRITY: str = "ERR_LEDGER_INTEGRITY"


CHECK_FAILURE_REASON_MAP: dict[str, str] = {
    "archive_extraction": ReasonCode.ERR_ARCHIVE_EXTRACT,
    "manifest_schema": ReasonCode.ERR_MANIFEST_SCHEMA,
    "trusted_key": ReasonCode.ERR_UNTRUSTED_KEY,
    "signature": ReasonCode.ERR_SIGNATURE_INVALID,
    "artifacts_integrity": ReasonCode.ERR_ARTIFACT_TAMPER,
    "archive_allowlist": ReasonCode.ERR_ALLOWLIST_VIOLATION,
    "semantic_telemetry": ReasonCode.ERR_SEMANTIC_MISMATCH,
}


@dataclass
class VerificationResult:
    ok: bool
    returncode: int
    reason_code: str
    reason: str
    checks: dict[str, bool] = field(default_factory=dict)
    ledger_entry_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "returncode": self.returncode,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "checks": {key: bool(self.checks.get(key, False)) for key in REQUIRED_CHECKS},
        }
        if self.ledger_entry_sha256 is not None:
            payload["ledger_entry_sha256"] = self.ledger_entry_sha256
        return payload


def infer_reason_code(checks: dict[str, bool], passed: bool) -> str:
    if passed:
        return ReasonCode.OK
    for check_name in REQUIRED_CHECKS:
        if not bool(checks.get(check_name, True)):
            return CHECK_FAILURE_REASON_MAP[check_name]
    return ReasonCode.ERR_LEDGER_INTEGRITY


def build_verification_result(
    *,
    passed: bool,
    reason: str,
    checks: dict[str, bool] | None = None,
    reason_code: str | None = None,
    ledger_entry_sha256: str | None = None,
) -> VerificationResult:
    normalized_checks = {
        key: bool((checks or {}).get(key, False)) for key in REQUIRED_CHECKS
    }
    is_ok = bool(passed) and all(normalized_checks.values())
    resolved_code = reason_code or infer_reason_code(normalized_checks, is_ok)
    return VerificationResult(
        ok=is_ok,
        returncode=0 if is_ok else 1,
        reason_code=resolved_code,
        reason=reason,
        checks=normalized_checks,
        ledger_entry_sha256=ledger_entry_sha256,
    )

