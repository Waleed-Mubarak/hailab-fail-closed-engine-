from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from verification_result import ReasonCode, VerificationResult


GENESIS_HASH = "0" * 64


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_entry_hash(prev_hash: str, entry_without_hash: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(b":")
    digest.update(_canonical_json(entry_without_hash))
    return digest.hexdigest()


def get_ledger_head_hash(ledger_path: str | Path) -> str:
    path = Path(ledger_path)
    if not path.exists():
        return GENESIS_HASH

    last_valid_hash = GENESIS_HASH
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            break
        if isinstance(record, dict) and isinstance(record.get("entry_sha256"), str):
            last_valid_hash = record["entry_sha256"]
    return last_valid_hash


def append_ledger_entry(
    ledger_path: str | Path,
    *,
    bundle_id: str,
    ok: bool,
    returncode: int,
    reason_code: str,
    reason: str,
    checks: dict[str, bool],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = Path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = get_ledger_head_hash(path)

    entry_body: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "bundle_id": bundle_id,
        "ok": bool(ok),
        "returncode": int(returncode),
        "reason_code": reason_code,
        "reason": reason,
        "checks": {k: bool(v) for k, v in checks.items()},
        "prev_hash": prev_hash,
    }
    if extra:
        entry_body["extra"] = extra

    entry_hash = compute_entry_hash(prev_hash, entry_body)
    record = dict(entry_body)
    record["entry_sha256"] = entry_hash

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    return record


def append_verification_to_ledger(
    ledger_path: str | Path,
    *,
    bundle_id: str,
    result: VerificationResult,
    execution_mode: str = "verify",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """يسجّل كائن VerificationResult مباشرة في السجل ويُحدّث ledger_entry_sha256 عليه."""
    merged_extra: dict[str, Any] = {"execution_mode": execution_mode}
    if extra:
        merged_extra.update(extra)

    record = append_ledger_entry(
        ledger_path=ledger_path,
        bundle_id=bundle_id,
        ok=result.ok,
        returncode=result.returncode,
        reason_code=result.reason_code,
        reason=result.reason,
        checks=result.checks,
        extra=merged_extra,
    )
    result.ledger_entry_sha256 = record["entry_sha256"]
    return record


def verify_ledger_chain(ledger_path: str | Path) -> dict[str, Any]:
    path = Path(ledger_path)
    if not path.exists():
        return {
            "ok": False,
            "reason_code": ReasonCode.ERR_LEDGER_INTEGRITY,
            "entries_count": 0,
            "head_sha256": None,
            "detail": f"Ledger file not found: {path}",
        }

    lines = path.read_text(encoding="utf-8").splitlines()
    expected_prev_hash = GENESIS_HASH
    last_good_hash: str | None = None
    valid_entries = 0

    for idx, raw_line in enumerate(lines):
        line_num = idx + 1
        if not raw_line.strip():
            continue

        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "reason_code": ReasonCode.ERR_LEDGER_INTEGRITY,
                "entries_count": valid_entries,
                "broken_at_index": idx,
                "broken_at_line": line_num,
                "head_sha256": last_good_hash,
                "detail": f"Invalid JSON at line {line_num}: {exc}",
            }

        if not isinstance(record, dict):
            return {
                "ok": False,
                "reason_code": ReasonCode.ERR_LEDGER_INTEGRITY,
                "entries_count": valid_entries,
                "broken_at_index": idx,
                "broken_at_line": line_num,
                "head_sha256": last_good_hash,
                "detail": f"Malformed entry object at line {line_num}",
            }

        recorded_prev = record.get("prev_hash")
        recorded_hash = record.get("entry_sha256")

        if recorded_prev != expected_prev_hash:
            return {
                "ok": False,
                "reason_code": ReasonCode.ERR_LEDGER_INTEGRITY,
                "entries_count": valid_entries,
                "broken_at_index": idx,
                "broken_at_line": line_num,
                "head_sha256": last_good_hash,
                "detail": f"Chain prev_hash mismatch at line {line_num}",
            }

        body = {k: v for k, v in record.items() if k != "entry_sha256"}
        recomputed_hash = compute_entry_hash(expected_prev_hash, body)

        if not isinstance(recorded_hash, str) or recorded_hash != recomputed_hash:
            return {
                "ok": False,
                "reason_code": ReasonCode.ERR_LEDGER_INTEGRITY,
                "entries_count": valid_entries,
                "broken_at_index": idx,
                "broken_at_line": line_num,
                "head_sha256": last_good_hash,
                "detail": f"Entry hash mismatch at line {line_num}",
            }

        expected_prev_hash = recomputed_hash
        last_good_hash = recomputed_hash
        valid_entries += 1

    return {
        "ok": True,
        "reason_code": ReasonCode.OK,
        "entries_count": valid_entries,
        "head_sha256": last_good_hash,
        "detail": "Ledger hash-chain verified",
    }

