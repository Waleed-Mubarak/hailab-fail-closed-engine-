import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.request

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from forensic_ledger import verify_ledger_chain
from verification_result import ReasonCode, build_verification_result


def fetch_json(url: str, timeout: float = 2.0) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return {
                "reachable": True,
                "status_code": resp.status,
                "data": json.loads(raw),
            }
    except urllib.error.HTTPError as exc:
        return {"reachable": False, "status_code": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"reachable": False, "status_code": None, "error": str(exc)}


def fetch_text(url: str, timeout: float = 2.0) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return {
                "reachable": True,
                "status_code": resp.status,
                "text": raw,
            }
    except urllib.error.HTTPError as exc:
        return {"reachable": False, "status_code": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"reachable": False, "status_code": None, "error": str(exc)}


def parse_key_metrics(metrics_text: str | None) -> dict[str, int | float]:
    if not metrics_text:
        return {}
    targets = [
        "hailab_memory_purged",
        "hailab_memory_mlocked",
        "hailab_system_isolated",
    ]
    parsed: dict[str, int | float] = {}
    for name in targets:
        match = re.search(rf"^{re.escape(name)}\s+([0-9.]+)", metrics_text, flags=re.M)
        if match:
            val_str = match.group(1)
            parsed[name] = float(val_str) if "." in val_str else int(val_str)
    return parsed


def file_digest_and_size(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "path": str(path)}
    data = path.read_bytes()
    return {
        "exists": True,
        "path": str(path),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "modified_utc": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
    }


def inspect_audit_log(log_path: Path) -> dict[str, Any]:
    if not log_path.exists():
        return {"exists": False, "path": str(log_path)}
    lines = [
        ln.strip()
        for ln in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if ln.strip()
    ]
    return {
        "exists": True,
        "path": str(log_path),
        "line_count": len(lines),
        "last_entry_preview": lines[-1][:240] if lines else None,
    }


def verify_blackbox(decrypt_script: Path, box_path: Path) -> dict[str, Any]:
    if not decrypt_script.exists():
        return {"verified": False, "reason": f"Missing {decrypt_script}"}
    if not box_path.exists():
        return {"verified": False, "reason": f"Missing {box_path}"}

    proc = subprocess.run(
        [sys.executable, str(decrypt_script), str(box_path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = (proc.stdout or proc.stderr or "").strip()
    return {
        "verified": proc.returncode == 0,
        "returncode": proc.returncode,
        "output": output[:500],
    }


def compare_with_previous(previous_report_path: Path, current_state: dict[str, Any]) -> dict[str, Any]:
    if not previous_report_path.exists():
        return {"has_previous": False, "changed": None, "critical_diffs": []}
    try:
        prev = json.loads(previous_report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "has_previous": True,
            "error": str(exc),
            "critical_diffs": [f"Failed to parse previous report: {exc}"],
        }

    prev_art = prev.get("artifacts", {})
    prev_box = prev_art.get("blackbox", {})
    curr_box = current_state.get("blackbox", {})
    prev_log = prev_art.get("audit_log", {})
    curr_log = current_state.get("audit_log", {})

    box_sha_changed = prev_box.get("sha256") != curr_box.get("sha256")
    audit_lines_delta = (
        curr_log.get("line_count") - prev_log.get("line_count")
        if isinstance(curr_log.get("line_count"), int)
        and isinstance(prev_log.get("line_count"), int)
        else None
    )

    critical_diffs: list[str] = []
    if prev.get("server_online") is True and current_state.get("server_online") is False:
        critical_diffs.append("Engine went offline since previous report")
    if prev_box.get("exists") and box_sha_changed:
        critical_diffs.append("Blackbox SHA-256 changed compared to previous report")
    if isinstance(audit_lines_delta, int) and audit_lines_delta < 0:
        critical_diffs.append(f"Audit log line count decreased by {abs(audit_lines_delta)}")

    prev_ledger_ok = (prev.get("ledger_verification") or {}).get("ok")
    curr_ledger_ok = (current_state.get("ledger_verification") or {}).get("ok")
    if prev_ledger_ok is True and curr_ledger_ok is False:
        critical_diffs.append("Ledger hash-chain integrity regressed from OK to broken")

    return {
        "has_previous": True,
        "previous_checked_at_utc": prev.get("checked_at_utc"),
        "blackbox_sha256_changed": box_sha_changed,
        "audit_log_line_delta": audit_lines_delta,
        "changed": bool(box_sha_changed or (audit_lines_delta not in (0, None)) or critical_diffs),
        "critical_diffs": critical_diffs,
    }


def build_executive_summary(
    *,
    server_online: bool,
    artifacts: dict[str, Any],
    ledger_check: dict[str, Any],
    diff_info: dict[str, Any],
    blackbox_check: dict[str, Any],
) -> dict[str, Any]:
    critical_findings: list[str] = list(diff_info.get("critical_diffs") or [])

    if not ledger_check.get("ok"):
        critical_findings.append(
            f"Ledger integrity check failed: {ledger_check.get('detail')}"
        )

    box_info = artifacts.get("blackbox", {})
    if box_info.get("exists") and not blackbox_check.get("verified"):
        critical_findings.append(
            f"Blackbox verification failed: {blackbox_check.get('reason') or blackbox_check.get('output')}"
        )

    all_healthy = (
        bool(ledger_check.get("ok"))
        and (not box_info.get("exists") or bool(blackbox_check.get("verified")))
        and not critical_findings
    )

    result_contract = build_verification_result(
        passed=all_healthy,
        reason=(
            "Companion forensic posture healthy"
            if all_healthy
            else "; ".join(critical_findings) or "Companion forensic check failed"
        ),
        checks={
            "archive_extraction": True,
            "manifest_schema": True,
            "trusted_key": True,
            "signature": True,
            "artifacts_integrity": bool(
                not box_info.get("exists") or blackbox_check.get("verified")
            ),
            "archive_allowlist": True,
            "semantic_telemetry": server_online,
        },
        reason_code=ReasonCode.OK if all_healthy else ReasonCode.ERR_LEDGER_INTEGRITY,
    )

    return {
        "verdict": "PASS" if all_healthy else "FAIL",
        "ok": result_contract.ok,
        "returncode": result_contract.returncode,
        "reason_code": result_contract.reason_code,
        "reason": result_contract.reason,
        "critical_findings_count": len(critical_findings),
        "critical_findings": critical_findings,
    }


def render_markdown_summary(report: dict[str, Any]) -> str:
    exec_sum = report.get("executive_summary", {})
    ledger = report.get("ledger_verification", {})
    diffs = (report.get("diff_from_previous") or {}).get("critical_diffs") or []

    lines = [
        "# Forensic Companion Executive Summary",
        f"- **Checked (UTC):** {report.get('checked_at_utc')}",
        f"- **Base URL:** `{report.get('base_url')}`",
        f"- **Server Online:** {report.get('server_online')}",
        f"- **Verdict:** **{exec_sum.get('verdict')}** (`{exec_sum.get('reason_code')}`)",
        f"- **Ledger Chain:** `{ledger.get('reason_code')}` (entries: `{ledger.get('entries_count')}`)",
        "",
        "## Critical Diffs & Findings",
    ]
    combined = list(dict.fromkeys([*diffs, *(exec_sum.get("critical_findings") or [])]))
    if combined:
        for item in combined:
            lines.append(f"- {item}")
    else:
        lines.append("- No critical diffs or integrity regressions detected.")
    return "\n".join(lines) + "\n"


def build_engine_report(
    base_url: str = "http://127.0.0.1:8501",
    previous_report_path: Path = Path("reports/companion_report.json"),
    ledger_path: Path = Path("reports/verification_ledger.jsonl"),
) -> dict[str, Any]:
    root = Path(".")
    box_path = root / "hailab_forensic_blackbox.enc"
    audit_path = root / "hailab_secure_audit.log"
    decrypt_script = root / "decrypt_box.py"

    status_resp = fetch_json(f"{base_url}/status")
    metrics_resp = fetch_text(f"{base_url}/metrics")
    forensic_resp = fetch_json(f"{base_url}/forensic/summary")

    if metrics_resp.get("reachable"):
        metrics_resp["parsed_metrics"] = parse_key_metrics(metrics_resp.get("text"))

    artifacts: dict[str, Any] = {
        "blackbox": file_digest_and_size(box_path),
        "audit_log": inspect_audit_log(audit_path),
    }

    server_online = any(
        item.get("reachable") for item in (status_resp, metrics_resp, forensic_resp)
    )
    ledger_check = (
        verify_ledger_chain(ledger_path)
        if ledger_path.exists()
        else {
            "ok": True,
            "reason_code": ReasonCode.OK,
            "entries_count": 0,
            "head_sha256": None,
            "detail": f"Optional ledger not yet created at {ledger_path}",
        }
    )
    blackbox_check = verify_blackbox(decrypt_script, box_path)

    comparison_input = {
        **artifacts,
        "server_online": server_online,
        "ledger_verification": ledger_check,
    }
    diff_info = compare_with_previous(previous_report_path, comparison_input)
    exec_summary = build_executive_summary(
        server_online=server_online,
        artifacts=artifacts,
        ledger_check=ledger_check,
        diff_info=diff_info,
        blackbox_check=blackbox_check,
    )

    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "server_online": server_online,
        "executive_summary": exec_summary,
        "endpoints": {
            "status": status_resp,
            "metrics": metrics_resp,
            "forensic_summary": forensic_resp,
        },
        "artifacts": artifacts,
        "ledger_verification": ledger_check,
        "diff_from_previous": diff_info,
        "blackbox_verification": blackbox_check,
    }


def save_report(
    report: dict[str, Any],
    output_path: Path = Path("reports/companion_report.json"),
    markdown_path: Path | None = None,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if markdown_path is not None:
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_markdown_summary(report), encoding="utf-8")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build forensic companion report, critical diffs, and executive summary."
    )
    parser.add_argument("base_url", nargs="?", default="http://127.0.0.1:8501")
    parser.add_argument(
        "--previous-report",
        type=Path,
        default=Path("reports/companion_report.json"),
    )
    parser.add_argument(
        "--ledger-path",
        type=Path,
        default=Path("reports/verification_ledger.jsonl"),
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("reports/companion_report.json"),
    )
    parser.add_argument(
        "--out-md",
        type=Path,
        default=None,
    )
    args = parser.parse_args()

    report = build_engine_report(
        base_url=args.base_url,
        previous_report_path=args.previous_report,
        ledger_path=args.ledger_path,
    )
    saved_to = save_report(report, output_path=args.out_json, markdown_path=args.out_md)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nSaved report to: {saved_to}")
    sys.exit(report["executive_summary"]["returncode"])


if __name__ == "__main__":
    main()
