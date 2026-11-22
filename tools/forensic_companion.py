import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def fetch_json(url: str, timeout: float = 2.0) -> dict:
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


def fetch_text(url: str, timeout: float = 2.0) -> dict:
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


def parse_key_metrics(metrics_text: str | None) -> dict:
    if not metrics_text:
        return {}
    targets = [
        "hailab_memory_purged",
        "hailab_memory_mlocked",
        "hailab_system_isolated",
    ]
    parsed = {}
    for name in targets:
        match = re.search(rf"^{re.escape(name)}\s+([0-9.]+)", metrics_text, flags=re.M)
        if match:
            val_str = match.group(1)
            parsed[name] = float(val_str) if "." in val_str else int(val_str)
    return parsed


def file_digest_and_size(path: Path) -> dict:
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


def inspect_audit_log(log_path: Path) -> dict:
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


def verify_blackbox(decrypt_script: Path, box_path: Path) -> dict:
    if not decrypt_script.exists():
        return {"verified": False, "reason": f"Missing {decrypt_script}"}
    if not box_path.exists():
        return {"verified": False, "reason": f"Missing {box_path}"}

    proc = subprocess.run(
        ["python3", str(decrypt_script), str(box_path)],
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


def compare_with_previous(previous_report_path: Path, current_artifacts: dict) -> dict:
    if not previous_report_path.exists():
        return {"has_previous": False, "changed": None}
    try:
        prev = json.loads(previous_report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"has_previous": True, "error": str(exc)}

    prev_art = prev.get("artifacts", {})
    prev_box = prev_art.get("blackbox", {})
    curr_box = current_artifacts.get("blackbox", {})
    prev_log = prev_art.get("audit_log", {})
    curr_log = current_artifacts.get("audit_log", {})

    box_sha_changed = prev_box.get("sha256") != curr_box.get("sha256")
    audit_lines_delta = (
        curr_log.get("line_count") - prev_log.get("line_count")
        if isinstance(curr_log.get("line_count"), int)
        and isinstance(prev_log.get("line_count"), int)
        else None
    )

    return {
        "has_previous": True,
        "previous_checked_at_utc": prev.get("checked_at_utc"),
        "blackbox_sha256_changed": box_sha_changed,
        "audit_log_line_delta": audit_lines_delta,
        "changed": bool(box_sha_changed or (audit_lines_delta not in (0, None))),
    }


def build_engine_report(
    base_url: str = "http://127.0.0.1:8501",
    previous_report_path: Path = Path("reports/companion_report.json"),
) -> dict:
    root = Path(".")
    box_path = root / "hailab_forensic_blackbox.enc"
    audit_path = root / "hailab_secure_audit.log"
    decrypt_script = root / "decrypt_box.py"

    status_resp = fetch_json(f"{base_url}/status")
    metrics_resp = fetch_text(f"{base_url}/metrics")
    forensic_resp = fetch_json(f"{base_url}/forensic/summary")

    if metrics_resp.get("reachable"):
        metrics_resp["parsed_metrics"] = parse_key_metrics(metrics_resp.get("text"))

    artifacts = {
        "blackbox": file_digest_and_size(box_path),
        "audit_log": inspect_audit_log(audit_path),
    }

    server_online = any(
        item.get("reachable") for item in (status_resp, metrics_resp, forensic_resp)
    )

    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "server_online": server_online,
        "endpoints": {
            "status": status_resp,
            "metrics": metrics_resp,
            "forensic_summary": forensic_resp,
        },
        "artifacts": artifacts,
        "diff_from_previous": compare_with_previous(previous_report_path, artifacts),
        "blackbox_verification": verify_blackbox(decrypt_script, box_path),
    }


def save_report(report: dict, output_path: Path = Path("reports/companion_report.json")) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return output_path


if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8501"
    report = build_engine_report(target_url)
    saved_to = save_report(report)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nSaved report to: {saved_to}")
