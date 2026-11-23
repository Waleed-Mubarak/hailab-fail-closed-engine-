import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def run_cmd(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _parse_json_safe(text: str) -> dict:
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                parsed = json.loads(text[start : end + 1])
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}


def _repack_extracted_dir(src_dir: Path, out_tar_gz: Path) -> None:
    out_tar_gz.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_tar_gz, "w:gz") as tar:
        for item in sorted(src_dir.rglob("*")):
            if item.is_file():
                tar.add(item, arcname=str(item.relative_to(src_dir)))


def run_full_suite(repo_dir: Path, bundle_script: Path, pub_key: Path, out_dir: Path) -> dict:
    results: dict = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "bundle_script": str(bundle_script),
        "trusted_pub_key": str(pub_key),
        "steps": {},
    }

    # 1. إنشاء حزمة موقّعة جديدة
    rc, out, err = run_cmd(
        [
            sys.executable,
            str(bundle_script),
            "create",
            "--case-id",
            "LAB-SUITE-FULL",
            "--notes",
            "Full forensic verification, artifact tamper, semantic tamper, and untrusted key suite",
            "--out-dir",
            str(out_dir),
        ],
        repo_dir,
    )
    if rc != 0:
        results["all_passed"] = False
        results["error"] = f"create failed: {err or out}"
        return results

    created_info = _parse_json_safe(out)
    bundle_path = Path(created_info.get("created_bundle", ""))
    if not bundle_path.exists():
        results["all_passed"] = False
        results["error"] = f"Created bundle not found: {bundle_path}"
        return results

    results["steps"]["create"] = {
        "ok": True,
        "bundle": str(bundle_path),
        "bundle_id": created_info.get("bundle_id"),
    }

    # 2. التحقق من الحزمة السليمة (يجب أن ينجح: exit 0 و valid=True)
    rc, out, err = run_cmd(
        [
            sys.executable,
            str(bundle_script),
            "verify",
            str(bundle_path),
            "--trusted-pub-key",
            str(pub_key),
        ],
        repo_dir,
    )
    verify_ok_data = _parse_json_safe(out)
    genuine_passed = (rc == 0) and (verify_ok_data.get("valid") is True)
    results["steps"]["genuine_verify"] = {
        "ok": genuine_passed,
        "returncode": rc,
        "checks": verify_ok_data.get("checks"),
    }

    with tempfile.TemporaryDirectory(prefix="hailab_suite_") as tmp:
        tmp_path = Path(tmp)

        # 3. اختبار التلاعب بملف دليل داخل الأرشيف
        art_extract = tmp_path / "art_extracted"
        art_extract.mkdir(parents=True, exist_ok=True)
        with tarfile.open(bundle_path, "r:gz") as tar:
            tar.extractall(path=art_extract)

        target_log = art_extract / "hailab_secure_audit.log"
        if target_log.exists():
            with target_log.open("ab") as f:
                f.write(b"\n[TAMPER_TEST_LINE]\n")
        else:
            target_log.write_text("[TAMPER_TEST_LINE]\n", encoding="utf-8")

        tampered_art_tar = tmp_path / "tampered_artifact.tar.gz"
        _repack_extracted_dir(art_extract, tampered_art_tar)

        rc_a, out_a, err_a = run_cmd(
            [
                sys.executable,
                str(bundle_script),
                "verify",
                str(tampered_art_tar),
                "--trusted-pub-key",
                str(pub_key),
            ],
            repo_dir,
        )
        art_data = _parse_json_safe(out_a)
        art_passed = (rc_a != 0) and (art_data.get("valid") is False)
        results["steps"]["artifact_tamper_rejected"] = {
            "ok": art_passed,
            "returncode": rc_a,
            "reason": art_data.get("reason") or err_a,
            "checks": art_data.get("checks"),
        }

        # 4. اختبار التزوير الدلالي في manifest.json
        sem_extract = tmp_path / "sem_extracted"
        sem_extract.mkdir(parents=True, exist_ok=True)
        with tarfile.open(bundle_path, "r:gz") as tar:
            tar.extractall(path=sem_extract)

        manifest_file = sem_extract / "manifest.json"
        m_obj = json.loads(manifest_file.read_text(encoding="utf-8"))
        snap = m_obj.get("telemetry_snapshot", {})
        audit_chain = snap.get("audit_chain", {})
        if isinstance(audit_chain, dict) and "entries" in audit_chain:
            audit_chain["entries"] = 999999
        else:
            snap["forged_field"] = "tampered"
        m_obj["telemetry_snapshot"] = snap
        manifest_file.write_text(json.dumps(m_obj, indent=2), encoding="utf-8")

        forged_sem_tar = tmp_path / "forged_semantic.tar.gz"
        _repack_extracted_dir(sem_extract, forged_sem_tar)

        rc_s, out_s, err_s = run_cmd(
            [
                sys.executable,
                str(bundle_script),
                "verify",
                str(forged_sem_tar),
                "--trusted-pub-key",
                str(pub_key),
            ],
            repo_dir,
        )
        sem_data = _parse_json_safe(out_s)
        sem_passed = (rc_s != 0) and (sem_data.get("valid") is False)
        results["steps"]["semantic_tamper_rejected"] = {
            "ok": sem_passed,
            "returncode": rc_s,
            "reason": sem_data.get("reason") or err_s,
            "checks": sem_data.get("checks"),
        }

        # 5. اختبار المفتاح غير الموثوق
        wrong_pub_pem = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        wrong_pub_path = tmp_path / "untrusted_pub.pem"
        wrong_pub_path.write_bytes(wrong_pub_pem)

        rc_k, out_k, err_k = run_cmd(
            [
                sys.executable,
                str(bundle_script),
                "verify",
                str(bundle_path),
                "--trusted-pub-key",
                str(wrong_pub_path),
            ],
            repo_dir,
        )
        key_data = _parse_json_safe(out_k)
        key_passed = (rc_k != 0) and (key_data.get("valid") is False)
        results["steps"]["untrusted_key_rejected"] = {
            "ok": key_passed,
            "returncode": rc_k,
            "reason": key_data.get("reason") or err_k,
            "checks": key_data.get("checks"),
        }

    results["all_passed"] = bool(
        genuine_passed and art_passed and sem_passed and key_passed
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run unified forensic bundle verification and security tamper suite."
    )
    parser.add_argument("--repo-dir", type=Path, default=Path("."))
    parser.add_argument("--bundle-script", type=Path, default=Path("tools/forensic_bundle.py"))
    parser.add_argument("--pub-key", type=Path, default=Path("keys/forensic_ed25519.pub"))
    parser.add_argument("--out-dir", type=Path, default=Path("reports/bundles"))
    parser.add_argument(
        "--report-out",
        type=Path,
        default=None,
        help="Optional output JSON file path to save the full test suite summary",
    )
    args = parser.parse_args()

    summary = run_full_suite(
        repo_dir=args.repo_dir.resolve(),
        bundle_script=args.bundle_script,
        pub_key=args.pub_key,
        out_dir=args.out_dir,
    )

    if args.report_out is not None:
        report_target = (
            args.report_out
            if args.report_out.is_absolute()
            else (args.repo_dir.resolve() / args.report_out)
        )
        report_target.parent.mkdir(parents=True, exist_ok=True)
        report_target.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        summary["report_saved_to"] = str(report_target)

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    sys.exit(0 if summary.get("all_passed") else 1)


if __name__ == "__main__":
    main()

