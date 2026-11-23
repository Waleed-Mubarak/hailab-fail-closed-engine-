import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN_PREFIX = b"HAILAB_FORENSIC_BUNDLE_V1\x00"
GENESIS_HASH = "0" * 64


def run_cmd(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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


def _verify_ledger_chain(ledger_file: Path) -> tuple[bool, int, str]:
    if not ledger_file.exists():
        return False, 0, "Ledger file does not exist"
    lines = [ln for ln in ledger_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        return False, 0, "Ledger file is empty"

    expected_prev = GENESIS_HASH
    for expected_idx, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except Exception as exc:
            return False, len(lines), f"Invalid JSON at ledger line {expected_idx}: {exc}"

        if obj.get("index") != expected_idx:
            return False, len(lines), f"Index mismatch at line {expected_idx}: got {obj.get('index')}"
        if obj.get("prev_entry_sha256") != expected_prev:
            return False, len(lines), f"Broken prev_entry_sha256 link at index {expected_idx}"

        recorded_hash = obj.get("entry_sha256")
        core = {k: v for k, v in obj.items() if k != "entry_sha256"}
        recomputed = _sha256_bytes(
            json.dumps(core, sort_keys=True, ensure_ascii=False).encode("utf-8")
        )
        if recorded_hash != recomputed:
            return False, len(lines), f"Hash mismatch at ledger index {expected_idx}"

        expected_prev = recorded_hash

    return True, len(lines), "Ledger hash-chain verified"


def _build_signed_semantic_tampered_bundle(
    source_bundle: Path, work_dir: Path
) -> tuple[Path, Path]:
    extract_dir = work_dir / "signed_sem_extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(source_bundle, "r:gz") as tar:
        tar.extractall(path=extract_dir)

    report_file = extract_dir / "companion_report.json"
    report_obj = json.loads(report_file.read_text(encoding="utf-8"))
    chain_obj = (
        report_obj.setdefault("endpoints", {})
        .setdefault("forensic_summary", {})
        .setdefault("data", {})
        .setdefault("chain", {})
    )
    chain_obj["entries"] = 777777
    report_file.write_text(
        json.dumps(report_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    test_priv = Ed25519PrivateKey.generate()
    test_pub = test_priv.public_key()
    pub_der = test_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    test_pub_fp = _sha256_bytes(pub_der)
    test_pub_pem = test_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (extract_dir / "signer_public.pem").write_bytes(test_pub_pem)
    temp_pub_path = work_dir / "temp_signer_pub.pem"
    temp_pub_path.write_bytes(test_pub_pem)

    manifest_file = extract_dir / "manifest.json"
    manifest_obj = json.loads(manifest_file.read_text(encoding="utf-8"))

    for art in manifest_obj.get("artifacts", []):
        member_rel = art.get("archive_member", "")
        member_path = extract_dir / member_rel
        if member_path.exists() and member_path.is_file():
            art["size_bytes"] = member_path.stat().st_size
            art["sha256"] = _sha256_file(member_path)

    manifest_obj.setdefault("signature_info", {})["public_key_sha256"] = test_pub_fp
    canonical_manifest = json.dumps(
        manifest_obj, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    manifest_file.write_bytes(canonical_manifest + b"\n")

    meta = manifest_obj.get("bundle_metadata", {})
    binding_header = json.dumps(
        {
            "domain": "HAILAB_FORENSIC_BUNDLE_V1",
            "schema_version": meta.get("schema_version"),
            "bundle_id": meta.get("bundle_id"),
            "case_id": meta.get("case_id"),
            "public_key_sha256": test_pub_fp,
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    signing_payload = DOMAIN_PREFIX + binding_header + b"\x00" + canonical_manifest
    sig_b64 = base64.b64encode(test_priv.sign(signing_payload)).decode("ascii")

    sig_payload = {
        "algorithm": "Ed25519",
        "domain_binding": "HAILAB_FORENSIC_BUNDLE_V1",
        "public_key_sha256": test_pub_fp,
        "signature_base64": sig_b64,
    }
    (extract_dir / "manifest.sig.json").write_text(
        json.dumps(sig_payload, indent=2) + "\n", encoding="utf-8"
    )

    out_tar = work_dir / "signed_semantic_forged.tar.gz"
    _repack_extracted_dir(extract_dir, out_tar)
    return out_tar, temp_pub_path


def run_full_suite(
    repo_dir: Path, bundle_script: Path, pub_key: Path, out_dir: Path
) -> dict:
    results: dict = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "bundle_script": str(bundle_script),
        "trusted_pub_key": str(pub_key),
        "steps": {},
    }

    with tempfile.TemporaryDirectory(prefix="hailab_suite_") as tmp:
        tmp_path = Path(tmp)
        temp_ledger = tmp_path / "suite_verification_ledger.jsonl"

        # 1. إنشاء حزمة موقّعة جديدة
        rc, out, err = run_cmd(
            [
                sys.executable,
                str(bundle_script),
                "create",
                "--case-id",
                "LAB-SUITE-V140",
                "--notes",
                "Unified forensic verification, tamper, signed semantic forgery, and ledger chain suite",
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

        # 2. التحقق من الحزمة السليمة + تسجيل في سجل التحقق
        rc, out, err = run_cmd(
            [
                sys.executable,
                str(bundle_script),
                "verify",
                str(bundle_path),
                "--trusted-pub-key",
                str(pub_key),
                "--ledger-out",
                str(temp_ledger),
            ],
            repo_dir,
        )
        verify_ok_data = _parse_json_safe(out)
        genuine_passed = (rc == 0) and (verify_ok_data.get("valid") is True)
        results["steps"]["genuine_verify"] = {
            "ok": genuine_passed,
            "returncode": rc,
            "checks": verify_ok_data.get("checks"),
            "ledger_entry_sha256": verify_ok_data.get("ledger_entry_sha256"),
        }

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
                "--ledger-out",
                str(temp_ledger),
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

        # 4. اختبار التزوير الدلالي الموقّع (تعديل التقرير + إعادة توقيع بمفتاح اختباري مؤقت)
        signed_sem_tar, temp_signer_pub = _build_signed_semantic_tampered_bundle(
            bundle_path, tmp_path
        )
        rc_s, out_s, err_s = run_cmd(
            [
                sys.executable,
                str(bundle_script),
                "verify",
                str(signed_sem_tar),
                "--trusted-pub-key",
                str(temp_signer_pub),
                "--ledger-out",
                str(temp_ledger),
            ],
            repo_dir,
        )
        sem_data = _parse_json_safe(out_s)
        sem_checks = sem_data.get("checks") or {}
        sem_passed = (
            (rc_s != 0)
            and (sem_data.get("valid") is False)
            and (sem_checks.get("signature") is True)
            and (sem_checks.get("artifacts_integrity") is True)
            and (sem_checks.get("semantic_telemetry") is False)
        )
        results["steps"]["signed_semantic_tamper_rejected"] = {
            "ok": sem_passed,
            "returncode": rc_s,
            "reason": sem_data.get("reason") or err_s,
            "checks": sem_checks,
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
                "--ledger-out",
                str(temp_ledger),
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

        # 6. التحقق من سلامة سلسلة الهاش في سجل التحقق
        ledger_ok, ledger_entries, ledger_msg = _verify_ledger_chain(temp_ledger)
        results["steps"]["verification_ledger_chain_valid"] = {
            "ok": ledger_ok,
            "entries_count": ledger_entries,
            "detail": ledger_msg,
        }

    results["all_passed"] = bool(
        genuine_passed and art_passed and sem_passed and key_passed and ledger_ok
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run unified forensic bundle verification and security tamper suite."
    )
    parser.add_argument("--repo-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--bundle-script", type=Path, default=Path("tools/forensic_bundle.py")
    )
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
