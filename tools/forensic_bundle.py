import argparse
import base64
import fcntl
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = "1.4.0"
DOMAIN_PREFIX = b"HAILAB_FORENSIC_BUNDLE_V1\x00"
RESERVED_MEMBERS = {"manifest.json", "manifest.sig.json", "signer_public.pem"}
MAX_MEMBER_BYTES = 100 * 1024 * 1024
MAX_TOTAL_EXTRACT_BYTES = 250 * 1024 * 1024
GENESIS_HASH = "0" * 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonicalize_manifest(manifest_obj: dict) -> bytes:
    return json.dumps(manifest_obj, sort_keys=True, ensure_ascii=False).encode("utf-8")


def build_signing_payload(manifest_obj: dict) -> bytes:
    meta = manifest_obj.get("bundle_metadata", {}) if isinstance(manifest_obj, dict) else {}
    binding_header = json.dumps(
        {
            "domain": "HAILAB_FORENSIC_BUNDLE_V1",
            "schema_version": meta.get("schema_version"),
            "bundle_id": meta.get("bundle_id"),
            "case_id": meta.get("case_id"),
            "public_key_sha256": manifest_obj.get("signature_info", {}).get("public_key_sha256"),
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return DOMAIN_PREFIX + binding_header + b"\x00" + canonicalize_manifest(manifest_obj)


def load_private_key(priv_path: Path, passphrase: str | None = None) -> Ed25519PrivateKey:
    if not priv_path.exists():
        raise FileNotFoundError(f"Private key not found: {priv_path}")
    pwd = passphrase.encode("utf-8") if passphrase else None
    try:
        key = serialization.load_pem_private_key(priv_path.read_bytes(), password=pwd)
    except TypeError as exc:
        raise ValueError("Private key requires a valid passphrase.") from exc
    except Exception as exc:
        raise ValueError(f"Failed to load private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key must be an Ed25519 key.")
    return key


def load_public_key(pub_path: Path) -> Ed25519PublicKey:
    if not pub_path.exists():
        raise FileNotFoundError(f"Public key not found: {pub_path}")
    key = serialization.load_pem_public_key(pub_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Public key must be an Ed25519 key.")
    return key


def public_key_fingerprint(pub_key: Ed25519PublicKey) -> str:
    pub_der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(pub_der)


def generate_keypair(
    priv_path: Path,
    pub_path: Path,
    passphrase: str | None = None,
    force: bool = False,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    if (priv_path.exists() or pub_path.exists()) and not force:
        raise FileExistsError(
            f"Key files already exist ({priv_path}, {pub_path}). Pass --force to overwrite."
        )

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass

    fp = public_key_fingerprint(pub)
    pub_path.with_suffix(".sha256").write_text(f"{fp}  {pub_path.name}\n", encoding="utf-8")
    return priv, pub


def build_artifact_entry(path: Path, role: str, archive_name: str) -> dict:
    return {
        "archive_member": archive_name,
        "source_filename": path.name,
        "role": role,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def extract_telemetry_summary(report_data: dict) -> dict:
    metrics_block = report_data.get("endpoints", {}).get("metrics", {})
    chain_block = (
        report_data.get("endpoints", {})
        .get("forensic_summary", {})
        .get("data", {})
        .get("chain", {})
    )
    bb_verify = report_data.get("blackbox_verification", {})

    return {
        "parsed_metrics": metrics_block.get("parsed_metrics", {}),
        "diff_from_previous": report_data.get("diff_from_previous", {}),
        "audit_chain": {
            "status": chain_block.get("status"),
            "entries": chain_block.get("entries"),
        },
        "blackbox_verification": {
            "verified": bb_verify.get("verified"),
            "returncode": bb_verify.get("returncode"),
        },
    }


def _validate_manifest_structure(manifest_obj: dict) -> tuple[bool, str]:
    if not isinstance(manifest_obj, dict):
        return False, "Manifest root must be a JSON object"

    for req_key in ("bundle_metadata", "telemetry_snapshot", "artifacts", "signature_info"):
        if req_key not in manifest_obj:
            return False, f"Missing required manifest section: {req_key}"

    meta = manifest_obj.get("bundle_metadata")
    if not isinstance(meta, dict):
        return False, "bundle_metadata must be a JSON object"
    for meta_key in ("schema_version", "bundle_id", "created_at_utc"):
        if not meta.get(meta_key):
            return False, f"Missing or empty bundle_metadata.{meta_key}"

    snapshot = manifest_obj.get("telemetry_snapshot")
    if not isinstance(snapshot, dict):
        return False, "telemetry_snapshot must be a JSON object"

    artifacts = manifest_obj.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False, "artifacts must be a non-empty list"

    seen_members: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            return False, "Artifact entry must be a JSON object"
        member = item.get("archive_member")
        sha_hex = item.get("sha256")
        size_val = item.get("size_bytes")
        if not isinstance(member, str) or not member:
            return False, "Invalid archive_member in manifest"
        if member in seen_members:
            return False, f"Duplicate archive_member in manifest: {member}"
        seen_members.add(member)
        if not isinstance(sha_hex, str) or len(sha_hex) != 64:
            return False, f"Invalid sha256 in manifest for {member}"
        if not isinstance(size_val, int) or isinstance(size_val, bool) or size_val < 0:
            return False, f"Invalid size_bytes in manifest for {member}"

    return True, "Manifest structure valid"


def _verify_semantic_and_cross_artifact(
    manifest_obj: dict,
    companion_report_path: Path,
    blackbox_path: Path,
    audit_log_path: Path,
) -> tuple[bool, str]:
    if not companion_report_path.exists() or not companion_report_path.is_file():
        return False, "companion_report.json missing for semantic telemetry check"

    try:
        report_data = json.loads(companion_report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Failed to parse companion_report.json: {exc}"

    if not isinstance(report_data, dict):
        return False, "companion_report.json root must be a JSON object"

    expected_snapshot = manifest_obj.get("telemetry_snapshot")
    actual_snapshot = extract_telemetry_summary(report_data)
    if actual_snapshot != expected_snapshot:
        return False, "Semantic mismatch: manifest telemetry_snapshot differs from companion_report.json"

    if not blackbox_path.exists() or blackbox_path.stat().st_size == 0:
        return False, "Cross-artifact anomaly: blackbox artifact is missing or empty"
    if not audit_log_path.exists() or audit_log_path.stat().st_size == 0:
        return False, "Cross-artifact anomaly: audit log artifact is missing or empty"

    entries = actual_snapshot.get("audit_chain", {}).get("entries")
    if isinstance(entries, int) and entries < 0:
        return False, "Cross-artifact anomaly: negative audit_chain entries count"

    return True, "Semantic telemetry and cross-artifact consistency verified"


def _is_safe_member_name(name: str) -> bool:
    p = Path(name)
    if not name or p.is_absolute() or ".." in p.parts or name.startswith(("/", "\\")):
        return False
    return True


def _safe_extract_tar(tar: tarfile.TarFile, dest_dir: Path) -> set[str]:
    resolved_dest = dest_dir.resolve()
    extracted_members: set[str] = set()
    total_bytes = 0

    for member in tar.getmembers():
        if not _is_safe_member_name(member.name):
            raise ValueError(f"Unsafe archive member path: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"Links are not allowed in forensic bundle: {member.name}")
        target = (resolved_dest / member.name).resolve()
        if not target.is_relative_to(resolved_dest):
            raise ValueError(f"Path traversal attempt detected: {member.name}")
        if member.isfile():
            if member.size > MAX_MEMBER_BYTES:
                raise ValueError(f"Archive member exceeds size limit: {member.name}")
            total_bytes += member.size
            if total_bytes > MAX_TOTAL_EXTRACT_BYTES:
                raise ValueError("Archive total uncompressed size exceeds limit")
            extracted_members.add(member.name)

    try:
        tar.extractall(path=resolved_dest, filter="data")
    except TypeError:
        tar.extractall(path=resolved_dest)
    return extracted_members


def append_verification_ledger(ledger_path: Path, bundle_file: Path, verify_result: dict) -> str:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_sha = sha256_file(bundle_file) if bundle_file.exists() else None
    now_iso = datetime.now(timezone.utc).isoformat()

    with ledger_path.open("a+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
            index = len(lines)
            prev_hash = GENESIS_HASH
            if lines:
                last_obj = json.loads(lines[-1])
                prev_hash = last_obj.get("entry_sha256", GENESIS_HASH)

            entry_core = {
                "index": index,
                "timestamp_utc": now_iso,
                "bundle_path": str(bundle_file),
                "bundle_sha256": bundle_sha,
                "bundle_id": verify_result.get("bundle_id"),
                "case_id": verify_result.get("case_id"),
                "schema_version": verify_result.get("schema_version"),
                "valid": verify_result.get("valid"),
                "reason": verify_result.get("reason"),
                "public_key_sha256": verify_result.get("public_key_sha256"),
                "checks": verify_result.get("checks"),
                "prev_entry_sha256": prev_hash,
            }
            serialized_core = json.dumps(entry_core, sort_keys=True, ensure_ascii=False).encode("utf-8")
            entry_hash = sha256_bytes(serialized_core)
            full_entry = dict(entry_core)
            full_entry["entry_sha256"] = entry_hash

            f.seek(0, os.SEEK_END)
            f.write(json.dumps(full_entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    return entry_hash


def create_bundle(
    report_path: Path,
    blackbox_path: Path,
    audit_log_path: Path,
    out_dir: Path,
    priv_key_path: Path,
    pub_key_path: Path,
    extra_files: list[Path] | None = None,
    passphrase: str | None = None,
    case_id: str | None = None,
    notes: str | None = None,
) -> dict:
    for p in (report_path, blackbox_path, audit_log_path):
        if not p.exists():
            raise FileNotFoundError(f"Required artifact missing: {p}")

    extra_files = extra_files or []
    for ep in extra_files:
        if not ep.exists():
            raise FileNotFoundError(f"Extra artifact missing: {ep}")

    priv_exists = priv_key_path.exists()
    pub_exists = pub_key_path.exists()
    if not priv_exists and not pub_exists:
        priv_key, pub_key = generate_keypair(priv_key_path, pub_key_path, passphrase=passphrase)
    elif priv_exists and pub_exists:
        priv_key = load_private_key(priv_key_path, passphrase=passphrase)
        pub_key = load_public_key(pub_key_path)
    else:
        missing = priv_key_path if not priv_exists else pub_key_path
        raise FileNotFoundError(f"Incomplete keypair; missing: {missing}")

    pub_fingerprint = public_key_fingerprint(pub_key)
    report_data = json.loads(report_path.read_text(encoding="utf-8"))

    staged_artifacts: list[tuple[Path, str, str]] = [
        (report_path, "companion_report", "companion_report.json"),
        (blackbox_path, "encrypted_blackbox", "hailab_forensic_blackbox.enc"),
        (audit_log_path, "audit_log", "hailab_secure_audit.log"),
    ]

    used_names = {a for _, _, a in staged_artifacts} | RESERVED_MEMBERS
    for idx, ep in enumerate(extra_files, start=1):
        arc_name = f"attachments/{idx:02d}_{ep.name}"
        if arc_name in used_names:
            arc_name = f"attachments/{idx:02d}_{uuid.uuid4().hex[:6]}_{ep.name}"
        used_names.add(arc_name)
        staged_artifacts.append((ep, "supporting_attachment", arc_name))

    artifacts_manifest = [
        build_artifact_entry(src_path, role, arc_name)
        for src_path, role, arc_name in staged_artifacts
    ]

    created_utc = datetime.now(timezone.utc).isoformat()
    bundle_id = str(uuid.uuid4())

    manifest = {
        "bundle_metadata": {
            "schema_version": SCHEMA_VERSION,
            "bundle_id": bundle_id,
            "case_id": case_id,
            "notes": notes,
            "created_at_utc": created_utc,
            "generator": "HAI LAB Forensic Bundle Tool",
            "execution_scope": "Linux x86_64 user-space | Phase 5 Scope B | LAB / DEMO",
        },
        "telemetry_snapshot": extract_telemetry_summary(report_data),
        "artifacts": artifacts_manifest,
        "signature_info": {
            "algorithm": "Ed25519",
            "signed_target": "manifest.json",
            "domain_binding": "HAILAB_FORENSIC_BUNDLE_V1",
            "public_key_sha256": pub_fingerprint,
        },
    }

    canonical_manifest = canonicalize_manifest(manifest)
    signing_payload = build_signing_payload(manifest)
    signature_b64 = base64.b64encode(priv_key.sign(signing_payload)).decode("ascii")
    sig_payload = {
        "algorithm": "Ed25519",
        "domain_binding": "HAILAB_FORENSIC_BUNDLE_V1",
        "public_key_sha256": pub_fingerprint,
        "signature_base64": signature_b64,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_file = out_dir / f"forensic_bundle_{stamp}_{bundle_id[:8]}.tar.gz"
    pub_pem_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        m_file = tmp_path / "manifest.json"
        s_file = tmp_path / "manifest.sig.json"
        k_file = tmp_path / "signer_public.pem"

        m_file.write_bytes(canonical_manifest + b"\n")
        s_file.write_text(json.dumps(sig_payload, indent=2) + "\n", encoding="utf-8")
        k_file.write_bytes(pub_pem_bytes)

        with tarfile.open(bundle_file, "w:gz") as tar:
            for src_path, _, arc_name in staged_artifacts:
                tar.add(src_path, arcname=arc_name)
            tar.add(m_file, arcname="manifest.json")
            tar.add(s_file, arcname="manifest.sig.json")
            tar.add(k_file, arcname="signer_public.pem")

    return {
        "created_bundle": str(bundle_file),
        "bundle_id": bundle_id,
        "bundle_sha256": sha256_file(bundle_file),
        "public_key_sha256": pub_fingerprint,
        "artifacts_count": len(artifacts_manifest),
    }


def verify_bundle(
    bundle_file: Path,
    trusted_pub_key_path: Path | None = None,
    extract_to: Path | None = None,
    ledger_path: Path | None = None,
) -> dict:
    checks: dict[str, bool] = {
        "archive_extraction": False,
        "manifest_schema": False,
        "trusted_key": False,
        "signature": False,
        "artifacts_integrity": False,
        "archive_allowlist": False,
        "semantic_telemetry": False,
    }

    def _finalize(payload: dict) -> dict:
        if ledger_path is not None:
            payload["ledger_entry_sha256"] = append_verification_ledger(
                ledger_path=ledger_path,
                bundle_file=bundle_file,
                verify_result=payload,
            )
        return payload

    if not bundle_file.exists():
        return _finalize({"valid": False, "reason": f"Bundle not found: {bundle_file}", "checks": checks})

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        try:
            with tarfile.open(bundle_file, "r:gz") as tar:
                archive_files = _safe_extract_tar(tar, tmp_path)
            checks["archive_extraction"] = True
        except Exception as exc:
            return _finalize(
                {"valid": False, "reason": f"Archive extraction rejected: {exc}", "checks": checks}
            )

        m_path = tmp_path / "manifest.json"
        s_path = tmp_path / "manifest.sig.json"
        k_path = tmp_path / "signer_public.pem"

        for req in (m_path, s_path, k_path):
            if not req.exists():
                return _finalize(
                    {"valid": False, "reason": f"Missing {req.name} in bundle", "checks": checks}
                )

        try:
            manifest_bytes = m_path.read_bytes().strip()
            manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
        except Exception as exc:
            return _finalize(
                {"valid": False, "reason": f"Invalid manifest JSON: {exc}", "checks": checks}
            )

        schema_ok, schema_msg = _validate_manifest_structure(manifest_obj)
        checks["manifest_schema"] = schema_ok
        if not schema_ok:
            return _finalize({"valid": False, "reason": schema_msg, "checks": checks})

        try:
            bundled_pub = load_public_key(k_path)
        except Exception as exc:
            return _finalize(
                {"valid": False, "reason": f"Invalid bundled public key: {exc}", "checks": checks}
            )

        bundled_fp = public_key_fingerprint(bundled_pub)

        if trusted_pub_key_path is not None:
            try:
                trusted_pub = load_public_key(trusted_pub_key_path)
            except Exception as exc:
                return _finalize(
                    {"valid": False, "reason": f"Invalid trusted public key: {exc}", "checks": checks}
                )
            trusted_fp = public_key_fingerprint(trusted_pub)
            if bundled_fp != trusted_fp:
                return _finalize(
                    {
                        "valid": False,
                        "reason": "Bundled public key does not match trusted public key",
                        "bundled_public_key_sha256": bundled_fp,
                        "trusted_public_key_sha256": trusted_fp,
                        "checks": checks,
                    }
                )
            verifier_key = trusted_pub
        else:
            verifier_key = bundled_pub
        checks["trusted_key"] = True

        try:
            sig_obj = json.loads(s_path.read_text(encoding="utf-8"))
            if sig_obj.get("algorithm") != "Ed25519":
                return _finalize(
                    {"valid": False, "reason": "Unsupported signature algorithm", "checks": checks}
                )
            if sig_obj.get("public_key_sha256") != bundled_fp:
                return _finalize(
                    {
                        "valid": False,
                        "reason": "Public key fingerprint mismatch in signature metadata",
                        "checks": checks,
                    }
                )
            if manifest_obj.get("signature_info", {}).get("public_key_sha256") != bundled_fp:
                return _finalize(
                    {
                        "valid": False,
                        "reason": "Public key fingerprint mismatch in manifest",
                        "checks": checks,
                    }
                )

            sig_raw = base64.b64decode(sig_obj["signature_base64"], validate=True)
            signing_payload = build_signing_payload(manifest_obj)
            verifier_key.verify(sig_raw, signing_payload)
            checks["signature"] = True
        except Exception as exc:
            return _finalize(
                {
                    "valid": False,
                    "reason": f"Signature or manifest verification failed: {exc}",
                    "checks": checks,
                }
            )

        verified_items = []
        manifest_members: set[str] = set()
        for item in manifest_obj.get("artifacts", []):
            member_name = item.get("archive_member", "")
            if not _is_safe_member_name(member_name):
                return _finalize(
                    {
                        "valid": False,
                        "reason": f"Unsafe artifact path in manifest: {member_name}",
                        "checks": checks,
                    }
                )
            manifest_members.add(member_name)
            member_path = tmp_path / member_name
            if not member_path.exists() or not member_path.is_file():
                return _finalize(
                    {
                        "valid": False,
                        "reason": f"Missing artifact member: {member_name}",
                        "checks": checks,
                    }
                )

            actual_size = member_path.stat().st_size
            actual_sha = sha256_file(member_path)
            if actual_size != item.get("size_bytes") or actual_sha != item.get("sha256"):
                return _finalize(
                    {
                        "valid": False,
                        "reason": f"Artifact integrity mismatch in {member_name}",
                        "checks": checks,
                    }
                )
            verified_items.append(
                {
                    "archive_member": member_name,
                    "role": item.get("role"),
                    "size_bytes": actual_size,
                    "sha256": actual_sha,
                }
            )
        checks["artifacts_integrity"] = True

        expected_members = manifest_members | RESERVED_MEMBERS
        unexpected_members = sorted(archive_files - expected_members)
        if unexpected_members:
            return _finalize(
                {
                    "valid": False,
                    "reason": f"Unexpected files in bundle outside manifest: {', '.join(unexpected_members)}",
                    "checks": checks,
                }
            )
        checks["archive_allowlist"] = True

        semantic_ok, semantic_msg = _verify_semantic_and_cross_artifact(
            manifest_obj=manifest_obj,
            companion_report_path=tmp_path / "companion_report.json",
            blackbox_path=tmp_path / "hailab_forensic_blackbox.enc",
            audit_log_path=tmp_path / "hailab_secure_audit.log",
        )
        checks["semantic_telemetry"] = semantic_ok
        if not semantic_ok:
            return _finalize({"valid": False, "reason": semantic_msg, "checks": checks})

        extracted_dir_str = None
        if extract_to is not None:
            extract_to.mkdir(parents=True, exist_ok=True)
            for rel_name in sorted(expected_members):
                src_file = tmp_path / rel_name
                dst_file = extract_to / rel_name
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dst_file)
            extracted_dir_str = str(extract_to.resolve())

        meta = manifest_obj.get("bundle_metadata", {})
        return _finalize(
            {
                "valid": True,
                "schema_version": meta.get("schema_version"),
                "bundle_id": meta.get("bundle_id"),
                "case_id": meta.get("case_id"),
                "created_at_utc": meta.get("created_at_utc"),
                "public_key_sha256": bundled_fp,
                "trusted_key_enforced": trusted_pub_key_path is not None,
                "checks": checks,
                "verified_artifacts": verified_items,
                "extracted_to": extracted_dir_str,
            }
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create and independently verify signed forensic evidence bundles."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate a new Ed25519 signing keypair")
    p_keygen.add_argument("--priv-key", type=Path, default=Path("keys/forensic_ed25519.key"))
    p_keygen.add_argument("--pub-key", type=Path, default=Path("keys/forensic_ed25519.pub"))
    p_keygen.add_argument("--passphrase-env", type=str, default="FORENSIC_KEY_PASSPHRASE")
    p_keygen.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing signing keypair if already present",
    )

    p_create = sub.add_parser("create", help="Create a signed forensic bundle")
    p_create.add_argument("--report", type=Path, default=Path("reports/companion_report.json"))
    p_create.add_argument("--blackbox", type=Path, default=Path("hailab_forensic_blackbox.enc"))
    p_create.add_argument("--audit-log", type=Path, default=Path("hailab_secure_audit.log"))
    p_create.add_argument("--extra", type=Path, nargs="*", default=[], help="Additional files to include")
    p_create.add_argument("--out-dir", type=Path, default=Path("reports/bundles"))
    p_create.add_argument("--priv-key", type=Path, default=Path("keys/forensic_ed25519.key"))
    p_create.add_argument("--pub-key", type=Path, default=Path("keys/forensic_ed25519.pub"))
    p_create.add_argument("--passphrase-env", type=str, default="FORENSIC_KEY_PASSPHRASE")
    p_create.add_argument("--case-id", type=str, default=None)
    p_create.add_argument("--notes", type=str, default=None)

    p_verify = sub.add_parser("verify", help="Verify a signed forensic bundle")
    p_verify.add_argument("bundle", type=Path)
    p_verify.add_argument(
        "--trusted-pub-key",
        type=Path,
        default=None,
        help="Optional external public key PEM to enforce signer identity",
    )
    p_verify.add_argument(
        "--extract-to",
        type=Path,
        default=None,
        help="Optional output directory after successful verification",
    )
    p_verify.add_argument(
        "--ledger-out",
        type=Path,
        default=None,
        help="Optional hash-chained JSONL ledger file path to record verification events",
    )

    args = parser.parse_args()

    try:
        if args.cmd == "keygen":
            passphrase = os.environ.get(args.passphrase_env) if args.passphrase_env else None
            _, pub = generate_keypair(
                args.priv_key,
                args.pub_key,
                passphrase=passphrase,
                force=args.force,
            )
            print(
                json.dumps(
                    {
                        "generated": True,
                        "private_key": str(args.priv_key),
                        "public_key": str(args.pub_key),
                        "public_key_sha256": public_key_fingerprint(pub),
                    },
                    indent=2,
                )
            )
            sys.exit(0)

        elif args.cmd == "create":
            passphrase = os.environ.get(args.passphrase_env) if args.passphrase_env else None
            out = create_bundle(
                report_path=args.report,
                blackbox_path=args.blackbox,
                audit_log_path=args.audit_log,
                out_dir=args.out_dir,
                priv_key_path=args.priv_key,
                pub_key_path=args.pub_key,
                extra_files=args.extra,
                passphrase=passphrase,
                case_id=args.case_id,
                notes=args.notes,
            )
            print(json.dumps(out, indent=2))
            sys.exit(0)

        elif args.cmd == "verify":
            res = verify_bundle(
                bundle_file=args.bundle,
                trusted_pub_key_path=args.trusted_pub_key,
                extract_to=args.extract_to,
                ledger_path=args.ledger_out,
            )
            print(json.dumps(res, indent=2))
            sys.exit(0 if res.get("valid") else 1)

    except Exception as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
