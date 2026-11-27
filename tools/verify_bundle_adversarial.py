#!/usr/bin/env python3
"""Independent CLI verifier for HAILAB forensic bundles (schema 1.4.0)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tarfile
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA_VERSION = "1.4.0"
DOMAIN_PREFIX = b"HAILAB_FORENSIC_BUNDLE_V1\x00"
RESERVED_MEMBERS = {"manifest.json", "manifest.sig.json", "signer_public.pem"}
MAX_MEMBER_BYTES = 100 * 1024 * 1024
MAX_TOTAL_EXTRACT_BYTES = 250 * 1024 * 1024


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
    sig_info = manifest_obj.get("signature_info", {}) if isinstance(manifest_obj, dict) else {}
    binding_header = json.dumps(
        {
            "domain": "HAILAB_FORENSIC_BUNDLE_V1",
            "schema_version": meta.get("schema_version"),
            "bundle_id": meta.get("bundle_id"),
            "case_id": meta.get("case_id"),
            "public_key_sha256": sig_info.get("public_key_sha256"),
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return DOMAIN_PREFIX + binding_header + b"\x00" + canonicalize_manifest(manifest_obj)


def _normalize_member_name(member_name: str) -> str | None:
    p = Path(member_name)
    if p.is_absolute() or ".." in p.parts:
        return None
    clean_parts = [part for part in p.parts if part not in ("", ".")]
    if not clean_parts:
        return None
    return Path(*clean_parts).as_posix()


def _safe_member_path(base_dir: Path, normalized_name: str) -> Path | None:
    p = Path(normalized_name)
    if p.is_absolute() or ".." in p.parts:
        return None
    resolved = (base_dir / p).resolve()
    try:
        resolved.relative_to(base_dir.resolve())
    except ValueError:
        return None
    return resolved


def verify_ledger_chain(ledger_path: Path, expected_head_sha256: str | None = None) -> tuple[bool, str]:
    if not ledger_path.exists():
        return False, f"Ledger not found: {ledger_path}"

    prev_hash = ""
    entries_count = 0
    last_entry_hash = ""

    with ledger_path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                return False, f"Invalid JSON at ledger line {line_no}: {exc}"

            if not isinstance(entry, dict):
                return False, f"Ledger entry at line {line_no} is not an object"

            recorded_prev = entry.get("prev_entry_sha256", entry.get("prev_hash", ""))
            if entries_count > 0 and prev_hash and recorded_prev and recorded_prev != prev_hash:
                return False, f"Chain break at line {line_no}"

            entry_hash = entry.get("entry_sha256") or entry.get("sha256")
            if not isinstance(entry_hash, str) or not entry_hash.strip():
                return False, f"Missing entry hash at ledger line {line_no}"

            prev_hash = entry_hash
            last_entry_hash = entry_hash
            entries_count += 1

    if entries_count == 0:
        return False, "Ledger is empty"

    if expected_head_sha256 and last_entry_hash != expected_head_sha256:
        return False, f"Head hash mismatch: expected {expected_head_sha256}, got {last_entry_hash}"

    return True, f"OK ({entries_count} entries)"


def verify_independent(bundle_path: Path, trusted_pub_key_path: Path, ledger_path: Path | None = None) -> dict:
    checks = {
        "archive_extraction": False,
        "manifest_schema": False,
        "trusted_key": False,
        "signature": False,
        "artifacts_integrity": False,
        "archive_allowlist": False,
        "semantic_telemetry": False,
    }
    errors: list[str] = []

    if not bundle_path.exists():
        return {"valid": False, "checks": checks, "errors": [f"Bundle not found: {bundle_path}"]}

    if not trusted_pub_key_path.exists():
        return {"valid": False, "checks": checks, "errors": [f"Trusted public key not found: {trusted_pub_key_path}"]}

    try:
        trusted_pub_bytes = trusted_pub_key_path.read_bytes()
        trusted_pub_key = serialization.load_pem_public_key(trusted_pub_bytes)
        if not isinstance(trusted_pub_key, Ed25519PublicKey):
            errors.append("Trusted key is not Ed25519")
            return {"valid": False, "checks": checks, "errors": errors}
        trusted_pub_fp = sha256_bytes(trusted_pub_bytes)
        checks["trusted_key"] = True
    except Exception as exc:
        errors.append(f"Failed to load trusted public key: {exc}")
        return {"valid": False, "checks": checks, "errors": errors}

    with tempfile.TemporaryDirectory(prefix="hailab_verify_") as tmp:
        tmp_dir = Path(tmp)
        total_bytes = 0
        extracted_members: set[str] = set()

        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise ValueError(f"Unsupported archive member type: {member.name}")
                    if member.size > MAX_MEMBER_BYTES:
                        raise ValueError(f"Member exceeds max size: {member.name}")
                    total_bytes += member.size
                    if total_bytes > MAX_TOTAL_EXTRACT_BYTES:
                        raise ValueError("Archive exceeds total extraction limit")

                    norm_name = _normalize_member_name(member.name)
                    if norm_name is None:
                        raise ValueError(f"Unsafe or invalid member path: {member.name}")

                    dest = _safe_member_path(tmp_dir, norm_name)
                    if dest is None:
                        raise ValueError(f"Unsafe member path: {member.name}")

                    dest.parent.mkdir(parents=True, exist_ok=True)
                    src_f = tar.extractfile(member)
                    if src_f is None:
                        raise ValueError(f"Cannot extract member: {member.name}")
                    with src_f, dest.open("wb") as out_f:
                        out_f.write(src_f.read())
                    extracted_members.add(norm_name)

            checks["archive_extraction"] = True
        except Exception as exc:
            errors.append(f"Archive extraction failed: {exc}")
            return {"valid": False, "checks": checks, "errors": errors}

        required_files = {"manifest.json", "manifest.sig.json", "signer_public.pem"}
        if not required_files.issubset(extracted_members):
            missing = sorted(required_files - extracted_members)
            errors.append(f"Missing required bundle members: {missing}")
            return {"valid": False, "checks": checks, "errors": errors}

        try:
            manifest_obj = json.loads((tmp_dir / "manifest.json").read_text(encoding="utf-8"))
            sig_obj = json.loads((tmp_dir / "manifest.sig.json").read_text(encoding="utf-8"))
            embedded_pub_bytes = (tmp_dir / "signer_public.pem").read_bytes()
            embedded_pub_fp = sha256_bytes(embedded_pub_bytes)

            meta = manifest_obj.get("bundle_metadata", {})
            if meta.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(f"Unsupported schema_version: {meta.get('schema_version')}")
            if not isinstance(manifest_obj.get("artifacts"), list):
                raise ValueError("Manifest artifacts must be a list")

            checks["manifest_schema"] = True
        except Exception as exc:
            errors.append(f"Manifest schema invalid: {exc}")
            return {"valid": False, "checks": checks, "errors": errors}

        sig_info = manifest_obj.get("signature_info", {})
        declared_fp = sig_info.get("public_key_sha256")
        if declared_fp != trusted_pub_fp or embedded_pub_fp != trusted_pub_fp:
            errors.append("Signer public key fingerprint does not match trusted public key")
            return {"valid": False, "checks": checks, "errors": errors}

        try:
            sig_b64 = sig_obj.get("signature_b64") or sig_obj.get("signature")
            if not sig_b64:
                raise ValueError("Missing signature field in manifest.sig.json")
            sig_bytes = base64.b64decode(sig_b64, validate=True)
            payload = build_signing_payload(manifest_obj)
            trusted_pub_key.verify(sig_bytes, payload)
            checks["signature"] = True
        except InvalidSignature:
            errors.append("Ed25519 signature verification failed")
            return {"valid": False, "checks": checks, "errors": errors}
        except Exception as exc:
            errors.append(f"Signature check error: {exc}")
            return {"valid": False, "checks": checks, "errors": errors}

        declared_names: set[str] = set()
        for a in manifest_obj.get("artifacts", []):
            if not isinstance(a, dict):
                continue
            raw_name = a.get("archive_member") or a.get("path") or a.get("name")
            if isinstance(raw_name, str):
                norm_art_name = _normalize_member_name(raw_name)
                if norm_art_name:
                    declared_names.add(norm_art_name)

        allowed_members = RESERVED_MEMBERS | declared_names

        if extracted_members.issubset(allowed_members):
            checks["archive_allowlist"] = True
        else:
            unexpected = sorted(extracted_members - allowed_members)
            errors.append(f"Unexpected archive members outside allowlist: {unexpected}")

        artifacts_ok = True
        for art in manifest_obj.get("artifacts", []):
            if not isinstance(art, dict):
                errors.append("Malformed artifact entry: expected JSON object")
                artifacts_ok = False
                continue

            raw_member_name = art.get("archive_member") or art.get("path") or art.get("name")
            member_name = _normalize_member_name(raw_member_name) if isinstance(raw_member_name, str) else None
            expected_sha = art.get("sha256")

            if not member_name or member_name not in extracted_members:
                errors.append(f"Declared artifact missing from archive: {raw_member_name}")
                artifacts_ok = False
                continue

            if not isinstance(expected_sha, str) or not expected_sha.strip():
                errors.append(f"Missing expected SHA-256 digest for {member_name}")
                artifacts_ok = False
                continue

            actual_sha = sha256_file(tmp_dir / member_name)
            if actual_sha != expected_sha.strip().lower():
                errors.append(f"SHA-256 mismatch for {member_name}")
                artifacts_ok = False
        checks["artifacts_integrity"] = artifacts_ok

        telemetry_ok = bool(meta.get("bundle_id")) and bool(meta.get("case_id")) and len(manifest_obj.get("artifacts", [])) > 0
        checks["semantic_telemetry"] = telemetry_ok
        if not telemetry_ok:
            errors.append("Missing required semantic metadata or empty artifacts list")

        ledger_status = None
        if ledger_path is not None:
            ok_ledger, ledger_msg = verify_ledger_chain(ledger_path)
            ledger_status = {"ok": ok_ledger, "detail": ledger_msg}
            if not ok_ledger:
                errors.append(f"Ledger verification failed: {ledger_msg}")

        all_passed = all(checks.values()) and (ledger_status is None or ledger_status["ok"]) and not errors
        return {
            "valid": all_passed,
            "bundle_id": meta.get("bundle_id"),
            "case_id": meta.get("case_id"),
            "trusted_key_sha256": trusted_pub_fp,
            "checks": checks,
            "ledger": ledger_status,
            "errors": errors,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent Verifier CLI for HAILAB forensic bundles.")
    parser.add_argument("bundle", type=Path, help="Path to forensic_bundle_*.tar.gz")
    parser.add_argument("--trusted-pub-key", type=Path, required=True, help="Path to trusted Ed25519 public key (.pub)")
    parser.add_argument("--ledger", type=Path, default=None, help="Optional path to verification_ledger.jsonl")
    args = parser.parse_args()

    result = verify_independent(
        bundle_path=args.bundle,
        trusted_pub_key_path=args.trusted_pub_key,
        ledger_path=args.ledger,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())

