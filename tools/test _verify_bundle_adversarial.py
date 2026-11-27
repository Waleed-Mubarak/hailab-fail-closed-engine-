#!/usr/bin/env python3
"""Unit tests for tools/verify_bundle_adversarial.py."""

from __future__ import annotations

import base64
import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tools.verify_bundle_adversarial as verifier


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_bundle(
    work_dir: Path,
    bundle_name: str = "forensic_bundle_test.tar.gz",
    dot_prefix_members: bool = False,
    omit_artifact_sha: bool = False,
    extra_member: tuple[str, bytes] | None = None,
    tamper_artifact: bool = False,
) -> tuple[Path, Path]:
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_fp = _sha256_bytes(pub_pem)

    pub_key_path = work_dir / "trusted_ed25519.pub"
    pub_key_path.write_bytes(pub_pem)

    artifact_bytes = b'{"status": "ok", "events": []}\n'
    if tamper_artifact:
        artifact_bytes = b'{"status": "tampered", "events": []}\n'
    actual_art_sha = _sha256_bytes(artifact_bytes)

    artifact_entry: dict[str, object] = {
        "archive_member": "artifacts/report.json",
        "role": "report",
        "size_bytes": len(artifact_bytes),
    }
    if not omit_artifact_sha:
        artifact_entry["sha256"] = _sha256_bytes(b'{"status": "ok", "events": []}\n')

    manifest_obj = {
        "bundle_metadata": {
            "schema_version": verifier.SCHEMA_VERSION,
            "bundle_id": "bundle-test-001",
            "case_id": "CASE-TEST-001",
        },
        "signature_info": {
            "public_key_sha256": pub_fp,
        },
        "artifacts": [artifact_entry],
    }

    payload = verifier.build_signing_payload(manifest_obj)
    sig_b64 = base64.b64encode(priv_key.sign(payload)).decode("ascii")
    sig_obj = {"signature_b64": sig_b64}

    manifest_bytes = json.dumps(manifest_obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    sig_bytes = json.dumps(sig_obj, sort_keys=True, ensure_ascii=False).encode("utf-8")

    members_payload: dict[str, bytes] = {
        "manifest.json": manifest_bytes,
        "manifest.sig.json": sig_bytes,
        "signer_public.pem": pub_pem,
        "artifacts/report.json": artifact_bytes if not tamper_artifact else b'{"status": "tampered"}\n',
    }
    if extra_member is not None:
        members_payload[extra_member[0]] = extra_member[1]

    bundle_path = work_dir / bundle_name
    with tarfile.open(bundle_path, "w:gz") as tar:
        for name, content in members_payload.items():
            arcname = f"./{name}" if dot_prefix_members else name
            tmp_file = work_dir / f"tmp_{name.replace('/', '_')}"
            tmp_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file.write_bytes(content)
            tar.add(tmp_file, arcname=arcname)

    _ = actual_art_sha
    return bundle_path, pub_key_path


class TestVerifyBundleAdversarial(unittest.TestCase):
    def test_valid_bundle_and_dot_prefix_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            bundle_path, pub_key_path = _build_bundle(work_dir, dot_prefix_members=True)
            res = verifier.verify_independent(bundle_path, pub_key_path)
            self.assertTrue(res["valid"])
            self.assertTrue(all(res["checks"].values()))
            self.assertEqual(res["errors"], [])

    def test_missing_artifact_sha256_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            bundle_path, pub_key_path = _build_bundle(work_dir, omit_artifact_sha=True)
            res = verifier.verify_independent(bundle_path, pub_key_path)
            self.assertFalse(res["valid"])
            self.assertFalse(res["checks"]["artifacts_integrity"])

    def test_unexpected_archive_member_fails_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            bundle_path, pub_key_path = _build_bundle(
                work_dir,
                extra_member=("unexpected/payload.txt", b"unexpected"),
            )
            res = verifier.verify_independent(bundle_path, pub_key_path)
            self.assertFalse(res["valid"])
            self.assertFalse(res["checks"]["archive_allowlist"])

    def test_ledger_chain_detects_break_and_missing_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            ledger_broken = work_dir / "ledger_broken.jsonl"
            e1 = {"entry_sha256": "aaa111", "prev_entry_sha256": ""}
            e2 = {"entry_sha256": "bbb222", "prev_entry_sha256": "wrong_prev"}
            ledger_broken.write_text(
                json.dumps(e1) + "\n" + json.dumps(e2) + "\n",
                encoding="utf-8",
            )
            ok, msg = verifier.verify_ledger_chain(ledger_broken)
            self.assertFalse(ok)
            self.assertIn("Chain break", msg)

            ledger_no_hash = work_dir / "ledger_no_hash.jsonl"
            ledger_no_hash.write_text(json.dumps({"event": "verify"}) + "\n", encoding="utf-8")
            ok2, msg2 = verifier.verify_ledger_chain(ledger_no_hash)
            self.assertFalse(ok2)
            self.assertIn("Missing entry hash", msg2)


if __name__ == "__main__":
    unittest.main()

