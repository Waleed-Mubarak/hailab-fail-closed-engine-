from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from tools.ephemeral_evidence import (
    DestructionReason,
    EphemeralSecretLease,
    EphemeralStateError,
    RefusalProofLedger,
)
from tools.ephemeral_forensic_ledger import (
    build_ephemeral_forensic_payload,
    write_ephemeral_forensic_artifact,
)
from tools.forensic_bundle import create_bundle, verify_bundle
from tools.forensic_ledger import append_ephemeral_refusal_to_ledger, verify_ledger_chain


class TestRefusalChainAdversarial(unittest.TestCase):
    def setUp(self) -> None:
        self.witness_key = os.urandom(32)
        self.ledger = RefusalProofLedger(witness_key=self.witness_key)

    def test_expired_lease_self_destructs_and_records_proof(self) -> None:
        lease = EphemeralSecretLease(
            b"super-secret-key-material",
            lease_id="lease-exp-01",
            lease_ttl_ms=15.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        time.sleep(0.025)

        with self.assertRaises(EphemeralStateError):
            with lease.acquire():
                pass

        self.assertTrue(lease.is_destroyed)
        recs = self.ledger.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].lease_id, "lease-exp-01")
        self.assertEqual(recs[0].reason, DestructionReason.EXPIRED)

        ok, msg = RefusalProofLedger.verify_chain(recs, witness_key=self.witness_key)
        self.assertTrue(ok, msg)

    def test_temporal_jitter_violation_triggers_fail_closed_burn(self) -> None:
        lease = EphemeralSecretLease(
            b"jitter-sensitive-secret",
            lease_id="lease-jit-01",
            lease_ttl_ms=1000.0,
            max_jitter_ms=10.0,
            proof_ledger=self.ledger,
        )
        time.sleep(0.020)

        with self.assertRaises(EphemeralStateError):
            with lease.acquire():
                pass

        self.assertTrue(lease.is_destroyed)
        recs = self.ledger.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].reason, DestructionReason.TEMPORAL_JITTER)

        ok, msg = RefusalProofLedger.verify_chain(recs, witness_key=self.witness_key)
        self.assertTrue(ok, msg)

    def test_in_memory_tamper_detected_and_wiped(self) -> None:
        lease = EphemeralSecretLease(
            b"untampered-secret-bytes",
            lease_id="lease-tmp-01",
            lease_ttl_ms=1000.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease._buf[0] ^= 0x01  # type: ignore[attr-defined]

        with self.assertRaises(EphemeralStateError):
            with lease.acquire():
                pass

        self.assertTrue(lease.is_destroyed)
        self.assertTrue(all(b == 0 for b in lease._buf))  # type: ignore[attr-defined]
        recs = self.ledger.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].reason, DestructionReason.TAMPER_DETECTED)

        ok, msg = RefusalProofLedger.verify_chain(recs, witness_key=self.witness_key)
        self.assertTrue(ok, msg)

    def test_post_destruction_access_refused_and_logged(self) -> None:
        lease = EphemeralSecretLease(
            b"short-lived-secret",
            lease_id="lease-post-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        first_proof = lease.burn(DestructionReason.EXPLICIT_BURN)
        self.assertEqual(first_proof.reason, DestructionReason.EXPLICIT_BURN)
        self.assertTrue(all(b == 0 for b in lease._buf))  # type: ignore[attr-defined]

        with self.assertRaises(EphemeralStateError):
            with lease.acquire():
                pass

        second_proof = lease.burn(DestructionReason.EXPLICIT_BURN)
        self.assertEqual(second_proof.reason, DestructionReason.ALREADY_DESTROYED)

        recs = self.ledger.records()
        self.assertEqual(len(recs), 3)
        ok, msg = RefusalProofLedger.verify_chain(recs, witness_key=self.witness_key)
        self.assertTrue(ok, msg)

    def test_ledger_tamper_detection_fails_closed(self) -> None:
        lease = EphemeralSecretLease(
            b"chain-integrity-secret",
            lease_id="lease-chn-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease.burn(DestructionReason.EXPLICIT_BURN)

        recs = list(self.ledger.records())
        tampered = [replace(recs[0], access_count=recs[0].access_count + 99)]

        ok, _ = RefusalProofLedger.verify_chain(tampered, witness_key=self.witness_key)
        self.assertFalse(ok)

    def test_concurrent_acquire_and_burn_race_safety(self) -> None:
        lease = EphemeralSecretLease(
            b"concurrent-secret-payload",
            lease_id="lease-race-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for _ in range(15):
                    try:
                        with lease.acquire() as view:
                            _ = bytes(view)
                    except EphemeralStateError:
                        pass
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        burner = threading.Thread(target=lambda: lease.burn(DestructionReason.EXPLICIT_BURN))
        threads = [threading.Thread(target=worker) for _ in range(4)]

        for t in threads:
            t.start()
        burner.start()
        for t in threads:
            t.join()
        burner.join()

        self.assertEqual(errors, [])
        self.assertTrue(lease.is_destroyed)
        ok, msg = RefusalProofLedger.verify_chain(
            self.ledger.records(), witness_key=self.witness_key
        )
        self.assertTrue(ok, msg)

    def test_ephemeral_view_is_wiped_on_context_exit(self) -> None:
        lease = EphemeralSecretLease(
            b"ephemeral-view-secret",
            lease_id="lease-view-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )

        with lease.acquire() as view:
            view[0] ^= 0xAA
            self.assertNotEqual(bytes(view), b"ephemeral-view-secret")

        # After exiting `acquire()`, the temporary view buffer must be zeroed
        self.assertTrue(all(b == 0 for b in view))
        # Underlying lease remains intact and uncorrupted
        self.assertFalse(lease.is_destroyed)
        with lease.acquire() as check_view:
            self.assertEqual(bytes(check_view), b"ephemeral-view-secret")

    def test_multi_record_chain_tamper_fails_closed(self) -> None:
        lease_a = EphemeralSecretLease(
            b"secret-alpha",
            lease_id="lease-chain-a",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease_b = EphemeralSecretLease(
            b"secret-beta",
            lease_id="lease-chain-b",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )

        lease_a.burn(DestructionReason.EXPLICIT_BURN)
        lease_b.burn(DestructionReason.EXPLICIT_BURN)

        recs = list(self.ledger.records())
        self.assertGreaterEqual(len(recs), 2)

        # Tamper with an earlier record in the chain and verify chain rejection
        tampered_chain = [replace(recs[0], access_count=recs[0].access_count + 1), *recs[1:]]
        ok, _ = RefusalProofLedger.verify_chain(tampered_chain, witness_key=self.witness_key)
        self.assertFalse(ok)

    def test_ephemeral_forensic_payload_and_artifact_write(self) -> None:
        lease = EphemeralSecretLease(
            b"forensic-bridge-secret",
            lease_id="lease-forensic-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease.burn(DestructionReason.EXPLICIT_BURN)

        payload = build_ephemeral_forensic_payload(
            self.ledger,
            witness_key=self.witness_key,
        )
        self.assertEqual(payload["evidence_type"], "ephemeral_refusal_chain")
        self.assertEqual(payload["summary"]["record_count"], 1)
        self.assertTrue(payload["summary"]["verified"])
        self.assertEqual(len(payload["records"]), 1)
        self.assertEqual(payload["records"][0]["lease_id"], "lease-forensic-01")

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "nested" / "ephemeral_refusal_evidence.json"
            written = write_ephemeral_forensic_artifact(
                self.ledger,
                out_path,
                witness_key=self.witness_key,
            )
            self.assertEqual(written, out_path)
            self.assertTrue(out_path.exists())
            loaded = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["summary"]["jsonl_sha256"], payload["summary"]["jsonl_sha256"])
            self.assertEqual(loaded["records"], payload["records"])

    def test_forensic_payload_rejects_wrong_witness_key_and_preserves_jsonl(self) -> None:
        lease = EphemeralSecretLease(
            b"wrong-key-check-secret",
            lease_id="lease-key-check-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease.burn(DestructionReason.EXPLICIT_BURN)

        wrong_key = os.urandom(32)
        payload = build_ephemeral_forensic_payload(
            self.ledger,
            witness_key=wrong_key,
        )
        self.assertFalse(payload["summary"]["verified"])
        self.assertTrue(payload["jsonl"].endswith("\n"))
        self.assertEqual(len(payload["records"]), 1)

    def test_create_and_verify_bundle_with_ephemeral_ledger(self) -> None:
        lease = EphemeralSecretLease(
            b"bundle-ephemeral-secret",
            lease_id="lease-bundle-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease.burn(DestructionReason.EXPLICIT_BURN)

        ephemeral_summary = build_ephemeral_forensic_payload(
            self.ledger,
            witness_key=self.witness_key,
        )["summary"]

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            report_path = base / "companion_report.json"
            blackbox_path = base / "hailab_forensic_blackbox.enc"
            audit_path = base / "hailab_secure_audit.log"
            out_dir = base / "bundles"
            extract_dir = base / "extracted"
            priv_key = base / "keys" / "ed25519.key"
            pub_key = base / "keys" / "ed25519.pub"

            report_payload = {
                "endpoints": {
                    "metrics": {"parsed_metrics": {"status": "ok"}},
                    "forensic_summary": {"data": {"chain": {"status": "ok", "entries": 1}}},
                },
                "diff_from_previous": {},
                "blackbox_verification": {"verified": True, "returncode": 0},
                "ephemeral_refusal_chain": ephemeral_summary,
            }
            report_path.write_text(json.dumps(report_payload), encoding="utf-8")
            blackbox_path.write_bytes(b"encrypted-blackbox-payload")
            audit_path.write_text('{"event":"init"}\n', encoding="utf-8")

            created = create_bundle(
                report_path=report_path,
                blackbox_path=blackbox_path,
                audit_log_path=audit_path,
                out_dir=out_dir,
                priv_key_path=priv_key,
                pub_key_path=pub_key,
                ephemeral_ledger=self.ledger,
                ephemeral_witness_key=self.witness_key,
            )

            verified = verify_bundle(
                Path(created["created_bundle"]),
                trusted_pub_key_path=pub_key,
                extract_to=extract_dir,
            )
            self.assertTrue(verified["valid"])
            self.assertTrue(
                (extract_dir / "attachments" / "ephemeral_refusal_chain.json").exists()
            )
            attached = json.loads(
                (extract_dir / "attachments" / "ephemeral_refusal_chain.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(attached["evidence_type"], "ephemeral_refusal_chain")
            self.assertTrue(attached["summary"]["verified"])

    def test_append_ephemeral_refusal_to_ledger_and_verify_chain(self) -> None:
        lease = EphemeralSecretLease(
            b"ledger-ephemeral-secret",
            lease_id="lease-ledger-01",
            lease_ttl_ms=500.0,
            max_jitter_ms=500.0,
            proof_ledger=self.ledger,
        )
        lease.burn(DestructionReason.EXPLICIT_BURN)

        with tempfile.TemporaryDirectory() as tmp_dir:
            ledger_file = Path(tmp_dir) / "unified_ledger.jsonl"
            entry = append_ephemeral_refusal_to_ledger(
                ledger_file,
                bundle_id="bundle-ephemeral-test",
                refusal_ledger=self.ledger,
                witness_key=self.witness_key,
            )
            self.assertTrue(entry["ok"])
            self.assertEqual(entry["extra"]["record_count"], 1)

            chain_status = verify_ledger_chain(ledger_file)
            self.assertTrue(chain_status["ok"])
            self.assertEqual(chain_status["entries_count"], 1)


if __name__ == "__main__":
    unittest.main()
