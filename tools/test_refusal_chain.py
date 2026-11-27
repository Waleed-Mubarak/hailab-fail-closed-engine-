from __future__ import annotations

from dataclasses import replace
import os
import threading
import time
import unittest

from src.ephemeral_state.refusal_chain import (
    DestructionReason,
    RefusalProofLedger,
)
from src.ephemeral_state.temporal_vault import (
    EphemeralSecretLease,
    EphemeralStateError,
)


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


if __name__ == "__main__":
    unittest.main()
