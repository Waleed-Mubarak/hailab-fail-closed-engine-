from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any, Iterator
import uuid

_FIELD_SEP = "\x1f"


class DestructionReason(str, Enum):
    EXPIRED = "expired"
    TEMPORAL_JITTER = "temporal_jitter"
    EXPLICIT_BURN = "explicit_burn"
    TAMPER_DETECTED = "tamper_detected"
    ALREADY_DESTROYED = "already_destroyed"


class EphemeralStateError(RuntimeError):
    """Raised when access is denied or state has self-destructed (fail-closed)."""


@dataclass(frozen=True)
class DestructionProofRecord:
    seq: int
    lease_id: str
    reason: DestructionReason
    observed_at_ns: int
    age_ns: int
    access_count: int
    pre_wipe_digest_hex: str
    prev_proof_hash_hex: str
    proof_hash_hex: str
    witness_hmac_hex: str

    def to_canonical_json(self) -> str:
        payload = {
            "seq": self.seq,
            "lease_id": self.lease_id,
            "reason": self.reason.value,
            "observed_at_ns": self.observed_at_ns,
            "age_ns": self.age_ns,
            "access_count": self.access_count,
            "pre_wipe_digest_hex": self.pre_wipe_digest_hex,
            "prev_proof_hash_hex": self.prev_proof_hash_hex,
            "witness_hmac_hex": self.witness_hmac_hex,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class RefusalProofLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self, witness_key: bytes | None = None, domain: str = "HAILAB_REFUSAL_PROOF_V1") -> None:
        self._lock = threading.Lock()
        self._domain = domain.encode("utf-8")
        self._witness_key: bytes = bytes(witness_key) if witness_key else b""
        self._records: list[DestructionProofRecord] = []
        self._head_hash: str = self.GENESIS_HASH

    @staticmethod
    def _encode_core_msg(
        *,
        seq: int,
        lease_id: str,
        reason: DestructionReason,
        observed_at_ns: int,
        age_ns: int,
        access_count: int,
        pre_wipe_digest_hex: str,
        prev_hash: str,
    ) -> bytes:
        return _FIELD_SEP.join(
            (
                str(seq),
                lease_id,
                reason.value,
                str(observed_at_ns),
                str(age_ns),
                str(access_count),
                pre_wipe_digest_hex,
                prev_hash,
            )
        ).encode("utf-8")

    @property
    def head_hash(self) -> str:
        with self._lock:
            return self._head_hash

    @property
    def is_signed(self) -> bool:
        with self._lock:
            return bool(self._witness_key)

    def records(self) -> tuple[DestructionProofRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def append_proof(
        self,
        *,
        lease_id: str,
        reason: DestructionReason,
        observed_at_ns: int,
        age_ns: int,
        access_count: int,
        pre_wipe_digest_hex: str,
    ) -> DestructionProofRecord:
        with self._lock:
            seq = len(self._records) + 1
            prev_hash = self._head_hash
            safe_age_ns = max(0, age_ns)
            safe_access_count = max(0, access_count)

            core_msg = self._encode_core_msg(
                seq=seq,
                lease_id=lease_id,
                reason=reason,
                observed_at_ns=observed_at_ns,
                age_ns=safe_age_ns,
                access_count=safe_access_count,
                pre_wipe_digest_hex=pre_wipe_digest_hex,
                prev_hash=prev_hash,
            )

            if self._witness_key:
                mac_hex = hmac.new(
                    self._witness_key,
                    self._domain + b"\x00" + core_msg,
                    hashlib.sha256,
                ).hexdigest()
            else:
                mac_hex = "UNSIGNED_LOCAL_CHAIN"

            proof_hash_hex = hashlib.sha256(
                self._domain + b"\x00" + core_msg + b"\x00" + mac_hex.encode("utf-8")
            ).hexdigest()

            rec = DestructionProofRecord(
                seq=seq,
                lease_id=lease_id,
                reason=reason,
                observed_at_ns=observed_at_ns,
                age_ns=safe_age_ns,
                access_count=safe_access_count,
                pre_wipe_digest_hex=pre_wipe_digest_hex,
                prev_proof_hash_hex=prev_hash,
                proof_hash_hex=proof_hash_hex,
                witness_hmac_hex=mac_hex,
            )
            self._records.append(rec)
            self._head_hash = proof_hash_hex
            return rec

    @classmethod
    def verify_chain(
        cls,
        records: list[DestructionProofRecord] | tuple[DestructionProofRecord, ...],
        *,
        witness_key: bytes | None = None,
        domain: str = "HAILAB_REFUSAL_PROOF_V1",
    ) -> tuple[bool, str]:
        dom_bytes = domain.encode("utf-8")
        expected_prev = cls.GENESIS_HASH
        expected_seq = 1

        for rec in records:
            if rec.seq != expected_seq:
                return False, f"Sequence mismatch at index {expected_seq}: got {rec.seq}"
            if rec.prev_proof_hash_hex != expected_prev:
                return False, f"Broken chain link at seq {rec.seq}"

            core_msg = cls._encode_core_msg(
                seq=rec.seq,
                lease_id=rec.lease_id,
                reason=rec.reason,
                observed_at_ns=rec.observed_at_ns,
                age_ns=rec.age_ns,
                access_count=rec.access_count,
                pre_wipe_digest_hex=rec.pre_wipe_digest_hex,
                prev_hash=rec.prev_proof_hash_hex,
            )

            if witness_key:
                expected_mac = hmac.new(
                    witness_key,
                    dom_bytes + b"\x00" + core_msg,
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(rec.witness_hmac_hex, expected_mac):
                    return False, f"HMAC mismatch at seq {rec.seq}"

            recomputed_hash = hashlib.sha256(
                dom_bytes + b"\x00" + core_msg + b"\x00" + rec.witness_hmac_hex.encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(rec.proof_hash_hex, recomputed_hash):
                return False, f"Proof hash mismatch at seq {rec.seq}"

            expected_prev = rec.proof_hash_hex
            expected_seq += 1

        return True, "OK"

    def to_jsonl(self) -> str:
        with self._lock:
            lines = []
            for r in self._records:
                d = asdict(r)
                d["reason"] = r.reason.value
                lines.append(json.dumps(d, sort_keys=True))
            return "\n".join(lines) + ("\n" if lines else "")

    def build_summary(self, *, witness_key: bytes | None = None) -> dict[str, Any]:
        with self._lock:
            recs = tuple(self._records)
            head_hash = self._head_hash
            effective_key = bytes(witness_key) if witness_key is not None else self._witness_key
            signed = bool(effective_key)
        verified, status = self.verify_chain(recs, witness_key=effective_key or None)
        jsonl_bytes = self.to_jsonl().encode("utf-8")
        return {
            "schema": "hailab.ephemeral_refusal_evidence.v1",
            "signed": signed,
            "verified": verified,
            "status": status,
            "record_count": len(recs),
            "head_hash_hex": head_hash,
            "jsonl_sha256": hashlib.sha256(jsonl_bytes).hexdigest(),
        }


class EphemeralSecretLease:
    def __init__(
        self,
        secret_bytes: bytes | bytearray,
        *,
        lease_id: str | None = None,
        lease_ttl_ms: float = 250.0,
        max_jitter_ms: float = 50.0,
        overwrite_passes: int = 3,
        proof_ledger: RefusalProofLedger | None = None,
    ) -> None:
        if not secret_bytes:
            raise ValueError("secret_bytes must not be empty")
        if lease_ttl_ms <= 0 or max_jitter_ms <= 0:
            raise ValueError("lease_ttl_ms and max_jitter_ms must be positive")
        if overwrite_passes < 1:
            raise ValueError("overwrite_passes must be at least 1")

        self._lock = threading.Lock()
        self._lease_id: str = lease_id or str(uuid.uuid4())
        self._lease_ttl_ns: int = int(lease_ttl_ms * 1_000_000)
        self._max_jitter_ns: int = int(max_jitter_ms * 1_000_000)
        self._overwrite_passes: int = overwrite_passes
        self._proof_ledger: RefusalProofLedger | None = proof_ledger

        self._buf: bytearray = bytearray(secret_bytes)
        self._baseline_digest: bytes = hashlib.sha256(self._buf).digest()
        self._access_count: int = 0
        self._destroyed: bool = False
        self._last_proof: DestructionProofRecord | None = None

        now_ns = time.perf_counter_ns()
        self._created_ns: int = now_ns
        self._last_touch_ns: int = now_ns

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def is_destroyed(self) -> bool:
        with self._lock:
            return self._destroyed

    @property
    def last_proof(self) -> DestructionProofRecord | None:
        with self._lock:
            return self._last_proof

    @staticmethod
    def _wipe_in_place(target: bytearray, passes: int) -> None:
        size = len(target)
        if size == 0:
            return
        for p in range(passes):
            if p % 2 == 0:
                rnd = os.urandom(size)
                for i in range(size):
                    target[i] = rnd[i]
            else:
                for i in range(size):
                    target[i] ^= 0xFF
        for i in range(size):
            target[i] = 0

    def _check_health_locked(self, now_ns: int) -> DestructionReason | None:
        if now_ns - self._created_ns > self._lease_ttl_ns:
            return DestructionReason.EXPIRED
        if now_ns - self._last_touch_ns > self._max_jitter_ns:
            return DestructionReason.TEMPORAL_JITTER
        if hashlib.sha256(self._buf).digest() != self._baseline_digest:
            return DestructionReason.TAMPER_DETECTED
        return None

    def _burn_locked(
        self,
        reason: DestructionReason,
        now_ns: int,
        *,
        record_to_ledger: bool = True,
    ) -> DestructionProofRecord:
        age_ns = max(0, now_ns - self._created_ns)
        pre_wipe_digest_hex = hashlib.sha256(self._buf).hexdigest()

        self._wipe_in_place(self._buf, self._overwrite_passes)
        self._destroyed = True

        proof: DestructionProofRecord | None = None
        if self._proof_ledger is not None and record_to_ledger:
            proof = self._proof_ledger.append_proof(
                lease_id=self._lease_id,
                reason=reason,
                observed_at_ns=now_ns,
                age_ns=age_ns,
                access_count=self._access_count,
                pre_wipe_digest_hex=pre_wipe_digest_hex,
            )
        elif self._last_proof is not None:
            proof = self._last_proof

        if proof is not None:
            self._last_proof = proof
            return proof

        fallback = DestructionProofRecord(
            seq=1,
            lease_id=self._lease_id,
            reason=reason,
            observed_at_ns=now_ns,
            age_ns=age_ns,
            access_count=self._access_count,
            pre_wipe_digest_hex=pre_wipe_digest_hex,
            prev_proof_hash_hex="0" * 64,
            proof_hash_hex=hashlib.sha256(
                f"{self._lease_id}|{reason.value}|{now_ns}|{pre_wipe_digest_hex}".encode("utf-8")
            ).hexdigest(),
            witness_hmac_hex="UNLEDGERED_BURN",
        )
        self._last_proof = fallback
        return fallback

    def burn(self, reason: DestructionReason = DestructionReason.EXPLICIT_BURN) -> DestructionProofRecord:
        with self._lock:
            now_ns = time.perf_counter_ns()
            if self._destroyed:
                age_ns = max(0, now_ns - self._created_ns)
                pre_wipe_digest_hex = hashlib.sha256(self._buf).hexdigest()
                if self._proof_ledger is not None:
                    proof = self._proof_ledger.append_proof(
                        lease_id=self._lease_id,
                        reason=DestructionReason.ALREADY_DESTROYED,
                        observed_at_ns=now_ns,
                        age_ns=age_ns,
                        access_count=self._access_count,
                        pre_wipe_digest_hex=pre_wipe_digest_hex,
                    )
                    self._last_proof = proof
                    return proof
                assert self._last_proof is not None
                return self._last_proof

            return self._burn_locked(reason, now_ns, record_to_ledger=True)

    @contextmanager
    def acquire(self) -> Iterator[bytearray]:
        with self._lock:
            if self._destroyed:
                now_ns = time.perf_counter_ns()
                age_ns = max(0, now_ns - self._created_ns)
                pre_wipe_digest_hex = hashlib.sha256(self._buf).hexdigest()
                if self._proof_ledger is not None:
                    proof = self._proof_ledger.append_proof(
                        lease_id=self._lease_id,
                        reason=DestructionReason.ALREADY_DESTROYED,
                        observed_at_ns=now_ns,
                        age_ns=age_ns,
                        access_count=self._access_count,
                        pre_wipe_digest_hex=pre_wipe_digest_hex,
                    )
                    self._last_proof = proof
                raise EphemeralStateError("Secret lease already destroyed (fail-closed)")

            now_ns = time.perf_counter_ns()
            violation = self._check_health_locked(now_ns)
            if violation is not None:
                proof = self._burn_locked(violation, now_ns, record_to_ledger=True)
                raise EphemeralStateError(
                    f"Access denied & secret self-destructed: reason={proof.reason.value}, seq={proof.seq}"
                )

            self._access_count += 1
            self._last_touch_ns = now_ns
            view = bytearray(self._buf)

        try:
            yield view
        finally:
            self._wipe_in_place(view, self._overwrite_passes)
            with self._lock:
                self._last_touch_ns = time.perf_counter_ns()
