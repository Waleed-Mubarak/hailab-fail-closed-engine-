from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import hmac
import json
import threading
from typing import Any


class DestructionReason(str, Enum):
    EXPIRED = "expired"
    TEMPORAL_JITTER = "temporal_jitter"
    EXPLICIT_BURN = "explicit_burn"
    TAMPER_DETECTED = "tamper_detected"
    ALREADY_DESTROYED = "already_destroyed"


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


class RefusalProofLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self, witness_key: bytes | None = None, domain: str = "HAILAB_REFUSAL_PROOF_V1") -> None:
        self._lock = threading.Lock()
        self._domain = domain.encode("utf-8")
        self._witness_key = bytes(witness_key) if witness_key else b""
        self._records: list[DestructionProofRecord] = []
        self._head_hash = self.GENESIS_HASH

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
            msg = (
                f"{seq}|{lease_id}|{reason.value}|{observed_at_ns}|"
                f"{age_ns}|{access_count}|{pre_wipe_digest_hex}|{prev_hash}"
            ).encode("utf-8")
            mac_hex = (
                hmac.new(self._witness_key, self._domain + b"\x00" + msg, hashlib.sha256).hexdigest()
                if self._witness_key
                else "UNSIGNED_LOCAL_CHAIN"
            )
            proof_hash = hashlib.sha256(
                self._domain + b"\x00" + msg + b"\x00" + mac_hex.encode("utf-8")
            ).hexdigest()
            rec = DestructionProofRecord(
                seq=seq,
                lease_id=lease_id,
                reason=reason,
                observed_at_ns=observed_at_ns,
                age_ns=max(0, age_ns),
                access_count=max(0, access_count),
                pre_wipe_digest_hex=pre_wipe_digest_hex,
                prev_proof_hash_hex=prev_hash,
                proof_hash_hex=proof_hash,
                witness_hmac_hex=mac_hex,
            )
            self._records.append(rec)
            self._head_hash = proof_hash
            return rec

    def to_jsonl(self) -> str:
        with self._lock:
            lines = []
            for r in self._records:
                d = asdict(r)
                d["reason"] = r.reason.value
                lines.append(json.dumps(d, sort_keys=True))
            return "\n".join(lines) + ("\n" if lines else "")

    def build_summary(self) -> dict[str, Any]:
        jsonl_bytes = self.to_jsonl().encode("utf-8")
        return {
            "schema": "hailab.ephemeral_refusal_evidence.v1",
            "record_count": len(self._records),
            "head_hash_hex": self._head_hash,
            "jsonl_sha256": hashlib.sha256(jsonl_bytes).hexdigest(),
        }

