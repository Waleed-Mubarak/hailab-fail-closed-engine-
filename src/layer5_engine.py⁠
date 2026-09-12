import hmac
import hashlib
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Layer5_SovereignEngine")

@dataclass
class Layer5Context:
    session_id: str
    node_id: str
    hsm_key_handle: str
    mpa_signatures: list

class Layer5SecureEnforcementEngine:
    def __init__(self, hsm_module_interface: Any):
        self.hsm = hsm_module_interface
        self.active_channels: Dict[str, str] = {}

    def _verify_hardware_binding(self, context: Layer5Context) -> bool:
        logger.info(f"Verifying hardware key handle {context.hsm_key_handle} for node {context.node_id}")
        return self.hsm.validate_handle(context.hsm_key_handle)

    def _enforce_mpa(self, signatures: list) -> bool:
        required_quorum = 2
        valid_signatures = [sig for sig in signatures if self.hsm.verify_signature(sig)]
        return len(valid_signatures) >= required_quorum

    def execute_sovereign_communication(self, context: Layer5Context, payload: dict) -> Dict[str, Any]:
        if not self._verify_hardware_binding(context):
            logger.error(f"FAIL_CLOSED_TRIGGERED: Hardware key verification failed for session {context.session_id}")
            return {"status": "FAIL_CLOSED_TRIGGERED", "reason": "HSM_BINDING_VIOLATION"}

        if not self._enforce_mpa(context.mpa_signatures):
            logger.error(f"FAIL_CLOSED_TRIGGERED: MPA quorum not met for session {context.session_id}")
            return {"status": "FAIL_CLOSED_TRIGGERED", "reason": "INSUFFICIENT_MPA_QUORUM"}

        serialized_payload = json.dumps(payload, sort_keys=True)
        hsm_signature = self.hsm.sign_with_hardware_key(context.hsm_key_handle, serialized_payload.encode())
        audit_hash = hashlib.sha3_256(serialized_payload.encode() + hsm_signature).hexdigest()

        logger.info(f"Layer 5 secure transmission established. Audit Hash: {audit_hash}")
        
        return {
            "status": "SECURE_TRANSMISSION_ACTIVE",
            "session_id": context.session_id,
            "hsm_signature": hsm_signature.hex(),
            "audit_evidence_hash": audit_hash
        }

class MockHSMInterface:
    def validate_handle(self, handle: str) -> bool:
        return handle.startswith("HSM-SECURE-KEY-")

    def verify_signature(self, sig: str) -> bool:
        return len(sig) > 10

    def sign_with_hardware_key(self, handle: str, data: bytes) -> bytes:
        return hmac.new(handle.encode(), data, hashlib.sha256).digest()

