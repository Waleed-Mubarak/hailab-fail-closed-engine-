import unittest
from layer5_engine import Layer5SecureEnforcementEngine, Layer5Context, MockHSMInterface

class TestLayer5SecureEnforcementEngine(unittest.TestCase):
    
    def setUp(self):
        self.mock_hsm = MockHSMInterface()
        self.engine = Layer5SecureEnforcementEngine(self.mock_hsm)
        self.valid_context = Layer5Context(
            session_id="l5-test-session-001",
            node_id="Node-Test-01",
            hsm_key_handle="HSM-SECURE-KEY-1234",
            mpa_signatures=["valid_sig_one_98765", "valid_sig_two_54321"]
        )

    def test_secure_transmission_success(self):
        payload = {"action": "sync_state", "data": "test_payload"}
        result = self.engine.execute_sovereign_communication(self.valid_context, payload)
        self.assertEqual(result["status"], "SECURE_TRANSMISSION_ACTIVE")

    def test_fail_closed_on_invalid_hsm_handle(self):
        invalid_context = Layer5Context(
            session_id="l5-test-session-002",
            node_id="Node-Test-02",
            hsm_key_handle="INVALID-HANDLE-9999",
            mpa_signatures=["valid_sig_one_98765", "valid_sig_two_54321"]
        )
        payload = {"action": "sync_state", "data": "test_payload"}
        result = self.engine.execute_sovereign_communication(invalid_context, payload)
        self.assertEqual(result["status"], "FAIL_CLOSED_TRIGGERED")
        self.assertEqual(result["reason"], "HSM_BINDING_VIOLATION")

    def test_fail_closed_on_insufficient_mpa_quorum(self):
        insufficient_context = Layer5Context(
            session_id="l5-test-session-003",
            node_id="Node-Test-03",
            hsm_key_handle="HSM-SECURE-KEY-5678",
            mpa_signatures=["single_weak_sig"]
        )
        payload = {"action": "sync_state", "data": "test_payload"}
        result = self.engine.execute_sovereign_communication(insufficient_context, payload)
        self.assertEqual(result["status"], "FAIL_CLOSED_TRIGGERED")
        self.assertEqual(result["reason"], "INSUFFICIENT_MPA_QUORUM")

if __name__ == "__main__":
    unittest.main()
