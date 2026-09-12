import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import unittest
from fail_closed_engine import FailClosedEngine, EngineContext

class TestFailClosedEngine(unittest.TestCase):
    
    def setUp(self):
        self.engine = FailClosedEngine()
        self.valid_context = EngineContext(
            session_id="session-001",
            security_clearance="LEVEL_HIGH",
            integrity_verified=True
        )

    def test_engine_initialization(self):
        self.assertIsNotNone(self.engine)

    def test_sovereign_execution_success(self):
        payload = {"action": "execute", "data": "secure_payload"}
        result = self.engine.execute_sovereign_communication(self.valid_context, payload)
        self.assertEqual(result["status"], "SECURE_TRANSMISSION_ACTIVE")

    def test_fail_closed_on_invalid_clearance(self):
        invalid_context = EngineContext(
            session_id="session-002",
            security_clearance="LEVEL_LOW",
            integrity_verified=True
        )
        payload = {"action": "execute", "data": "secure_payload"}
        result = self.engine.execute_sovereign_communication(invalid_context, payload)
        self.assertEqual(result["status"], "FAIL_CLOSED_TRIGGERED")

    def test_fail_closed_on_integrity_violation(self):
        corrupt_context = EngineContext(
            session_id="session-003",
            security_clearance="LEVEL_HIGH",
            integrity_verified=False
        )
        payload = {"action": "execute", "data": "secure_payload"}
        result = self.engine.execute_sovereign_communication(corrupt_context, payload)
        self.assertEqual(result["status"], "FAIL_CLOSED_TRIGGERED")

if __name__ == "__main__":
    unittest.main()
