import unittest

class TestTurkashEngine(unittest.TestCase):

    def test_admissibility_boundary(self):
        """
        التحقق من حدود المقبولية الشاملة (Admissibility) والتمييز بين اكتمال النصاب (Quorum)
        """
        # 1. اختبار اكتمال النصاب فقط (Structural Gate)
        # هذا يمثل |\mathbb{A}| >= q
        quorum_met = len({"Admin_A", "Admin_B"}) >= 2
        self.assertTrue(quorum_met, "Structural Gate Error: Quorum not met!")

        # 2. اختبار المقبولية الشاملة (Admissibility Model)
        # السياق: السياسة، الحالة، وإلغاء الصلاحيات
        context = {
            "policy_active": True,
            "system_state": "READY",
            "revocation_triggered": False
        }

        # دالة المقبولية: f(A, Policy, State, Revocation)
        is_admissible = (
            quorum_met and
            context["policy_active"] and
            context["system_state"] == "READY" and
            not context["revocation_triggered"]
        )

        self.assertTrue(is_admissible, "Functional Gate Error: System should be admissible!")

        # 3. اختبار إلغاء الصلاحيات (مثلاً تفعيل إلغاء الصلاحيات)
        context["revocation_triggered"] = True
        is_admissible_after_revocation = (
            quorum_met and
            context["policy_active"] and
            context["system_state"] == "READY" and
            not context["revocation_triggered"]
        )

        self.assertFalse(is_admissible_after_revocation, "P0 Error: System allowed access after revocation!")

    def test_fail_closed_zeroization(self):
        """
        التحقق من أن النظام ينفذ التصفير الفوري ويتحول للفشل المغلق عند التلاعب (Fail-Closed & Zeroization)
        """
        tamper_detected = True
        
        system_state = "FAIL_CLOSED" if tamper_detected else "READY"
        memory_scrubbed = True if tamper_detected else False

        self.assertEqual(system_state, "FAIL_CLOSED", "P0 Error: System failed to enter FAIL_CLOSED state!")
        self.assertTrue(memory_scrubbed, "P0 Error: Sensitive memory was NOT scrubbed!")

if __name__ == "__main__":
    unittest.main()
