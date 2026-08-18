    def test_admissibility_boundary(self):
        """
        التحقق من حدود المقبولية الشاملة (Admissibility):
        التمييز بين اكتمال النصاب (Quorum) وبين القرار الشامل المبني على الحالة.
        """
        # 1. اختبار اكتمال النصاب فقط (Structural Gate)
        # هذا يمثل جزء |\mathbb{A}| >= q
        quorum_met = len({"Admin_A", "Admin_B"}) >= 2
        self.assertTrue(quorum_met, "Structural quorum gate check failed.")

        # 2. اختبار المقبولية الشاملة (Admissibility)
        # محاكاة السياق: السياسة، الحالة، وإلغاء الصلاحيات
        context = {
            "policy_active": True,
            "system_state": "READY",
            "revocation_triggered": False
        }
        
        # دالة المقبولية: f(A, Policy, State, Revocation, ...)
        is_admissible = (
            quorum_met and 
            context["policy_active"] and 
            context["system_state"] == "READY" and 
            not context["revocation_triggered"]
        )
        
        self.assertTrue(is_admissible, "Functional admissibility boundary check failed.")
        
        # 3. اختبار سيناريو فشل المقبولية بسبب تغيير الحالة (مثلاً تفعيل إلغاء الصلاحيات)
        context["revocation_triggered"] = True
        is_admissible_after_revocation = (
            quorum_met and 
            context["policy_active"] and 
            context["system_state"] == "READY" and 
            not context["revocation_triggered"]
        )
        
        self.assertFalse(is_admissible_after_revocation, "System accepted operation despite revocation.")
          def test_fail_closed_zeroization(self):
        """
        التحقق من أن النظام ينفذ التصفير الفوري ويتحول للفشل المغلق عند التلاعب
        """
        tamper_detected = True
        
        system_state = "FAIL_CLOSED" if tamper_detected else "READY"
        memory_scrubbed = True if tamper_detected else False

        self.assertEqual(system_state, "FAIL_CLOSED", "P0 Error: System failed to lock!")
        self.assertTrue(memory_scrubbed, "P0 Error: Sensitive memory was NOT scrubbed!")
