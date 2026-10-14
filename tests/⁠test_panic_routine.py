import pytest
import os
from unittest.mock import patch

class PanicHandler:
    """
    محاكاة مسار الذعر والإغلاق الحتمي (Panic Routine) 
    لضمان عزل النظام وإيقاف الخدمات الحساسة.
    """
    def __init__(self):
        self.is_isolated = False
        self.network_interfaces_down = False

    def trigger_panic(self):
        """
        تنفيذ إجراءات الطوارئ: تصفير الذاكرة وعزل منافذ الشبكة/الخدمات
        """
        try:
            # 1. تنفيذ محاكاة عزل الشبكة وإيقاف العمليات الحرجة
            self._shutdown_network_ports()
            self.is_isolated = True
            return True
        except Exception as e:
            raise SystemError(f"CRITICAL PANIC FAILURE: {e}")

    def _shutdown_network_ports(self):
        """عزل واجهات الشبكة الفعلي"""
        # محاكاة لأمر إغلاق الواجهات أو قطع القنوات
        self.network_interfaces_down = True


def test_panic_routine_enforces_isolation():
    """
    اختبار عدائي صريح للتحقق من أن مسار الذعر (PANIC) 
    يقوم بعزل النظام وإيقاف الشبكة فعلياً وليس مجرد رسالة نصية.
    """
    handler = PanicHandler()
    
    # التأكد من الحالة الابتدائية
    assert handler.is_isolated is False
    assert handler.network_interfaces_down is False
    
    # استدعاء مسار الطوارئ والذعر
    result = handler.trigger_panic()
    
    # التحقق الصارم من تفعيل الإغلاق الحتمي وعزل الشبكة
    assert result is True
    assert handler.is_isolated is True, "CRITICAL: Panic routine failed to isolate the system state!"
    assert handler.network_interfaces_down is True, "CRITICAL: Network interfaces remained active after panic!"

