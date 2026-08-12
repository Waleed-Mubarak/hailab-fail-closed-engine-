import time
import os
import hashlib
import logging

# إعداد السجلات الأمنية (Secure Logging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FailClosedEngine:
    def __init__(self):
        # محاكاة مفتاح سري حقيقي مخزن في الذاكرة الحية (RAM-resident key)
        self._secure_ram_key = bytearray(os.urandom(32))
        self.is_zeroized = False
        self.system_locked = False

    def verify_chassis_sensors(self) -> bool:
        """التحقق من سلامة الهيكل والمستشعرات المادية"""
        if self.system_locked or self.is_zeroized:
            return False
        # محاكاة حالة سليمة للمستشعرات
        return True

    def check_duress_trigger(self, duress_signal: bool) -> None:
        """تفعيل نظام التطهير الفوري (Zeroization) عند رصد ضغط أو خطر أمني"""
        if duress_signal:
            logging.warning("DURESS SIGNAL DETECTED! Initiating emergency Zeroization...")
            self.execute_zeroization()

    def execute_zeroization(self) -> None:
        """مسح المفتاح من الذاكرة الحية تماماً (Zeroization) وإغلاق النظام (Fail-Closed)"""
        if not self.is_zeroized:
            # الكتابة فوق الذاكرة بأصفار لتدمير المفتاح تماماً
            for i in range(len(self._secure_ram_key)):
                self._secure_ram_key[i] = 0
            
            self.is_zeroized = True
            self.system_locked = True
            logging.error("CRITICAL: RAM key zeroized. System locked in Fail-Closed state.")

    def get_key_status(self) -> str:
        """التحقق من حالة المفتاح في الذاكرة لأغراض التدقيق"""
        if self.is_zeroized:
            return "ZEROIZED_SECURE"
        return "ACTIVE"
