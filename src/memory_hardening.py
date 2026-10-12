import ctypes
import os

class SecureMemoryBuffer:
    """
    مكون أصلي لتخصيص مخازن مؤقتة حساسة وتأمين الذاكرة الأصلية (Memory Hardening)
    لمنع النسخ غير المقصود للبيانات الحساسة وضمان المسح الصريح.
    """
    def __init__(self, size=256):
        self.size = size
        # تخصيص ذاكرة محمية في مساحة المستخدم
        self.buffer = ctypes.create_string_buffer(size)
        self._locked = False
        self._lock_memory()

    def _lock_memory(self):
        try:
            # محاولة تثبيت الذاكرة في RAM (mlock) لمنع تسريبها إلى Swap
            libc = ctypes.CDLL("libc.so.6")
            addr = ctypes.addressof(self.buffer)
            res = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(self.size))
            if res == 0:
                self._locked = True
        except Exception:
            self._locked = False

    def write_sensitive_data(self, data: str):
        encoded = data.encode('utf-8')
        length = min(len(encoded), self.size - 1)
        self.buffer[:length] = encoded[:length]
        self.buffer[length] = 0

    def explicit_purge(self):
        """مسح صريح وتطهير جذري للذاكرة الحساسة"""
        try:
            ctypes.memset(ctypes.addressof(self.buffer), 0, self.size)
            return True
        except Exception:
            return False

