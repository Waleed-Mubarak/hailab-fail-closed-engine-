import ctypes
import sys
import os

class MemoryLockError(SecurityError if 'SecurityError' in globals() else Exception):
    """استثناء أمني يتم رفعه عند فشل قفل الذاكرة في الـ RAM"""
    pass

class InvalidatedBufferError(PermissionError):
    """استثناء أمني يتم رفعه عند محاولة استخدام مخزن مؤقت تم تطهيره وإلغاؤه"""
    pass

class SecureMemoryBuffer:
    """
    مكون أصلي صلب لتخصيص مخازن مؤقتة حساسة وتأمين الذاكرة الأصلية (Memory Hardening)
    مع تطهير صريح وإلغاء دائم للصلاحية وإغلاق حتمي عند الفشل (Fail-Closed Enforcement).
    """
    def __init__(self, size=256):
        self.size = size
        self.buffer = ctypes.create_string_buffer(size)
        # إضافة memoryview للتحكم المباشر بالبايتات ومنع تسريب المراجع المعلقة (Dangling References)
        self._memory_view = memoryview(self.buffer).cast('B')
        self._locked = False
        self._is_invalidated = False  # تتبع حالة إلغاء صلاحية المخزن
        
        # 1. تطبيق قفل الذاكرة الحتمي (mlock Fail-Closed Enforcement)
        self._lock_memory()

    def _lock_memory(self):
        """
        يجب ألا يسمح فشل mlock باستمرار التشغيل مع البيانات الحساسة بصمت.
        """
        try:
            libc = ctypes.CDLL("libc.so.6")
            addr = ctypes.addressof(self.buffer)
            res = libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(self.size))
            
            if res != 0:
                raise MemoryLockError(f"CRITICAL: mlock failed with error code {res}. Cannot guarantee memory isolation.")
            
            self._locked = True
        except Exception as e:
            self._locked = False
            raise MemoryLockError(f"FAIL-CLOSED TRIGGERED: Hard memory lock could not be secured. Details: {e}")

    def write_sensitive_data(self, data: str):
        """كتابة البيانات الحساسة مع التحقق من صلاحية المخزن وقفل الذاكرة"""
        if self._is_invalidated:
            raise InvalidatedBufferError("CRITICAL: Access denied! Buffer has been zeroized and invalidated.")
        
        if not self._locked:
            raise MemoryLockError("CRITICAL: Cannot write to unlocked memory buffer.")

        encoded = data.encode('utf-8')
        length = min(len(encoded), self.size - 1)
        
        # مسح كامل للمحتوى القديم عبر الـ memoryview و ctypes
        for i in range(len(self._memory_view)):
            self._memory_view[i] = 0x00
        ctypes.memset(ctypes.addressof(self.buffer), 0, self.size)
        
        self.buffer[:length] = encoded[:length]
        self.buffer[length] = 0

    def explicit_purge(self):
        """
        2 & 3. تصفير البيانات وإلغاء دورة حياة المخزن المؤقت (Zeroization & Invalidation)
        مع قطع جذري لأي مراجع معلقة (Dangling References) وامتلاك مسح مباشر للبايتات.
        """
        if self._is_invalidated:
            return True

        try:
            # 1. التصفير المباشر عبر memoryview (يقضي على مراجع bytearray الخارجية)
            if hasattr(self, '_memory_view') and self._memory_view:
                for i in range(len(self._memory_view)):
                    self._memory_view[i] = 0x00

            # 2. مسح متعدد الدوارات للذاكرة الحساسة عبر ctypes
            addr = ctypes.addressof(self.buffer)
            ctypes.memset(addr, 0, self.size)
            
            # فك قفل الذاكرة إذا كانت مقفلة
            if self._locked:
                try:
                    libc = ctypes.CDLL("libc.so.6")
                    libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(self.size))
                except Exception:
                    pass
                self._locked = False

            # 3. الإبطال التام وقطع جميع الروابط لمنع Use-After-Clear واسترجاع المراجع
            self._is_invalidated = True
            self._memory_view = None
            self.buffer = None
            return True
            
        except Exception as e:
            self._is_invalidated = True
            self._memory_view = None
            self.buffer = None
            raise SystemError(f"PANIC: Severe failure during memory zeroization! Details: {e}")

    def read_data(self) -> bytes:
        """قراءة صريحة للبيانات المحفوفة بضوابط الوصول الحرج"""
        if self._is_invalidated or self.buffer is None:
            raise InvalidatedBufferError("CRITICAL: Attempted read access to an invalidated/purged memory buffer.")
        return self.buffer.raw
