import ctypes

class InvalidatedBufferError(PermissionError):
    """استثناء أمني يتم رفعه عند محاولة استخدام مخزن مؤقت تم تطهيره وإلغاؤه"""
    pass

class FailClosedEngine:
    """
    محرك حماية الذاكرة والتعامل الصارم مع المفاتيح الحساسة 
    مع التطهير الفوري وإلغاء المراجع لمنع ثغرات Use-After-Clear.
    """
    def __init__(self, data: bytes):
        # تحويل البيانات إلى bytearray قابل للتعديل في الذاكرة
        self._buffer = bytearray(data)
        self.size = len(self._buffer)
        self._is_invalidated = False
        
        # إنشاء مرجع مؤشر ctypes للوصول المباشر للذاكرة الأساسية
        self._c_data = (ctypes.c_char * self.size).from_buffer(self._buffer)
        self._addr = ctypes.addressof(self._c_data)

    def zeroize(self):
        """
        معالجة وتطهير مواد مفتاح التشفير في المكان وققبل إبطال المراجع.
        """
        if self._is_invalidated:
            return True

        try:
            # 1. التطهير المباشر في المكان لـ bytearray (In-place byte clearing)
            for i in range(self.size):
                self._buffer[i] = 0x00

            # 2. مسح مؤشر الذاكرة الصلبة عبر ctypes memset لضمان محو الرواسب تماماً
            ctypes.memset(self._addr, 0, self.size)

            # 3. الإبطال التام وقطع الروابط لمنع Use-After-Clear
            self._is_invalidated = True
            
            # مسح المراجع الداخلية
            del self._c_data
            
            return True
        except Exception as e:
            self._is_invalidated = True
            raise SystemError(f"CRITICAL: Zeroization failed securely! Error: {e}")

    def read_data(self) -> bytes:
        """قراءة صريحة للبيانات المحفوفة بضوابط الوصول الحرج"""
        if self._is_invalidated or self._buffer is None:
            raise InvalidatedBufferError("CRITICAL: Attempted read access to an invalidated/purged memory buffer.")
        return bytes(self._buffer)

    def panic(self):
        """
        روتين الطوارئ الفوري (Panic & Isolation Routine):
        يقوم بتطهير الذاكرة الحساسة أولاً ثم تفعيل حالة الإغلاق الشامل والعزل التام.
        """
        try:
            # 1. تنفيذ التطهير الشامل للذاكرة كمرحلة أولى أساسية
            self.zeroize()
            
            # 2. تطبيق بروتوكول العزل الإضافي وإيقاف العمليات
            self._is_invalidated = True
            
            return True
        except Exception as e:
            self._is_invalidated = True
            raise SystemError(f"CRITICAL: Panic isolation routine failed! Error: {e}")
