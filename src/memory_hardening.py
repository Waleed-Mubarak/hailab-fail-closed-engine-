import ctypes

class FailClosedEngine:
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
        معالجة وتطهير مواد مفتاح التشفير في المكان وقبل إبطال المراجع.
        """
        if self._is_invalidated:
            return True

        try:
            # 1. التطهير المباشر في المكان لـ bytearray (In-place byte clearing)
            for i in range(self.size):
                self._buffer[i] = 0x00

            # 2. مسح مؤشر الذاكرة الصلبة عبر ctypes memset لضمان محو الرواسب تماماً
            ctypes.memset(self._addr, 0, self.size)

            # 3. إبطال المراجع بشكل قاطع لمنع Use-After-Clear
            self._is_invalidated = True
            
            # قطع ارتباط المؤشرات الداخلية
            del self._c_data
            
            return True
        except Exception as e:
            self._is_invalidated = True
            raise SystemError(f"CRITICAL: Zeroization failed securely! Error: {e}")
