import pytest
import ctypes
from src.memory_hardening import SecureMemoryBuffer, InvalidatedBufferError, MemoryLockError

def test_memory_zeroization_and_dangling_references():
    """
    اختبار تصفير البيانات وتدمير المراجع المعلقة (Zeroization & Reference Destruction)
    """
    buffer_size = 128
    sec_buffer = SecureMemoryBuffer(size=buffer_size)
    
    # كتابة بيانات حساسة
    secret_data = "SuperSecretKey123"
    sec_buffer.write_sensitive_data(secret_data)
    
    # التأكد من صحة القراءة قبل التطهير
    assert secret_data.encode('utf-8') in sec_buffer.read_data()
    
    # تنفيذ التطهير الصريح
    sec_buffer.explicit_purge()
    
    # 1. التحقق من رفع استثناء عند محاولة القراءة بعد التطهير
    with pytest.raises(InvalidatedBufferError):
        sec_buffer.read_data()

    # 2. التحقق من قطع مرجع الذاكرة وتصفيره (Buffer is cleared / set to None)
    assert sec_buffer.buffer is None
    assert sec_buffer._memory_view is None

def test_use_after_purge_prevention():
    """
    اختبار منع الاستخدام بعد التنظيف (Use-After-Clear Prevention)
    """
    sec_buffer = SecureMemoryBuffer(size=64)
    sec_buffer.write_sensitive_data("ConfidentialData")
    
    sec_buffer.explicit_purge()
    
    # محاولة كتابة بيانات جديدة بعد التطهير يجب أن تفشل فوراً
    with pytest.raises(InvalidatedBufferError):
        sec_buffer.write_sensitive_data("NewDataAttempt")

def test_multiple_purges_safety():
    """
    اختبار سلامة النظام عند تنفيذ التطهير المزدوج/المتكرر
    """
    sec_buffer = SecureMemoryBuffer(size=32)
    sec_buffer.explicit_purge()
    
    # التطهير للمرة الثانية يجب ألا يسبب انهياراً أو أخطاء غير متوقعة
    assert sec_buffer.explicit_purge() is True

def test_physical_zeroization_verification():
    """
    اختبار عدائي إضافي: التحقق من خلو الذاكرة الخشنة تماماً من البايتات الحساسة بعد التنظيف
    استجابة لتقرير التدقيق الثاني لد. حكمة كريموف.
    """
    buffer_size = 64
    sec_buffer = SecureMemoryBuffer(size=buffer_size)
    
    # حفظ عنوان الذاكرة مؤقتاً قبل التطهير للفحص
    addr = ctypes.addressof(sec_buffer.buffer)
    
    sec_buffer.write_sensitive_data("AcrobatSecret999")
    
    # تنفيذ التطهير
    sec_buffer.explicit_purge()
    
    # التحقق المباشر من أن محتوى العنوان المادي يحتوي حصراً على أصفار (0x00)
    # عبر قراءة بايتات الذاكرة من نفس العنوان عبر ctypes
    raw_bytes_check = ctypes.string_at(addr, buffer_size)
    
    # التأكد من أن جميع البايتات أصبحت أصفاراً تماماً ولا توجد بقايا مفاتيح تشفير
    assert all(b == 0 for b in raw_bytes_check), "CRITICAL: Physical memory contains lingering un-zeroized bytes!"
