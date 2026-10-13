import pytest
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
