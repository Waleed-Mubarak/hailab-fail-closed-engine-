import pytest
from src.memory_hardening import SecureMemoryBuffer, MemoryLockError, InvalidatedBufferError

def test_secure_buffer_initialization():
    """التحقق من تهيئة المخزن المؤقت بنجاح وقفل الذاكرة"""
    buffer = SecureMemoryBuffer(size=128)
    assert buffer.size == 128
    assert buffer._is_invalidated is False

def test_sensitive_data_write_and_read():
    """التحقق من الكتابة الآمنة وقراءة البيانات الحساسة"""
    buffer = SecureMemoryBuffer(size=256)
    buffer.write_sensitive_data("Confidential-Data-2026")
    data = buffer.read_data()
    assert b"Confidential-Data-2026" in data

def test_buffer_explicit_purge_and_invalidation():
    """التحقق من التطهير الصريح وإبطال صلاحية المخزن لمنع Use-After-Clear"""
    buffer = SecureMemoryBuffer(size=128)
    buffer.write_sensitive_data("Secret-Token")
    
    # تنفيذ التطهير الجذري
    assert buffer.explicit_purge() is True
    assert buffer._is_invalidated is True

    # محاولة قراءة مخزن تم تطهيره وإلغاؤه يجب أن ترفع استثناء أمني صارم
    with pytest.raises(InvalidatedBufferError):
        buffer.read_data()

    # محاولة كتابة جديدة في مخزن ملغى يجب أن ترفض تماماً
    with pytest.raises(InvalidatedBufferError):
        buffer.write_sensitive_data("New-Data")

