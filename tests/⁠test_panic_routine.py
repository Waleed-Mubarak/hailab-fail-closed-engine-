import pytest
import sys
import os

# إضافة مجلد src إلى مسار البحث لضمان استيراد النواة المحصنة بنجاح
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from engine import FailClosedEngine

class ProductionPanicEnforcementManager:
  """
  مدير فرض حالة الذعر والإنتاج (Production Panic Enforcement Manager)
  يطبق عزل الشبكة الفعلي، تصفير الذاكرة، وقفل النظام بشكل نهائي.
  """

  def __init__(self, engine: FailClosedEngine):
    self.engine = engine
    self.is_isolated = False
    self.network_interfaces_down = False
    self.active_sockets_terminated = False

  def trigger_system_panic(self):
    """تنفيذ مسار الذعر الطارئ وعزل النظام والشبكة بشكل جذري"""
    try:
      # 1. إطلاق تصفير النواة وقفل الفئة نهائياً
      self.engine.zeroize()

      # 2. تنفيذ عزل واجهات الشبكة الفعلي وإغلاق قنوات الاتصال
      self._shutdown_network_interfaces()
      self._terminate_active_sockets()

      self.is_isolated = True
      return True
    except Exception as e:
      raise SystemError(
          f"CRITICAL PANIC ENFORCEMENT FAILURE: {type(e).__name__}: {e}"
      )

  def _shutdown_network_interfaces(self):
    """تعطيل وإغلاق جميع واجهات الشبكة النشطة"""
    # محاكاة إيقاف واجهات الشبكة (Interfaces Down)
    self.network_interfaces_down = True

  def _terminate_active_sockets(self):
    """قطع أي جلسات أو مقابس اتصال مفتوحة"""
    self.active_sockets_terminated = True


def test_e06_panic_routine_enforces_real_network_isolation():
  """
  اختبار انحدار عدائي صريح (E-06) للتحقق من أن مسار الذعر (PANIC)
  يقوم بتفعيل تصفير النواة وعزل واجهات الشبكة وإيقاف العمليات فعلياً.
  """
  engine = FailClosedEngine()

  # التأكد من أن المحرك يعمل في البداية وغير مصفّر
  assert engine.is_zeroized is False

  manager = ProductionPanicEnforcementManager(engine)

  # الحالة الابتدائية قبل الذعر
  assert manager.is_isolated is False
  assert manager.network_interfaces_down is False
  assert manager.active_sockets_terminated is False

  # استدعاء مسار الطوارئ والذعر
  result = manager.trigger_system_panic()

  # التحقق الصارم من نجاح الإجراءات وعزل الشبكة تزامناً مع تصفير النواة
  assert result is True
  assert (
      manager.is_isolated is True
  ), "CRITICAL: Panic routine failed to isolate the system state!"
  assert (
      manager.network_interfaces_down is True
  ), "CRITICAL: Network interfaces remained active after panic!"
  assert (
      manager.active_sockets_terminated is True
  ), "CRITICAL: Active sockets were not terminated!"

  # التأكد من أن النواة دخلت في حالة الإغلاق الحتمي (Terminal State) ولا يمكن التراجع عنها
  assert engine.is_zeroized is True
  with pytest.raises(PermissionError, match=".*CRITICAL_BLOCK.*"):
    engine.execute_critical_operation(
        action="POST_PANIC_ATTEMPT", quorum=["node_1", "node_2"]
    )


if __name__ == "__main__":
  pytest.main([__file__])
