# Scope B Requirements Traceability Matrix

يوضح الجدول التالي مصفوفة تتبع المتطلبات الأمنية للنطاق الثاني (`Scope B`) وارتباطها المباشر بدوال المحرك ووفرة الاختبارات الآلية لضمان معمارية الإغلاق الحازم (`Fail-Closed Architecture`).

| معرف المتطلب (Requirement ID) | الوصف الأمني (Security Requirement) | دالة المحرك المرتبطة (Engine Method) | اختبار الوحدة المسؤول (Test Function) | حالة التحقق (Status) |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-SCOPE-B-01** | تهيئة النظام والتحقق من الحالة الأساسية | `__init__` | `test_engine_initialization` | ✅ مجتاز |
| **REQ-SCOPE-B-02** | تطبيق سياسات العزل والبيانات الآمنة | `enforce_policy` | `test_enforce_policy_passed` | ✅ مجتاز |
| **REQ-SCOPE-B-03** | تفعيل آلية الإغلاق الحازم عند الخرق | `_fail_closed` | `test_fail_closed_on_breach` / `insecure` | ✅ مجتاز |
| **REQ-SCOPE-B-04** | تصفية استدعاءات النظام (Syscall Validation & Seccomp) | `validate_syscall_policy` | `test_validate_syscall_policy_*` | ✅ مجتاز |
| **REQ-SCOPE-B-05** | مراقبة النظام عبر مؤقت مستقل (Watchdog) | `check_watchdog_signal` | `test_check_watchdog_signal_*` | ✅ مجتاز |
| **REQ-SCOPE-B-06** | عزل العمليات وفصل الامتيازات (Process Isolation) | `enforce_process_isolation` | `test_enforce_process_isolation_*` | ✅ مجتاز |
| **REQ-SCOPE-B-07** | قفل وحماية الذاكرة (Memory Hardening) | `enforce_memory_hardening` | `test_enforce_memory_hardening` | ✅ مجتاز |

---
**أدلة التنفيذ:** تم التحقق من كافة الاختبارات وتمريرها بنجاح تام عبر مسار التكامل المستمر (CI) للمستودع.

