"""
Automatic Test Files Cleaner and Sanitizer Script
Fixes E-04: Removes invisible Unicode characters (like U+2060) and normalizes test filenames.
"""

import os
import shutil

# تحديث النطاق ليشمل المجلد الجذر والمجلدات الفرعية بالكامل
TARGET_DIRS = [".", "tests", "src", "docs"]

def sanitize_filename(filename):
    # إزالة أي محارف غير مطبوعة أو Unicode مشبوه مثل U+2060
    cleaned = "".join(c for c in filename if ord(c) < 127 and c != '\u2060')
    return cleaned

def clean_project_files():
    print("[*] بدء فحص وتنظيف الملفات من محارف Unicode الخفية...")
    
    seen_paths = set()
    for directory in TARGET_DIRS:
        if not os.path.exists(directory):
            print(f"[-] المجلد غير موجود: {directory}")
            continue
            
        for root, dirs, files in os.walk(directory):
            for file in files:
                old_path = os.path.join(root, file)
                if old_path in seen_paths:
                    continue
                seen_paths.add(old_path)
                
                clean_name = sanitize_filename(file)
                
                # التأكد من أن أسماء ملفات الاختبار تبدأ بـ test_
                if "tests" in root and not clean_name.startswith("test_") and not clean_name.startswith("__"):
                    clean_name = "test_" + clean_name

                new_path = os.path.join(root, clean_name)
                
                # إذا كان الاسم يحتوي على محارف خفية وتم تغييره
                if old_path != new_path:
                    print(f"[!] تنظيف اسم الملف:\n    من: {repr(old_path)}\n    إلى: {repr(new_path)}")
                    try:
                        shutil.copy2(old_path, new_path)
                        os.remove(old_path)
                    except Exception as ex:
                        print(f"[-] خطأ أثناء إعادة التسمية {old_path}: {ex}")
                else:
                    # التحقق الداخلي من محتوى الملف للتأكد من خلوه من رموز Unicode الضارة
                    try:
                        with open(old_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        if '\u2060' in content:
                            print(f"[!] تم العثور على محارف U+2060 داخل محتوى الملف: {old_path}")
                            clean_content = content.replace('\u2060', '')
                            with open(old_path, 'w', encoding='utf-8') as f:
                                f.write(clean_content)
                            print(f"[OK] تم تنظيف محتوى الملف بنجاح: {old_path}")
                    except Exception as e:
                        pass

    print("[+] تم الانتهاء من فحص وتنظيف كافة الملفات بنجاح!")

if __name__ == "__main__":
    clean_project_files()
