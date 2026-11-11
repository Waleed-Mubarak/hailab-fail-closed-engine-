"""
Automatic Test Files Cleaner and Sanitizer Script (Updated for Scope B & CI Workflows)
Fixes E-04: Removes invisible Unicode characters (like U+2060) from filenames, directory names,
and internal contents across all project paths including .github/workflows.
"""

import os
import shutil

# إضافة مسارات Scope B ومجلدات الـ CI (.github/workflows) لتتم معالجتها بدقة وتطهيرها
TARGET_DIRS = [".", "tests", "src", "docs", "src/scope_b", "tests/scope_b", ".github/workflows"]
BAD_CHARS = ["\u2060", "\u200b", "\ufeff"]

def sanitize_name(name):
    cleaned = name
    for bc in BAD_CHARS:
        cleaned = cleaned.replace(bc, "")
    return cleaned

def clean_project_files():
    print("[*] بدء فحص وتنظيف الملفات، المجلدات، وملفات الـ CI من محارف Unicode الخفية...")
    
    for target in TARGET_DIRS:
        if not os.path.exists(target):
            continue
            
        for root, dirs, files in os.walk(target, topdown=False):
            # تنظيف أسماء الملفات (بما فيها ملفات الـ CI مثل scope_b.yml)
            for file in files:
                old_path = os.path.join(root, file)
                clean_file_name = sanitize_name(file)

                new_path = os.path.join(root, clean_file_name)
                
                if old_path != new_path:
                    print(f"[!] تنظيف اسم الملف (إزالة التلوث): {repr(old_path)} -> {repr(new_path)}")
                    try:
                        shutil.move(old_path, new_path)
                    except Exception as e:
                        print(f"[-] خطأ في نقل الملف: {e}")
                
                # تحديث مسار الملف بعد أي تعديل في الاسم
                current_file_path = new_path if os.path.exists(new_path) else old_path

                # فحص المحتوى الداخلي للملف للتأكد من خلوه من محارف Unicode المخفية وتطهيره
                try:
                    with open(current_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    modified = False
                    for bc in BAD_CHARS:
                        if bc in content:
                            content = content.replace(bc, '')
                            modified = True
                            
                    if modified:
                        with open(current_file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        print(f"[!] تم تنظيف المحتوى الداخلي للملف من الحروف المخفية: {current_file_path}")
                except Exception:
                    pass

            # تنظيف أسماء المجلدات وحذف المجلدات الوهمية الفارغة
            for directory in dirs:
                old_dir_path = os.path.join(root, directory)
                clean_dir_name = sanitize_name(directory)
                
                if not clean_dir_name.strip():
                    print(f"[-] حذف مجلد وهمي فارغ/مشفوع: {repr(old_dir_path)}")
                    try:
                        shutil.rmtree(old_dir_path)
                    except Exception as e:
                        print(f"[-] خطأ في حذف المجلد: {e}")
                    continue

                new_dir_path = os.path.join(root, clean_dir_name)
                if old_dir_path != new_dir_path:
                    print(f"[!] تنظيف اسم المجلد: {repr(old_dir_path)} -> {repr(new_dir_path)}")
                    try:
                        os.rename(old_dir_path, new_dir_path)
                    except Exception as e:
                        print(f"[-] خطأ في إعادة تسمية المجلد: {e}")

    print("[+] تم الانتهاء من تطهير كافة الملفات ومجلدات Scope B وملفات الـ CI بنجاح تام!")

if __name__ == "__main__":
    clean_project_files()
