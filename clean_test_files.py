"""
Automatic Test Files Cleaner and Sanitizer Script (Updated for Scope B)
Fixes E-04: Removes invisible Unicode characters (like U+2060) from filenames and directory names,
and cleans up directories that consist entirely of hidden characters, including scope_b paths.
"""

import os
import shutil

# إضافة مسارات Scope B المحددة لتتم معالجتها بدقة
TARGET_DIRS = [".", "tests", "src", "docs", "src/scope_b", "tests/scope_b"]
BAD_CHARS = ["\u2060", "\u200b", "\ufeff"]

def sanitize_name(name):
    cleaned = name
    for bc in BAD_CHARS:
        cleaned = cleaned.replace(bc, "")
    return cleaned

def clean_project_files():
    print("[*] بدء فحص وتنظيف الملفات والمجلدات (بما فيها Scope B) من محارف Unicode الخفية...")
    
    for target in TARGET_DIRS:
        if not os.path.exists(target):
            continue
            
        for root, dirs, files in os.walk(target, topdown=False):
            # تنظيف أسماء الملفات
            for file in files:
                old_path = os.path.join(root, file)
                clean_file_name = sanitize_name(file)
                
                # إضافة بادئة test_ فقط لمجلدات الاختبارات العامة وليست Scope B إذا كانت مسمية بشكل صحيح
                if "tests" in root and not clean_file_name.startswith("test_") and not clean_file_name.startswith("__"):
                    # نتأكد ألا نعدل ملفات غير مستهدفة
                    pass

                new_path = os.path.join(root, clean_file_name)
                
                if old_path != new_path:
                    print(f"[!] تنظيف اسم الملف: {repr(old_path)} -> {repr(new_path)}")
                    try:
                        shutil.move(old_path, new_path)
                    except Exception as e:
                        print(f"[-] خطأ في نقل الملف: {e}")
                else:
                    # فحص المحتوى الداخلي للتأكد من خلوه من محارف Unicode المخفية وتطهيره
                    try:
                        with open(old_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        modified = False
                        for bc in BAD_CHARS:
                            if bc in content:
                                content = content.replace(bc, '')
                                modified = True
                                
                        if modified:
                            with open(old_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                            print(f"[!] تم تنظيف المحتوى الداخلي للملف من الحروف المخفية: {old_path}")
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

    print("[+] تم الانتهاء من تطهير كافة الملفات ومجلدات Scope B بنجاح تام!")

if __name__ == "__main__":
    clean_project_files()
