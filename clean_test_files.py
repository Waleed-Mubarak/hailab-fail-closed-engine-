"""
Automatic Test Files Cleaner and Sanitizer Script
Fixes E-04: Removes invisible Unicode characters (like U+2060) from filenames and directory names.
"""

import os
import shutil

TARGET_DIRS = [".", "tests", "src", "docs"]
BAD_CHARS = ["\u2060", "\u200b", "\ufeff"]

def sanitize_name(name):
    cleaned = name
    for bc in BAD_CHARS:
        cleaned = cleaned.replace(bc, "")
    return cleaned

def clean_project_files():
    print("[*] بدء فحص وتنظيف الملفات والمجلدات من محارف Unicode الخفية...")
    
    # استخدام topdown=False لتتمكن من إعادة تسمية المجلدات من الداخل إلى الخارج
    for target in TARGET_DIRS:
        if not os.path.exists(target):
            continue
            
        for root, dirs, files in os.walk(target, topdown=False):
            # تنظيف أسماء الملفات
            for file in files:
                old_path = os.path.join(root, file)
                clean_file_name = sanitize_name(file)
                
                if "tests" in root and not clean_file_name.startswith("test_") and not clean_file_name.startswith("__"):
                    clean_file_name = "test_" + clean_file_name

                new_path = os.path.join(root, clean_file_name)
                
                if old_path != new_path:
                    print(f"[!] تنظيف اسم الملف: {repr(old_path)} -> {repr(new_path)}")
                    try:
                        shutil.move(old_path, new_path)
                    except Exception as e:
                        print(f"[-] خطأ في نقل الملف: {e}")
                else:
                    # فحص المحتوى الداخلي للتأكد من خلوه من \u2060
                    try:
                        with open(old_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        if '\u2060' in content:
                            content = content.replace('\u2060', '')
                            with open(old_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                    except Exception:
                        pass

            # تنظيف أسماء المجلدات
            for directory in dirs:
                old_dir_path = os.path.join(root, directory)
                clean_dir_name = sanitize_name(directory)
                new_dir_path = os.path.join(root, clean_dir_name)
                
                if old_dir_path != new_dir_path:
                    print(f"[!] تنظيف اسم المجلد: {repr(old_dir_path)} -> {repr(new_dir_path)}")
                    try:
                        os.rename(old_dir_path, new_dir_path)
                    except Exception as e:
                        print(f"[-] خطأ في إعادة تسمية المجلد: {e}")

    print("[+] تم الانتهاء من تطهير كافة الملفات والمجلدات بنجاح!")

if __name__ == "__main__":
    clean_project_files()
