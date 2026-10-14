from flask import Flask, render_template, jsonify
import subprocess
import sys
import logging

# إعداد نظام التسجيل (Logging) لتتبع الطلبات وحالة الاختبارات في الوقت الفعلي
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/')
def home():
    """عرض الصفحة الرئيسية لواجهة التحكم"""
    logger.info("Accessing main security dashboard interface.")
    return render_template('index.html')

@app.route('/run-tests', methods=['GET'])
def run_tests():
    """
    تشغيل مجموعة اختبارات Pytest بالكامل (بما فيها اختبارات الذاكرة، 
    التطهير المادي، وإجراءات الذعر) وإرجاع النتائج بصيغة JSON.
    """
    try:
        logger.info("Initiating automated adversarial and unit test suites...")
        
        # تنفيذ اختبارات بايثون باستخدام بيئة التشغيل الحالية
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', '-v'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout if result.stdout else result.stderr
        
        if result.returncode == 0:
            logger.info("All test suites passed successfully.")
            status_msg = "SUCCESS: All security and panic routines passed verification."
        else:
            logger.warning("Some tests failed or encountered warnings.")
            status_msg = "WARNING/FAILURE: Review test output below."

        return jsonify({
            'status': status_msg,
            'exit_code': result.returncode,
            'result': output if output else 'Tests completed with no textual output.'
        })

        
    except subprocess.TimeoutExpired:
        logger.error("Test execution timed out.")
        return jsonify({
            'status': 'ERROR',
            'exit_code': -1,
            'result': 'CRITICAL ERROR: Test execution timed out after 60 seconds.'
        }), 500
        
    except Exception as e:
        logger.error(f"Unexpected error during test execution: {str(e)}")
        return jsonify({
            'status': 'ERROR',
            'exit_code': -1,
            'result': f'CRITICAL ERROR: {str(e)}'
        }), 500

if __name__ == '__main__':
    # تشغيل الخادم المحلي على المنفذ المخصص مع تفعيل وضع التطوير
    app.run(host='0.0.0.0', port=8501, debug=True)
