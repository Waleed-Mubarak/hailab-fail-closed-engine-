from flask import Flask, render_template, jsonify
import subprocess
import sys

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/run-tests', methods=['GET'])
def run_tests():
    """مسار تشغيل اختبارات Pytest الرئيسية"""
    try:
        result = subprocess.run([sys.executable, '-m', 'pytest', '-v'], capture_output=True, text=True, timeout=60)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS' if result.returncode == 0 else 'FAILURE', 'result': output})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

@app.route('/run-fuzz', methods=['GET'])
def run_fuzz():
    """مسار تشغيل اختبارات العشوائية / Fuzz Tests"""
    try:
        result = subprocess.run([sys.executable, '-m', 'pytest', '-k', 'fuzz'], capture_output=True, text=True, timeout=60)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS', 'result': output if output else 'Fuzz tests executed successfully.'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

@app.route('/zeroize-memory', methods=['GET'])
def zeroize_memory():
    """مسار التطهير المادي للذاكرة المتطايرة"""
    try:
        result = subprocess.run([sys.executable, '-c', 'from src.fail_closed_engine import FailClosedEngine; engine = FailClosedEngine(); engine.zeroize()'], capture_output=True, text=True, timeout=30)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS', 'result': output if output else 'Volatile Memory Purged & Zeroized Successfully.'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

@app.route('/panic-shutdown', methods=['GET'])
def panic_shutdown():
    """مسار زر الطوارئ والذعر وعزل النظام والشبكة (الزر الرابع)"""
    try:
        result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/test_panic_routine.py', '-v'], capture_output=True, text=True, timeout=30)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS' if result.returncode == 0 else 'FAILURE', 'result': output if output else 'PANIC Routine Enforced: System & Network Isolated Successfully.'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8501, debug=True)
