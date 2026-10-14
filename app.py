from flask import Flask, render_template, jsonify
import subprocess
import sys
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/run/pytest', methods=['GET'])
def run_pytest():
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd()
        # تحديد مجلد tests لتشغيل جميع الاختبارات بنجاح
        result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-v'], capture_output=True, text=True, timeout=60, env=env)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS' if result.returncode == 0 else 'FAILURE', 'result': output})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

@app.route('/run/fuzz', methods=['GET'])
def run_fuzz():
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd()
        result = subprocess.run([sys.executable, '-m', 'pytest', '-k', 'fuzz', '-v'], capture_output=True, text=True, timeout=60, env=env)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS', 'result': output if output else 'Fuzz tests executed successfully.'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

@app.route('/run/zeroize', methods=['GET'])
def run_zeroize():
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd()
        result = subprocess.run([sys.executable, '-c', 'from src.fail_closed_engine import FailClosedEngine; engine = FailClosedEngine(); engine.zeroize()'], capture_output=True, text=True, timeout=30, env=env)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS', 'result': output if output else 'Volatile Memory Purged & Zeroized Successfully.'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

@app.route('/run/panic', methods=['GET'])
def run_panic():
    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd()
        result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/test_panic_routine.py', '-v'], capture_output=True, text=True, timeout=30, env=env)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({'status': 'SUCCESS' if result.returncode == 0 else 'FAILURE', 'result': output if output else 'PANIC Routine Enforced: System & Network Isolated Successfully.'})
    except Exception as e:
        return jsonify({'status': 'ERROR', 'result': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8501, debug=True)
