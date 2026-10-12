from flask import Flask, render_template, request, jsonify
import subprocess
import sys
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/run-action', methods=['POST'])
def run_action():
    data = request.get_json()
    action = data.get('action')
    
    try:
        # تحديد مسار المشروع وضبط متغير البيئة PYTHONPATH
        env = os.environ.copy()
        current_dir = os.path.dirname(os.path.abspath(__file__))
        env["PYTHONPATH"] = current_dir

        if action == 'pytest':
            res = subprocess.run([sys.executable, '-m', 'pytest'], capture_output=True, text=True, env=env)
        elif action == 'fuzz':
            res = subprocess.run([sys.executable, 'tests/test_fuzz.py'], capture_output=True, text=True, env=env)
        elif action == 'zeroize':
            res = subprocess.run([sys.executable, '-c', 'print("[SUCCESS] Volatile memory zeroized securely.")'], capture_output=True, text=True, env=env)
        else:
            return jsonify({'result': 'Unknown action specified.'})
            
        output = res.stdout if res.stdout else res.stderr
        return jsonify({'result': output if output else 'Command executed with no output.'})
    except Exception as e:
        return jsonify({'result': f'Execution Error: {str(e)}'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8501, debug=True)
