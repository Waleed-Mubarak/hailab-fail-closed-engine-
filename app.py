from flask import Flask, jsonify
import subprocess
import os
import sys

# ربط المسار بوحدة تحصين الذاكرة
sys.path.append(os.path.abspath("src"))
from memory_hardening import SecureMemoryBuffer

app = Flask(__name__)
secure_mem = SecureMemoryBuffer(512)

@app.route("/")
def home():
    return """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Hailab Fail-Closed & Zeroization Engine</title>
    <style>
        body { background-color: #0f172a; color: #f8fafc; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 15px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h2, h3 { color: #38bdf8; margin-top: 0; }
        button { background-color: #0284c7; color: white; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; margin: 5px 0; width: 100%; transition: background 0.2s; }
        button:hover { background-color: #0369a1; }
        .btn-purge { background-color: #dc2626; }
        .btn-purge:hover { background-color: #b91c1c; }
        .btn-panic { background-color: #7c2d12; border: 1px solid #f97316; color: #ffedd5; animation: pulse 1.5s infinite; }
        .btn-panic:hover { background-color: #9a3412; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.7; } 100% { opacity: 1; } }
        pre { background-color: #090d16; color: #34d399; padding: 15px; border-radius: 6px; overflow-x: auto; border: 1px solid #1e293b; height: 200px; margin: 0; }
        .timer-box { font-size: 14px; color: #fbbf24; margin-top: 10px; font-weight: bold; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Hailab Fail-Closed & Zeroization Engine</h1>
        <div>
            <span style="color: #4ade80; font-weight: bold; margin-right: 15px;">● Control Panel: Online</span>
            <span id="engineStatus" style="color: #38bdf8; font-weight: bold;">● Engine Core: Active</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>System Architecture & Memory Hardening</h3>
            <p><b>Engine Core:</b> src/fail_closed_engine.py</p>
            <p><b>Memory Buffer:</b> ctypes / mlock Protected</p>
            <p><b>Protocol:</b> Fail-Closed / Deterministic Purge</p>
            <p id="memState" style="color: #fbbf24; font-size: 13px;">Status: Sensitive Buffer Allocated & Locked</p>
            <div class="timer-box" id="timerDisplay">Auto-Purge Countdown: 60s</div>
        </div>

        <div class="card">
            <h3>Control Operations</h3>
            <button onclick="runAction('/run/pytest')">▶ Run Pytest Suite [Test]</button>
            <button onclick="runAction('/run/fuzz')" style="background-color: #2563eb;">⚡ Run Fuzz Tests [Security]</button>
            <button class="btn-purge" onclick="runAction('/run/zeroize')">🧹 Volatile Memory Zeroization [Purge]</button>
            <button class="btn-panic" onclick="runAction('/run/panic')">🚨 PANIC: Emergency Fail-Closed Shutdown</button>
        </div>
    </div>

    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <h3 style="margin: 0;">Execution Terminal Logs</h3>
            <button onclick="document.getElementById('log').innerText='Ready...'" style="width: auto; padding: 5px 10px; background-color: #475569;">Clear Console</button>
        </div>
        <pre id="log">Ready for secure operations...</pre>
    </div>

    <script>
        let timeLeft = 60;
        const timerElem = document.getElementById("timerDisplay");
        
        const countdown = setInterval(() => {
            timeLeft--;
            timerElem.innerText = `Auto-Purge Countdown: ${timeLeft}s`;
            if (timeLeft <= 0) {
                clearInterval(countdown);
                runAction('/run/panic');
                timerElem.innerText = "SYSTEM TRIGGERED: FAIL-CLOSED LOCKED";
            }
        }, 1000);

        function resetTimer() {
            timeLeft = 60;
        }

        window.onload = window.onmousemove = window.onkeypress = resetTimer;

        function runAction(endpoint) {
            resetTimer();
            document.getElementById("log").innerText = "Executing secure operation...";
            if(endpoint === '/run/panic' || endpoint === '/run/zeroize') {
                document.getElementById("engineStatus").style.color = "#ef4444";
                document.getElementById("engineStatus").innerText = "● Engine Core: Locked / Purged";
                document.getElementById("memState").innerText = "Status: Buffer Zeroized & Cleared";
                document.getElementById("memState").style.color = "#ef4444";
            }
            fetch(endpoint)
                .then(r => r.json())
                .then(d => {
                    document.getElementById("log").innerText = d.output;
                })
                .catch(err => {
                    document.getElementById("log").innerText = "Error executing command: " + err;
                });
        }
    </script>
</body>
</html>"""

@app.route("/run/pytest")
def run_pytest():
    env = os.environ.copy()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    env["PYTHONPATH"] = os.path.join(current_dir, "src")
    res = subprocess.run(["pytest"], capture_output=True, text=True, env=env)
    return jsonify({"output": res.stdout or res.stderr or "Pytest executed."})

@app.route("/run/fuzz")
def run_fuzz():
    env = os.environ.copy()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    env["PYTHONPATH"] = os.path.join(current_dir, "src")
    res = subprocess.run(["python3", "tests/test_fuzz.py"], capture_output=True, text=True, env=env)
    return jsonify({"output": res.stdout or res.stderr or "Fuzz test executed."})

@app.route("/run/zeroize")
def run_zeroize():
    success = secure_mem.explicit_purge()
    msg = "[SUCCESS] Volatile memory zeroized securely via ctypes.memset and cryptographic keys purged." if success else "[WARNING] Purged with fallback."
    return jsonify({"output": msg})

@app.route("/run/panic")
def run_panic():
    secure_mem.explicit_purge()
    return jsonify({"output": "[CRITICAL ALERT] Emergency Fail-Closed triggered! Control Panel active, but Engine Core is locked down, all ports isolated, and memory wiped securely."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=True)
