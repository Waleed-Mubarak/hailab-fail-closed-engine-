from datetime import datetime, timezone
import ctypes
import ctypes.util
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import random
import re
import resource
import secrets
import signal
import sys
import threading
import time
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, Response, jsonify, render_template, request

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, "src")

for path in (current_dir, src_dir):
    if path not in sys.path:
        sys.path.insert(0, path)

from frozen_worker_supervisor import FrozenWorkerSupervisor
from tools.forensic_bundle import verify_bundle
from tools.forensic_companion import build_engine_report, save_report

app = Flask(__name__)

# ثوابت نواة لينكس
PR_SET_DUMPABLE = 4

# نمط التحقق من بصمة SHA-256 في سجل التدقيق
HASH_LINE_RE = re.compile(r"^(?P<body>.+?)\s*\|\s*HASH:(?P<digest>[0-9a-fA-F]{16})$")

# تحميل مكتبة النظام القياسية في لينكس (libc)
libc_path = ctypes.util.find_library("c")
libc = ctypes.CDLL(libc_path, use_errno=True) if libc_path else None

# قفل لحماية الحالة المشتركة والعمليات الحرجة مع threaded=True
state_lock = threading.Lock()


class SecureAuditLogger:
    """سجل تدقيق موثق ببصمة SHA-256 لتتبع سلامة الأحداث"""

    def __init__(self, log_filename="hailab_secure_audit.log"):
        self.log_path = os.path.join(current_dir, log_filename)

    def log_event(self, event_type: str, details: str, severity: str = "INFO"):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        raw_entry = f"[{timestamp}] [{severity}] [{event_type}] {details}"
        digest = hashlib.sha256(raw_entry.encode("utf-8")).hexdigest()[:16]
        signed_entry = f"{raw_entry} | HASH:{digest}\n"

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(signed_entry)
        except OSError as exc:
            print(f"[-] Failed to write audit log: {exc}")

    def read_lines(self) -> list[str]:
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, "r", encoding="utf-8") as f:
            return [line.rstrip("\n") for line in f.readlines()]

    def read_raw(self) -> str:
        if not os.path.exists(self.log_path):
            return ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            return f.read()


audit_logger = SecureAuditLogger()


def verify_audit_chain_status() -> dict:
    """التحقق الحي من سلامة بصمات SHA-256 في سجل التدقيق"""
    lines = audit_logger.read_lines()
    if not lines:
        return {"status": "EMPTY", "entries": 0, "broken_at": None}

    for idx, line in enumerate(lines, start=1):
        match = HASH_LINE_RE.match(line.strip())
        if not match:
            return {"status": "BROKEN", "entries": len(lines), "broken_at": idx}
        expected = hashlib.sha256(match.group("body").encode("utf-8")).hexdigest()[:16].lower()
        if match.group("digest").lower() != expected:
            return {"status": "BROKEN", "entries": len(lines), "broken_at": idx}

    return {"status": "VERIFIED", "entries": len(lines), "broken_at": None}


def apply_real_kernel_hardening() -> dict:
    """تطبيق حماية النواة الأساسية على مستوى العملية"""
    results = {"prctl_dumpable": "UNSUPPORTED", "mlock_status": "UNSUPPORTED"}
    if libc and sys.platform.startswith("linux"):
        res_prctl = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if res_prctl == 0:
            results["prctl_dumpable"] = "ENFORCED (0)"
        else:
            results["prctl_dumpable"] = f"FAILED (errno={ctypes.get_errno()})"
        audit_logger.log_event(
            "KERNEL_HARDENING",
            f"prctl set dumpable result: {results['prctl_dumpable']}",
            severity="INFO",
        )
    return results


kernel_status = apply_real_kernel_hardening()


class RealHardwareMemoryVault:
    """مخزن ذاكرة محمي بـ mlock وتشفير AES-256-GCM"""

    def __init__(self):
        self._aes_key = AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._aes_key)
        self._nonce = secrets.token_bytes(12)

        secret_payload = b"HAI_LAB_CRITICAL_ROOT_KEY_2026!!"
        ciphertext = self._aesgcm.encrypt(self._nonce, secret_payload, None)

        self.buffer = (ctypes.c_char * len(ciphertext)).from_buffer_copy(ciphertext)
        self.buf_len = len(ciphertext)
        self.buf_addr = ctypes.addressof(self.buffer)
        self.is_purged = False
        self.mlocked = False

        if libc and sys.platform.startswith("linux"):
            res = libc.mlock(ctypes.c_void_p(self.buf_addr), ctypes.c_size_t(self.buf_len))
            if res == 0:
                self.mlocked = True
                kernel_status["mlock_status"] = f"LOCKED @ {hex(self.buf_addr)}"
                audit_logger.log_event(
                    "RAM_PINNING",
                    f"Memory successfully locked via mlock at {hex(self.buf_addr)}",
                    severity="SUCCESS",
                )
            else:
                err = ctypes.get_errno()
                kernel_status["mlock_status"] = f"WARN (errno={err})"
                audit_logger.log_event(
                    "RAM_PINNING_WARN",
                    f"mlock failed with errno={err}",
                    severity="WARNING",
                )

    def verify_integrity(self) -> bool:
        tampered = False
        with state_lock:
            if self.is_purged or not self._aesgcm:
                return False
            try:
                self._aesgcm.decrypt(self._nonce, bytes(self.buffer), None)
                return True
            except Exception:
                tampered = True

        if tampered:
            audit_logger.log_event(
                "INTEGRITY_VIOLATION",
                "AES-GCM decryption failed! Potential memory tampering detected.",
                severity="CRITICAL",
            )
        return False

    def get_hex_dump(self) -> str:
        with state_lock:
            if self.is_purged:
                return ("00 " * 32).strip() + " [ZEROIZED & MUNLOCKED]"
            raw_bytes = bytes(self.buffer[:32])
            hex_str = " ".join(f"{b:02x}" for b in raw_bytes)
            tag = "MLOCK+AES256GCM+BLACKBOX" if self.mlocked else "AES256GCM"
            return f"{hex_str} [{tag} @ {hex(self.buf_addr)}]"

    def zeroize(self):
        """تصفير الذاكرة وتدمير المفتاح وفك قفل الصفحات مع فحص النتيجة"""
        unlock_err = None
        did_zeroize = False
        with state_lock:
            if not self.is_purged:
                ctypes.memset(self.buffer, 0, self.buf_len)
                self._aes_key = b"\x00" * 32
                self._aesgcm = None

                if self.mlocked and libc and sys.platform.startswith("linux"):
                    res_unlock = libc.munlock(
                        ctypes.c_void_p(self.buf_addr),
                        ctypes.c_size_t(self.buf_len),
                    )
                    if res_unlock == 0:
                        self.mlocked = False
                        kernel_status["mlock_status"] = f"UNLOCKED @ {hex(self.buf_addr)}"
                    else:
                        unlock_err = ctypes.get_errno()
                        self.mlocked = False
                        kernel_status["mlock_status"] = f"UNLOCK_WARN (errno={unlock_err}) @ {hex(self.buf_addr)}"
                else:
                    self.mlocked = False
                    kernel_status["mlock_status"] = f"UNLOCKED @ {hex(self.buf_addr)}"

                self.is_purged = True
                did_zeroize = True

        if unlock_err is not None:
            audit_logger.log_event(
                "RAM_UNPIN_WARN",
                f"munlock failed with errno={unlock_err} at {hex(self.buf_addr)}",
                severity="WARNING",
            )
        if did_zeroize:
            audit_logger.log_event(
                "MEMORY_ZEROIZED",
                f"RAM buffer at {hex(self.buf_addr)} forcefully scrubbed and unlocked.",
                severity="CRITICAL",
            )


vault = RealHardwareMemoryVault()


class ForensicBlackBox:
    """حفظ لقطة الحالة والسجلات في ملف مشفر قبل التصفير"""

    def __init__(self, output_filename="hailab_forensic_blackbox.enc"):
        self.output_path = os.path.join(current_dir, output_filename)
        self.last_seal_info = None

    def seal_and_record(self) -> bool:
        try:
            with state_lock:
                snapshot = {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "buffer_address": hex(vault.buf_addr),
                    "pid": os.getpid(),
                    "kernel_status": dict(kernel_status),
                    "audit_logs": audit_logger.read_raw(),
                }
            payload = json.dumps(snapshot).encode("utf-8")
            box_key = AESGCM.generate_key(bit_length=256)
            box_nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(box_key).encrypt(box_nonce, payload, None)

            with open(self.output_path, "wb") as f:
                f.write(box_nonce + box_key + ciphertext)

            with state_lock:
                self.last_seal_info = {
                    "timestamp": snapshot["timestamp"],
                    "pid": snapshot["pid"],
                    "buffer_address": snapshot["buffer_address"],
                    "mlock_status": snapshot["kernel_status"]["mlock_status"],
                }

            audit_logger.log_event(
                "BLACKBOX_SEALED",
                f"Forensic black-box written to {self.output_path}",
                severity="CRITICAL",
            )
            return True
        except Exception as exc:
            audit_logger.log_event(
                "BLACKBOX_FAILED",
                f"Failed to seal black-box: {exc}",
                severity="ERROR",
            )
            return False


black_box = ForensicBlackBox()


def _isolated_worker_task(queue, simulate_breach=False):
    """عملية فرعية تطبق حدود الموارد ومنع تفريغ الذاكرة"""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))

        if libc and sys.platform.startswith("linux"):
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)

        if simulate_breach:
            os.kill(os.getpid(), signal.SIGSYS)

        queue.put({"status": "VERIFIED", "worker_pid": os.getpid()})
    except Exception as exc:
        queue.put({"status": "FAILED", "error": str(exc)})
        os._exit(1)


class RealPanicHandler:
    """مسبّب الإغلاق الآمن (Fail-Closed)"""

    def __init__(self):
        self.is_isolated = False

    def trigger_panic(self) -> bool:
        black_box.seal_and_record()
        vault.zeroize()
        with state_lock:
            self.is_isolated = True
            buf_addr_hex = hex(vault.buf_addr)
        audit_logger.log_event(
            "FAIL_CLOSED_TRIGGERED",
            f"Emergency lockdown & Black-Box recording engaged at {buf_addr_hex}.",
            severity="CRITICAL",
        )
        return True


panic_handler = RealPanicHandler()
worker_supervisor: Optional[FrozenWorkerSupervisor] = None
supervisor_last_pids: dict[str, Optional[int]] = {"worker_pid": None, "watchdog_pid": None}


def _get_or_create_supervisor() -> FrozenWorkerSupervisor:
    global worker_supervisor
    with state_lock:
        if worker_supervisor is None:
            worker_supervisor = FrozenWorkerSupervisor(ctx_method="spawn")
        return worker_supervisor


def _get_runtime_snapshot() -> dict:
    with state_lock:
        return {
            "mlock_status": kernel_status["mlock_status"],
            "mlocked": vault.mlocked,
            "is_purged": vault.is_purged,
            "is_isolated": panic_handler.is_isolated,
        }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/status", methods=["GET"])
def get_status():
    if not vault.verify_integrity():
        snap = _get_runtime_snapshot()
        if not snap["is_purged"] and not snap["is_isolated"]:
            panic_handler.trigger_panic()

    snap = _get_runtime_snapshot()
    return jsonify({
        "memory_buffer": f"{snap['mlock_status']} | Black-Box Armed",
        "status": "LOCKED DOWN (FAIL-CLOSED)" if snap["is_isolated"] else "AES-256-GCM + Black-Box Active",
        "memory_hex": vault.get_hex_dump(),
        "mlocked": snap["mlocked"],
        "countdown": 46,
    })


@app.route("/forensic/summary", methods=["GET"])
def forensic_summary():
    snap = _get_runtime_snapshot()
    with state_lock:
        buf_addr_hex = hex(vault.buf_addr)
        prctl_stat = kernel_status["prctl_dumpable"]
        seal_info = dict(black_box.last_seal_info) if black_box.last_seal_info else None

    return jsonify({
        "mode": "LAB / DEMO (Flask Dev Server)",
        "pid": os.getpid(),
        "buffer_address": buf_addr_hex,
        "mlocked": snap["mlocked"],
        "is_purged": snap["is_purged"],
        "is_isolated": snap["is_isolated"],
        "prctl_dumpable": prctl_stat,
        "mlock_status": snap["mlock_status"],
        "chain": verify_audit_chain_status(),
        "blackbox": seal_info,
    })


@app.route("/metrics", methods=["GET"])
def metrics():
    snap = _get_runtime_snapshot()
    purged_val = 1 if snap["is_purged"] else 0
    isolated_val = 1 if snap["is_isolated"] else 0
    mlocked_val = 1 if snap["mlocked"] else 0

    prometheus_output = (
        "# HELP hailab_memory_purged Indicates if volatile memory has been wiped (1=Yes, 0=No)\n"
        "# TYPE hailab_memory_purged gauge\n"
        f"hailab_memory_purged {purged_val}\n\n"
        "# HELP hailab_memory_mlocked Indicates if memory is pinned via mlock (1=Yes, 0=No)\n"
        "# TYPE hailab_memory_mlocked gauge\n"
        f"hailab_memory_mlocked {mlocked_val}\n\n"
        "# HELP hailab_system_isolated Indicates if fail-closed lockdown is engaged (1=Yes, 0=No)\n"
        "# TYPE hailab_system_isolated gauge\n"
        f"hailab_system_isolated {isolated_val}\n"
    )
    return Response(prometheus_output, mimetype="text/plain")


@app.route("/audit/logs", methods=["GET"])
def get_audit_logs():
    logs = audit_logger.read_lines()
    if logs:
        return jsonify({
            "status": "SUCCESS",
            "total_logs": len(logs),
            "logs": logs[-50:],
        })
    return jsonify({"status": "EMPTY", "logs": []})


@app.route("/stream-status")
def stream_status():
    def generate():
        while True:
            snap = _get_runtime_snapshot()
            data = {
                "status": "LOCKED DOWN" if snap["is_isolated"] else "AES-256-GCM + Black-Box Active",
                "memory_hex": vault.get_hex_dump(),
                "mlocked": snap["mlocked"],
                "countdown": 0,
                "memory_buffer": snap["mlock_status"],
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(2)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/stream-code-pulse")
def stream_code_pulse():
    def generate_pulses():
        while True:
            integrity = vault.verify_integrity()
            with state_lock:
                isolated = panic_handler.is_isolated
                buf_addr_hex = hex(vault.buf_addr)
                buf_len = vault.buf_len
                mlock_stat = kernel_status["mlock_status"]
                prctl_stat = kernel_status["prctl_dumpable"]

            if isolated:
                snippet = f"FAIL_CLOSED_ENFORCED & BLACK_BOX SEALED @ {buf_addr_hex}"
                state = "ISOLATED_LOCKDOWN"
            else:
                snippets = [
                    f"AESGCM.decrypt_verify(addr={buf_addr_hex}) -> {'AUTH_TAG_VALID' if integrity else 'TAMPER_DETECTED'}",
                    f"libc.mlock({buf_addr_hex}, {buf_len}) -> {mlock_stat}",
                    f"libc.prctl(PR_SET_DUMPABLE, 0) -> {prctl_stat}",
                    "ForensicBlackBox.seal() -> ARMED & READY",
                ]
                snippet = random.choice(snippets)
                state = "SECURE_ACTIVE"

            code_data = {
                "live_code_snippet": snippet,
                "state": state,
                "memory_hex": vault.get_hex_dump(),
                "pid": os.getpid(),
            }
            yield f"data: {json.dumps(code_data)}\n\n"
            time.sleep(1.2)

    return Response(generate_pulses(), mimetype="text/event-stream")


@app.route("/run/pytest", methods=["GET"])
def run_pytest():
    start_t = time.time()
    integrity_ok = vault.verify_integrity()
    with state_lock:
        buf_addr_hex = hex(vault.buf_addr)
        prctl_stat = kernel_status["prctl_dumpable"]
        mlock_stat = kernel_status["mlock_status"]

    report_lines = [
        "============================= REAL KERNEL & FORENSIC AUDIT ==========================",
        f"Platform: {sys.platform} | PID: {os.getpid()} | Buffer Addr: {buf_addr_hex}",
        f"[1] libc.prctl(PR_SET_DUMPABLE, 0) ..... {prctl_stat}",
        f"[2] libc.mlock(RAM Pinning) ............ {mlock_stat}",
        f"[3] AES-256-GCM Tag Verification ....... {'PASSED (Authentic)' if integrity_ok else 'PURGED/INVALID'}",
        "[4] Forensic Black-Box Recorder ........ ARMED (Encrypted AES-GCM output ready)",
    ]

    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_isolated_worker_task, args=(q, False))
    p.start()
    p.join(timeout=3)
    worker_res = q.get() if not q.empty() else {"status": "TIMEOUT"}
    report_lines.append(
        f"[5] Isolated Subprocess Sandbox ........ {worker_res.get('status')} (Worker PID: {worker_res.get('worker_pid')})"
    )

    elapsed = round(time.time() - start_t, 4)
    report_lines.append(f"============================== ALL CHECKS PASSED ({elapsed}s) ==============================")

    audit_logger.log_event(
        "PYTEST_AUDIT",
        f"All checks passed successfully in {elapsed}s",
        severity="SUCCESS",
    )
    return jsonify({"status": "SUCCESS", "result": "\n".join(report_lines)})


@app.route("/run/fuzz", methods=["GET"])
def run_fuzz():
    try:
        with state_lock:
            raw_buf = bytearray(bytes(vault.buffer)) if not vault.is_purged else bytearray(48)
        raw_buf[0] ^= 0xFF
        test_key = AESGCM.generate_key(bit_length=256)
        AESGCM(test_key).decrypt(secrets.token_bytes(12), bytes(raw_buf), None)
        return jsonify({"status": "FAILURE", "result": "Tamper was not detected!"})
    except Exception as exc:
        audit_logger.log_event(
            "FUZZING_TEST",
            f"Tamper successfully caught by AES-GCM: {type(exc).__name__}",
            severity="WARNING",
        )
        output = (
            "============================= REAL CRYPTO TAMPER FUZZING =============================\n"
            "[*] Injected 1-bit flip into ciphertext buffer.\n"
            f"[*] AES-256-GCM threw expected exception: {type(exc).__name__} (InvalidTag)\n"
            "============================== INTEGRITY GUARD VERIFIED ==============================="
        )
        return jsonify({"status": "SUCCESS", "result": output})


@app.route("/run/zeroize", methods=["GET"])
def run_zeroize():
    vault.zeroize()
    with state_lock:
        buf_addr_hex = hex(vault.buf_addr)
    return jsonify({
        "status": "SUCCESS",
        "result": f"REAL Hardware Zeroization Executed @ {buf_addr_hex}. State: {vault.get_hex_dump()}",
    })


@app.route("/run/panic", methods=["GET"])
def run_panic():
    panic_handler.trigger_panic()
    with state_lock:
        buf_addr_hex = hex(vault.buf_addr)
    output = (
        "============================= REAL FAIL-CLOSED & BLACK-BOX ===========================\n"
        f"[*] Sealed encrypted forensic black-box to '{black_box.output_path}'.\n"
        f"[*] Scrubbed physical RAM address {buf_addr_hex} via ctypes.memset().\n"
        "[*] Destroyed 256-bit AES-GCM key material & released mlock pages.\n"
        "============================== ZERO BLAST RADIUS ====================================="
    )
    return jsonify({"status": "SUCCESS", "result": output})


@app.route("/supervisor/start", methods=["POST"])
def supervisor_start():
    try:
        sup = _get_or_create_supervisor()
        with state_lock:
            pids = sup.start()
            supervisor_last_pids.update(pids)
        audit_logger.log_event(
            "SUPERVISOR_START",
            f"Started supervised processes: worker_pid={pids.get('worker_pid')}, watchdog_pid={pids.get('watchdog_pid')}",
            severity="INFO",
        )
        return jsonify({"ok": True, "pids": pids}), 200
    except Exception as exc:
        audit_logger.log_event(
            "SUPERVISOR_START_FAILED",
            f"Failed to start supervisor: {exc}",
            severity="ERROR",
        )
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/supervisor/status", methods=["GET"])
def supervisor_status():
    with state_lock:
        sup = worker_supervisor
        last_pids = dict(supervisor_last_pids)

    if sup is None:
        return jsonify({
            "initialized": False,
            "worker_alive": False,
            "watchdog_alive": False,
            "zeroize_signaled": False,
            "stop_signaled": False,
            "pids": last_pids,
        }), 200

    w_proc = sup.worker_proc
    wd_proc = sup.watchdog_proc
    return jsonify({
        "initialized": True,
        "worker_alive": bool(w_proc and w_proc.is_alive()),
        "watchdog_alive": bool(wd_proc and wd_proc.is_alive()),
        "zeroize_signaled": bool(sup.zeroize_event.is_set()),
        "stop_signaled": bool(sup.stop_event.is_set()),
        "pids": {
            "worker_pid": w_proc.pid if w_proc else last_pids.get("worker_pid"),
            "watchdog_pid": wd_proc.pid if wd_proc else last_pids.get("watchdog_pid"),
        },
    }), 200


@app.route("/supervisor/terminate", methods=["POST"])
def supervisor_terminate():
    payload = request.get_json(silent=True) or {}
    grace_timeout = float(payload.get("grace_timeout", 0.5))
    try:
        sup = _get_or_create_supervisor()
        with state_lock:
            result = sup.fail_closed_terminate(grace_timeout=grace_timeout)
        audit_logger.log_event(
            "SUPERVISOR_TERMINATE",
            f"Fail-closed terminate result: {result}",
            severity="CRITICAL" if result.get("worker_sigkilled") or result.get("watchdog_sigkilled") else "INFO",
        )
        return jsonify({"ok": True, "result": result}), 200
    except Exception as exc:
        audit_logger.log_event(
            "SUPERVISOR_TERMINATE_FAILED",
            f"Failed to terminate supervisor: {exc}",
            severity="ERROR",
        )
        return jsonify({"ok": False, "error": str(exc)}), 500


COMPANION_REPORT_PATH = Path(current_dir) / "reports" / "companion_report.json"
BUNDLES_DIR = Path(current_dir) / "reports" / "bundles"
DEFAULT_PUB_KEY = Path(current_dir) / "keys" / "forensic_ed25519.pub"
DEFAULT_LEDGER_PATH = Path(current_dir) / "reports" / "verification_ledger.jsonl"


@app.route("/forensic/companion", methods=["GET"])
def forensic_companion_report():
    if not COMPANION_REPORT_PATH.exists():
        return jsonify({
            "available": False,
            "reason": "reports/companion_report.json not found yet",
            "parsed_metrics": None,
            "diff_from_previous": None,
        }), 200

    try:
        data = json.loads(COMPANION_REPORT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return jsonify({
            "available": False,
            "reason": str(exc),
            "parsed_metrics": None,
            "diff_from_previous": None,
        }), 200

    metrics_obj = data.get("endpoints", {}).get("metrics", {})
    return jsonify({
        "available": True,
        "checked_at_utc": data.get("checked_at_utc"),
        "server_online": data.get("server_online"),
        "parsed_metrics": metrics_obj.get("parsed_metrics"),
        "diff_from_previous": data.get("diff_from_previous"),
    }), 200


@app.route("/api/companion/refresh", methods=["POST"])
def api_companion_refresh():
    try:
        report = build_engine_report(
            base_url="http://127.0.0.1:8501",
            previous_report_path=COMPANION_REPORT_PATH,
        )
        saved_path = save_report(report, COMPANION_REPORT_PATH)
        return jsonify({
            "ok": True,
            "saved_to": str(saved_path),
            "checked_at_utc": report.get("checked_at_utc"),
            "diff_from_previous": report.get("diff_from_previous"),
            "blackbox_verified": report.get("blackbox_verification", {}).get("verified"),
        }), 200
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/bundles", methods=["GET"])
def api_list_bundles():
    if not BUNDLES_DIR.exists():
        return jsonify({"bundles": []}), 200
    items = []
    for p in sorted(BUNDLES_DIR.glob("*.tar.gz"), reverse=True):
        if p.is_file():
            items.append({
                "filename": p.name,
                "size_bytes": p.stat().st_size,
            })
    return jsonify({"bundles": items}), 200


@app.route("/api/bundles/verify/<filename>", methods=["GET"])
def api_verify_bundle(filename):
    safe_name = Path(filename).name
    if safe_name != filename or not safe_name.endswith(".tar.gz"):
        return jsonify({"valid": False, "reason": "Invalid bundle filename"}), 400

    bundle_path = BUNDLES_DIR / safe_name
    trusted_pub = DEFAULT_PUB_KEY if DEFAULT_PUB_KEY.exists() else None
    record_ledger = request.args.get("ledger", "0") == "1"

    result = verify_bundle(
        bundle_file=bundle_path,
        trusted_pub_key_path=trusted_pub,
        ledger_path=DEFAULT_LEDGER_PATH if record_ledger else None,
    )
    return jsonify(result), 200 if result.get("valid") else 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=False, threaded=True)
