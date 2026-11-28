import importlib.util
import multiprocessing as mp
import os
import signal
from pathlib import Path
from typing import Callable, Optional


def _resolve_engine_path(engine_path: Optional[Path] = None) -> Path:
    base_dir = Path(__file__).resolve().parent
    candidates = [
        engine_path,
        base_dir / "src" / "scope_b" / "engine.py",
        base_dir / "src" / "scope b" / "engine.py",
        base_dir / "src" / "engine.py",
    ]
    resolved = next((Path(p).resolve() for p in candidates if p is not None and Path(p).exists()), None)
    if resolved is None:
        raise FileNotFoundError(f"Unable to locate engine.py in candidates: {candidates}")
    return resolved


def load_scope_b_engine(engine_path: Optional[Path] = None) -> tuple[Callable, Callable]:
    resolved_path = _resolve_engine_path(engine_path)
    spec = importlib.util.spec_from_file_location("hailab_scope_b_engine", resolved_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load engine module from {resolved_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "worker_process_target") or not hasattr(module, "watchdog_process_target"):
        raise ImportError(f"Required process targets missing in {resolved_path}")
    return module.worker_process_target, module.watchdog_process_target


def _worker_entry(engine_path_str: str, zeroize_event, stop_event) -> None:
    worker_target, _ = load_scope_b_engine(Path(engine_path_str))
    worker_target(zeroize_event, stop_event)


def _watchdog_entry(engine_path_str: str, worker_pid: int, zeroize_event, stop_event) -> None:
    _, watchdog_target = load_scope_b_engine(Path(engine_path_str))
    watchdog_target(worker_pid, zeroize_event, stop_event)


class FrozenWorkerSupervisor:
    def __init__(
        self,
        ctx_method: str = "spawn",
        worker_target: Optional[Callable] = None,
        watchdog_target: Optional[Callable] = None,
        engine_path: Optional[Path] = None,
    ) -> None:
        self.engine_path = _resolve_engine_path(engine_path)
        self._custom_worker_target = worker_target
        self._custom_watchdog_target = watchdog_target

        # التحقق المسبق من وجود الأهداف دون تمرير دوال غير قابلة للـ pickle تحت spawn
        if self._custom_worker_target is None or self._custom_watchdog_target is None:
            loaded_worker, loaded_watchdog = load_scope_b_engine(self.engine_path)
            if self._custom_worker_target is None:
                self._custom_worker_target = loaded_worker
            if self._custom_watchdog_target is None:
                self._custom_watchdog_target = loaded_watchdog

        self.ctx = mp.get_context(ctx_method)
        self.zeroize_event = self.ctx.Event()
        self.stop_event = self.ctx.Event()
        self.worker_proc: Optional[mp.Process] = None
        self.watchdog_proc: Optional[mp.Process] = None

    def start(self) -> dict[str, Optional[int]]:
        if self.worker_proc is None or not self.worker_proc.is_alive():
            self.zeroize_event.clear()
            self.stop_event.clear()
            self.worker_proc = self.ctx.Process(
                target=_worker_entry,
                args=(str(self.engine_path), self.zeroize_event, self.stop_event),
                name="frozen_worker",
            )
            self.worker_proc.start()

        if self.watchdog_proc is None or not self.watchdog_proc.is_alive():
            worker_pid = self.worker_proc.pid if self.worker_proc else -1
            self.watchdog_proc = self.ctx.Process(
                target=_watchdog_entry,
                args=(str(self.engine_path), worker_pid, self.zeroize_event, self.stop_event),
                name="frozen_watchdog",
            )
            self.watchdog_proc.start()

        return {
            "worker_pid": self.worker_proc.pid if self.worker_proc else None,
            "watchdog_pid": self.watchdog_proc.pid if self.watchdog_proc else None,
        }

    def _stop_process(self, proc: Optional[mp.Process], grace_timeout: float) -> tuple[bool, bool]:
        if proc is None or not proc.is_alive():
            return False, False

        proc.join(timeout=grace_timeout)
        if not proc.is_alive():
            return False, False

        if proc.pid:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.join(timeout=grace_timeout)
        return True, bool(proc.is_alive())

    def fail_closed_terminate(self, grace_timeout: float = 0.5) -> dict[str, object]:
        self.zeroize_event.set()
        self.stop_event.set()

        worker_sigkilled, worker_still_alive = self._stop_process(self.worker_proc, grace_timeout)

        if self.watchdog_proc and self.watchdog_proc.is_alive():
            self.watchdog_proc.terminate()
        watchdog_sigkilled, watchdog_still_alive = self._stop_process(
            self.watchdog_proc, grace_timeout
        )

        zeroize_confirmed = not worker_sigkilled and not worker_still_alive

        return {
            "zeroize_signaled": True,
            "zeroize_confirmed": zeroize_confirmed,
            "worker_sigkilled": worker_sigkilled,
            "watchdog_sigkilled": watchdog_sigkilled,
            "worker_alive": worker_still_alive,
            "watchdog_alive": watchdog_still_alive,
        }
