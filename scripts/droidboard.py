from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
PID_FILE = ROOT_DIR / "data" / "droidboard.pid"
LOG_FILE = ROOT_DIR / "data" / "droidboard.log"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop"))
    parser.add_argument("--alliface", action="store_true")
    args = parser.parse_args(argv[1:])

    host = os.environ.get("DROIDBOARD_HOST", "127.0.0.1")
    port = os.environ.get("DROIDBOARD_PORT", "5000")
    proxy_host = os.environ.get("DROIDBOARD_PROXY_HOST") or os.environ.get("ARKADROID_PROXY_HOST", "127.0.0.1")
    if args.alliface:
        host = "0.0.0.0"
        proxy_host = "0.0.0.0"

    if args.action == "start":
        return start_app(host, port, proxy_host)
    return stop_app()


def start_app(host: str, port: str, proxy_host: str) -> int:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    running_pid = running_process_id()
    if running_pid is not None:
        print(f"Droidboard is already running with PID {running_pid} on http://{host}:{port}")
        return 0

    remove_pid_file()
    env = os.environ.copy()
    backend_path = str(ROOT_DIR / "backend")
    env["PYTHONPATH"] = backend_path + os.pathsep + env.get("PYTHONPATH", "")
    env["ARKADROID_PROXY_HOST"] = proxy_host

    with LOG_FILE.open("ab") as log_file:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "flask",
                "--app",
                "droidboard.app:app",
                "run",
                "--host",
                host,
                "--port",
                port,
            ],
            cwd=ROOT_DIR,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
    PID_FILE.write_text(str(process.pid), encoding="utf-8")
    print(f"Droidboard started with PID {process.pid} on http://{host}:{port}")
    print(f"Proxy bind host: {proxy_host}")
    print(f"Log file: {LOG_FILE}")
    return 0


def stop_app() -> int:
    running_pid = running_process_id()
    if running_pid is None:
        remove_pid_file()
        print("Droidboard is not running.")
        return 0

    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(running_pid), "/T", "/F"], check=False, stdout=subprocess.DEVNULL)
        remove_pid_file()
        print("Droidboard stopped.")
        return 0

    os.kill(running_pid, signal.SIGTERM)
    for _ in range(20):
        if not process_exists(running_pid):
            remove_pid_file()
            print("Droidboard stopped.")
            return 0
        time.sleep(0.2)

    os.kill(running_pid, signal.SIGKILL)
    remove_pid_file()
    print("Droidboard force-stopped.")
    return 0


def running_process_id() -> int | None:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return pid if process_exists(pid) else None


def process_exists(pid: int) -> bool:
    if os.name == "nt":
        completed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            check=False,
            capture_output=True,
            text=True,
        )
        return str(pid) in completed.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def remove_pid_file() -> None:
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
