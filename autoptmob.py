#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from time import monotonic, sleep
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText


SCRIPT = Path(__file__).resolve().with_suffix(".sh")
DEFAULT_AVD = "Pixel_5"
DEFAULT_DEVICE = "emulator-5554"
BOOT_TIMEOUT = 180


def find_emulator() -> str | None:
    result = subprocess.run(
        ["adb", "devices"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    emulators = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].startswith("emulator-"):
            serial, state = fields[:2]
            emulators.append((state != "device", serial != DEFAULT_DEVICE, serial))
    return min(emulators)[2] if emulators else None


def start_emulator() -> subprocess.Popen:
    # Same AVD and launch options as ArkaDroid's mobile service.
    return subprocess.Popen(
        [
            "emulator", "-avd", DEFAULT_AVD, "-port", DEFAULT_DEVICE.removeprefix("emulator-"),
            "-gpu", "swiftshader_indirect", "-no-snapshot", "-no-boot-anim",
            "-memory", "4096", "-cores", "4", "-writable-system",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_for_emulator(serial: str, launched: subprocess.Popen | None) -> None:
    deadline = monotonic() + BOOT_TIMEOUT
    while monotonic() < deadline:
        if launched is not None and (status := launched.poll()) is not None:
            raise RuntimeError(f"L'emulatore {DEFAULT_AVD} è terminato (codice {status}).")
        try:
            result = subprocess.run(
                ["adb", "-s", serial, "shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip() == "1":
                return
        except subprocess.TimeoutExpired:
            pass
        sleep(1)
    raise RuntimeError(f"L'emulatore {serial} non è pronto dopo {BOOT_TIMEOUT} secondi.")


class ProxyWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.messages: Queue[str | int] = Queue()
        self.status = tk.StringVar(value="Pronto")
        self.invisible = tk.BooleanVar(value=True)
        self.busy = False

        root.title("ArkaDroid · Proxy")
        root.minsize(460, 280)
        root.protocol("WM_DELETE_WINDOW", self.close)

        panel = ttk.Frame(root, padding=12)
        panel.pack(fill="both", expand=True)
        controls = ttk.Frame(panel)
        controls.pack(fill="x")
        self.start = ttk.Button(controls, text="Start", command=lambda: self.run("start"))
        self.stop = ttk.Button(controls, text="Stop", command=lambda: self.run("stop"))
        self.start.pack(side="left")
        self.stop.pack(side="left", padx=(8, 0))
        self.mode = ttk.Checkbutton(controls, text="Proxy invisibile", variable=self.invisible)
        self.mode.pack(side="left", padx=(12, 0))
        ttk.Label(controls, textvariable=self.status).pack(side="left", padx=12)
        self.output = ScrolledText(panel, width=76, height=18, wrap="word", state="disabled")
        self.output.pack(fill="both", expand=True, pady=(12, 0))

    def run(self, action: str) -> None:
        mode_flag = "--invisible" if self.invisible.get() else "--normal"
        self.busy = True
        self.start.state(["disabled"])
        self.stop.state(["disabled"])
        self.mode.state(["disabled"])
        self.status.set(f"{action.capitalize()} in corso…")
        Thread(target=self.run_script, args=(action, mode_flag), daemon=True).start()
        self.root.after(50, self.read_messages)

    def run_script(self, action: str, mode_flag: str) -> None:
        try:
            serial = find_emulator()
            launched = None
            if serial is None:
                serial = DEFAULT_DEVICE
                self.messages.put(f"Avvio dell'emulatore {DEFAULT_AVD}…\n")
                launched = start_emulator()
            self.messages.put(f"Attendo che {serial} sia pronto…\n")
            wait_for_emulator(serial, launched)
            self.messages.put(f"$ {SCRIPT.name} {action} {mode_flag} ({serial})\n")
            with subprocess.Popen(
                ["bash", str(SCRIPT), action, mode_flag],
                env={**os.environ, "AUTOPTMOB_DEVICE": serial},
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            ) as process:
                for line in process.stdout:
                    self.messages.put(line)
                self.messages.put(process.wait())
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            self.messages.put(f"Errore: {error}\n")
            self.messages.put(1)

    def read_messages(self) -> None:
        try:
            while True:
                message = self.messages.get_nowait()
                if isinstance(message, int):
                    self.status.set("Completato" if message == 0 else f"Errore (codice {message})")
                    self.start.state(["!disabled"])
                    self.stop.state(["!disabled"])
                    self.mode.state(["!disabled"])
                    self.busy = False
                    return
                self.append_output(message)
        except Empty:
            self.root.after(50, self.read_messages)

    def append_output(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def close(self) -> None:
        if self.busy:
            self.root.bell()
            return
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ProxyWindow(root)
    root.mainloop()
