"""Locate Objection's Python environment, including pipx installations."""
from __future__ import annotations

import shlex
import shutil
from pathlib import Path

VERSION_CODE = "import frida; print(frida.__version__)"
PROBE_CODE = ("import frida, sys; device = frida.get_device(sys.argv[1], timeout=5); "
              "print('Processes:', len(device.enumerate_processes()))")


def objection_python() -> list[str] | None:
    executable = shutil.which("objection")
    if not executable:
        return None
    path = Path(executable).resolve()
    try:
        with path.open("rb") as source:
            first_line = source.read(512).split(b"\n", 1)[0].decode("utf-8", "replace")
        if first_line.startswith("#!"):
            argv = shlex.split(first_line[2:].strip())
            if argv and any("python" in Path(part).name.lower() for part in argv):
                return argv
    except (OSError, ValueError):
        pass
    # Windows console launchers and Unix virtual environments.
    for candidate in (path.parent / "python.exe", path.parent.parent / "python.exe",
                      path.parent / "python"):
        if candidate.is_file():
            return [str(candidate)]
    return None
