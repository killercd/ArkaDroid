# DroidBoard

DroidBoard is a Python security testing application with a Flask web interface
and a Windows desktop launcher. It includes project management, an HTTP/HTTPS
proxy, traffic inspection, Repeater, Authorize, Reflector, Fuzzer, mobile tools,
and static analysis. The backend lives in `backend/app`; templates and static
assets live in `droidboard`. No separate frontend build is required.

## Setup

Use Python 3.12 and install the application in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows:

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

`requirements.txt` is also available for installing pinned dependencies.
The default database is `data/arkadroid.sqlite3`; override it with `DATABASE_URL`.
Existing database names and `ARKADROID_*` environment settings remain supported.

## Droidboard Startup

Start the Flask board:

```bash
scripts/droidboard.sh start
```

On Windows:

```bat
scripts\droidboard.bat start
```

Start the Flask board and bind both the web interface and proxy to every
network interface:

```bash
scripts/droidboard.sh start --alliface
```

On Windows:

```bat
scripts\droidboard.bat start --alliface
```

Stop it:

```bash
scripts/droidboard.sh stop
```

On Windows:

```bat
scripts\droidboard.bat stop
```

By default the board runs on `http://127.0.0.1:5000`, writes its PID to
`data/droidboard.pid`, and writes logs to `data/droidboard.log`. The proxy also
binds to `127.0.0.1` by default. Use `--alliface` only when the board and proxy
must be reachable from other machines on the network.

You can override the board host and port:

```bash
DROIDBOARD_HOST=127.0.0.1 DROIDBOARD_PORT=5050 scripts/droidboard.sh start
```

You can override the proxy bind host without using `--alliface`:

```bash
DROIDBOARD_PROXY_HOST=0.0.0.0 scripts/droidboard.sh start
```

Droidboard reads configuration from environment variables and from the `.env`
file supported by the backend settings. The HTTP exchanges page size defaults to
20 rows and can be changed with:

```bash
DROIDBOARD_PAGE_SIZE=50
```

## Droidboard desktop for Windows

The desktop launcher embeds the existing Flask board in a native pywebview
window using Microsoft Edge WebView2. The backend starts automatically on a
random `127.0.0.1` port and stops when the window closes, along with the proxy.
Uploads and downloads (including CA exports) use the embedded browser.

Build on **Windows x64 with Python 3.12** from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-droidboard-windows.ps1
```

For a specific Python installation, pass `-Python C:\path\to\python.exe`.
The script creates an isolated `.venv-desktop` and generates:

- `dist\Droidboard\Droidboard.exe`
- `dist\Droidboard-windows-x64.zip`

Distribute the ZIP and extract the **whole folder**, then double-click
`Droidboard.exe`. Python is included; the target PC needs the
[Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).
This is a portable folder build, not a standalone single-file executable.
The manual GitHub Actions workflow **Build Droidboard for Windows** also produces
the ZIP as a downloadable artifact after these files are pushed to GitHub.

Desktop data is stored in `%LOCALAPPDATA%\Droidboard\data`, the optional `.env`
file in `%LOCALAPPDATA%\Droidboard`, and startup logs in
`%LOCALAPPDATA%\Droidboard\desktop.log`. Set `ARKADROID_PROJECT_ROOT` to use a
different writable directory; existing `DATABASE_URL` and `DATA_DIR` settings
remain supported. Existing repository data is not copied automatically. To migrate,
close both applications and copy the repository's `data` folder into
`%LOCALAPPDATA%\Droidboard` (including certificates, not just the SQLite file).
The desktop build never bundles captured traffic, certificates, or local config.

For development on Windows, install `pip install -e ".[desktop]"` and run
`python scripts\droidboard_desktop.py`. Optional mobile/static-analysis features
still require their external tools on `PATH` (ADB, Java/JADX, apktool, aapt,
OpenSSL, strings, and any iOS utilities used). The `pexpect`-based interactive
iOS sideloader remains unavailable on Windows. The webview does not replace
these tools. Closing the window interrupts active work.

The server lifecycle can be tested without a GUI; WebView2 rendering, native file
dialogs and the frozen executable still need a Windows smoke test. PyInstaller
[requires a Windows build host](https://pyinstaller.org/en/stable/).

## Persistence and Logging

Persistence uses SQLite through SQLAlchemy. Intercepted requests are stored in
`http_exchanges`; relevant application calls are stored in `call_logs`.

Authorize plugin replays are stored in `authorize_exchanges`, separate from the
main HTTP history.

Repeater records created from the board are stored in `repeater_requests`, so
sent, edited, cloned, and deleted replay records persist across board sessions.

The `call_logs` table contains:

- `source`: call origin (`console`, `proxy`, `authorize`)
- `operation`: command or request
- `project_id`: related project, when available
- `exchange_id`: related HTTP exchange, when available
- `status`, `message`, `payload`
- `timestamp`

## Tests

```bash
python -m pytest backend/tests
```

`make run`, `make stop`, and `make test` launch, stop, and test DroidBoard.
