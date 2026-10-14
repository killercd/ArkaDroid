from __future__ import annotations

import hashlib
import json
import posixpath
import re
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from time import perf_counter
from urllib.parse import parse_qsl, urljoin, urlsplit

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from sqlalchemy import asc, desc, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import defer
from werkzeug.utils import secure_filename

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.db.session import SessionLocal, init_db  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.models.authorize import AuthorizeExchange, AuthorizeUser  # noqa: E402
from app.models.call_log import CallLog  # noqa: E402
from app.models.http import HttpExchange  # noqa: E402
from app.models.projects import Project  # noqa: E402
from app.models.repeater import RepeaterRequest  # noqa: E402
from app.models.show_response import ShowResponseLink  # noqa: E402
from app.services.authorize import remove_authorize_user, set_authorize_enabled  # noqa: E402
from app.services.board_cleanup import clear_authorize_history, clear_http_exchanges  # noqa: E402
from app.services.ca import ensure_ca  # noqa: E402
from app.services.curl import build_curl  # noqa: E402
from app.services import fuzzer  # noqa: E402
from app.services import mobile as mobile_service  # noqa: E402
from app.services import ios_install  # noqa: E402
from app.services.repeater import exchange_url, method_and_url, send_repeater_request  # noqa: E402
from app.services.show_response import HOP_BY_HOP_HEADERS, parse_raw_response  # noqa: E402
from app.services.proxy import proxy_controller  # noqa: E402
from app.services.reflector import set_reflector_enabled  # noqa: E402


METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
FUZZ_JOBS: dict[int, dict] = {}
FUZZ_LOCK = threading.Lock()
FUZZ_JOB_COUNTER = 0
STATIC_ANALYSIS_RESULTS: dict[str, dict] = {}
EXCHANGE_SORT_COLUMNS = {
    "id": HttpExchange.id,
    "timestamp": HttpExchange.timestamp,
    "method": HttpExchange.method,
    "host": HttpExchange.host,
    "path": HttpExchange.path,
    "status": HttpExchange.status_code,
    "reflected": HttpExchange.reflecte_params,
}

DASHBOARD_SECRET_RULES = (
    ("email", "Email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), 0),
    ("token", "JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),
    ("token", "Bearer token", re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{12,})\b", re.IGNORECASE), 1),
    ("token", "Basic auth", re.compile(r"\bBasic\s+([A-Za-z0-9+/=]{12,})\b", re.IGNORECASE), 1),
    ("token", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0),
    ("token", "GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"), 0),
    ("token", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("password", "Possible password", re.compile(r'''(?ix)\b(?:password|passwd|pwd)\b["']?\s*[:=]\s*["']?([^"'\s<>,;]{4,})'''), 1),
    ("secret", "Secret/API key", re.compile(r'''(?ix)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|refresh[_-]?token|secret|session[_-]?id)\b["']?\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{8,})'''), 1),
    ("private_key", "Private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE), 0),
    ("base64", "Possible Base64", re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])"), 0),
)

DASHBOARD_SECRET_CATEGORY_LABELS = {
    "email": "Email",
    "token": "Tokens and credentials",
    "password": "Possible passwords",
    "secret": "Secrets and API keys",
    "private_key": "Private keys",
    "base64": "Base64",
}

DASHBOARD_SECTIONS = (
    ("status", "Status codes"),
    ("secrets", "Possible secrets"),
    ("api", "API JSON / XML"),
    ("hidden", "Hidden endpoints"),
    ("authorize", "Authorize"),
    ("fuzzer", "Fuzzer"),
    ("reflector", "Reflector"),
    ("error", "Error"),
)
DASHBOARD_HIDDEN_PAGE_SIZE = 200
ERROR_SIGNATURES_PATH = Path("/tmp/errlist.txt")
FUZZER_SORT_COLUMNS = {"index", "source", "value", "status", "size", "duration", "url", "error"}
DASHBOARD_ABSOLUTE_ENDPOINT_PATTERN = re.compile(r'''https?://[^\s"'<>\\]+''', re.IGNORECASE)
DASHBOARD_RELATIVE_ENDPOINT_PATTERN = re.compile(
    r'''["'`](\/[^\s"'`<>\\]{1,2047})["'`]''', re.IGNORECASE
)
DASHBOARD_ENDPOINT_HINT_PATTERN = re.compile(
    r"(?:/api(?:/|$)|\.json(?:[?#]|$)|\.xml(?:[?#]|$)|graphql|endpoint|/v\d+(?:/|$))",
    re.IGNORECASE,
)


def create_app() -> Flask:
    init_db()
    flask_app = Flask(__name__)
    ios_jobs = ios_install.InstallJobs()
    flask_app.config["SECRET_KEY"] = "arkadroid-board-dev"
    flask_app.jinja_env.globals["dashboard_exchange_url"] = _dashboard_exchange_url

    @flask_app.after_request
    def async_redirect_response(response):
        if not _wants_json_response() or response.status_code not in {301, 302, 303, 307, 308}:
            return response
        messages = [{"category": category, "message": message} for category, message in session.pop("_flashes", [])]
        location = response.headers.get("Location") or url_for("index")
        return jsonify(
            {
                "ok": not any(item["category"] == "error" for item in messages),
                "messages": messages,
                "redirect": location,
            }
        )

    @flask_app.get("/")
    def index():
        project_id = _selected_project_id()
        tab = request.args.get("tab", "exchanges")
        with SessionLocal() as db:
            context = _base_context(db, project_id, tab)
            project_id = context["project"].id if context["project"] is not None else None
            if project_id is not None:
                if tab == "repeater":
                    context.update(_repeater_context(db, project_id))
                elif tab == "authorize":
                    context.update(_authorize_context(db, project_id))
                elif tab == "fuzzer":
                    context.update(_fuzzer_context(db, project_id))
                elif tab == "dashboard":
                    context.update(_dashboard_context(db, project_id))
                elif tab == "intercept":
                    context.update(_intercept_context(project_id))
                elif tab == "mobile":
                    context.update(_mobile_context(project_id))
                elif tab == "static-analysis":
                    context.update(_static_analysis_context())
                else:
                    context.update(_exchanges_context(db, project_id))
            return render_template("board.html", **context)

    @flask_app.post("/projects/create")
    def create_project():
        name = request.form.get("name", "").strip()
        port = _int_form("port", 8080)
        if not name:
            flash("Project name is required.", "error")
            return _back()
        with SessionLocal() as db:
            listen_host = _proxy_listen_host({})
            project = Project(
                name=name,
                proxy_config={"port": port, "listen_all_interfaces": listen_host == "0.0.0.0"},
            )
            db.add(project)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                flash(f"A project named {name!r} already exists.", "error")
                return _back()
            proxy_controller.open_project(
                db, project.id, port, listen_host=listen_host, invisible_proxy=False,
            )
            flash(f"Created and opened project #{project.id}.", "success")
            return redirect(url_for("index", project_id=project.id))

    @flask_app.post("/projects/open")
    def open_project():
        project_id = _int_form("project_id")
        with SessionLocal() as db:
            project = db.get(Project, project_id)
            if project is None:
                flash("Project not found.", "error")
                return _back()
            config = project.proxy_config or {}
            port = int(config.get("port", 8080))
            proxy_controller.open_project(
                db,
                project.id,
                port,
                listen_host=_proxy_listen_host(config),
                invisible_proxy=bool(config.get("invisible_proxy")),
            )
            flash(f"Opened project #{project.id}.", "success")
            return redirect(url_for("index", project_id=project.id, tab=request.args.get("tab", "exchanges")))

    @flask_app.post("/projects/<int:project_id>/delete")
    def delete_project(project_id: int):
        with SessionLocal() as db:
            project = db.get(Project, project_id)
            if project is None:
                flash("Project not found.", "error")
                return _back()
            if proxy_controller.state.active_project_id == project_id:
                proxy_controller.stop(db)
                proxy_controller.state.active_project_id = None
            db.query(AuthorizeExchange).filter(AuthorizeExchange.project_id == project_id).delete(synchronize_session=False)
            db.query(AuthorizeUser).filter(AuthorizeUser.project_id == project_id).delete(synchronize_session=False)
            db.query(RepeaterRequest).filter(RepeaterRequest.project_id == project_id).delete(synchronize_session=False)
            db.query(ShowResponseLink).filter(ShowResponseLink.project_id == project_id).delete(synchronize_session=False)
            db.query(HttpExchange).filter(HttpExchange.project_id == project_id).delete(synchronize_session=False)
            db.query(CallLog).filter(CallLog.project_id == project_id).delete(synchronize_session=False)
            db.delete(project)
            db.commit()
            flash(f"Removed project #{project_id}.", "success")
            return redirect(url_for("index"))

    @flask_app.post("/exchanges/clear")
    def clear_exchanges():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        with SessionLocal() as db:
            deleted = clear_http_exchanges(db, project_id)
            db.commit()
        flash(f"Cleared {deleted} HTTP exchange records.", "success")
        return redirect(url_for("index", project_id=project_id, tab="exchanges"))

    @flask_app.post("/proxy/<action>")
    def proxy(action: str):
        with SessionLocal() as db:
            try:
                if action == "start":
                    project_id = _selected_project_id()
                    project = db.get(Project, project_id) if project_id is not None else None
                    if project is None:
                        flash("Select a project.", "error")
                        db.commit()
                        return _back()
                    if "invisible_proxy_present" in request.form:
                        enabled = request.form.get("invisible_proxy") == "on"
                        project.proxy_config = {**(project.proxy_config or {}), "invisible_proxy": enabled}
                        proxy_controller.set_invisible_proxy(enabled)
                    if "listen_all_interfaces_present" in request.form:
                        listen_all = request.form.get("listen_all_interfaces") == "on"
                        project.proxy_config = {
                            **(project.proxy_config or {}),
                            "listen_all_interfaces": listen_all,
                        }
                        proxy_controller.set_listen_host(_proxy_listen_host(project.proxy_config))
                    proxy_controller.start(db)
                    flash(
                        f"Proxy started on {proxy_controller.state.listen_host}:"
                        f"{proxy_controller.state.listen_port}.",
                        "success",
                    )
                elif action == "stop":
                    proxy_controller.stop(db)
                    flash("Proxy stopped.", "success")
                elif action == "config":
                    project_id = _selected_project_id()
                    project = db.get(Project, project_id) if project_id is not None else None
                    if project is None:
                        flash("Select a project.", "error")
                    elif proxy_controller.state.running:
                        flash("Stop the proxy before changing proxy mode.", "error")
                    else:
                        enabled = request.form.get("invisible_proxy") == "on"
                        listen_all = request.form.get("listen_all_interfaces") == "on"
                        project.proxy_config = {
                            **(project.proxy_config or {}),
                            "invisible_proxy": enabled,
                            "listen_all_interfaces": listen_all,
                        }
                        proxy_controller.set_invisible_proxy(enabled)
                        proxy_controller.set_listen_host(_proxy_listen_host(project.proxy_config))
                        flash("Proxy settings updated.", "success")
                else:
                    flash("Invalid proxy action.", "error")
            except Exception as exc:  # noqa: BLE001
                flash(str(exc), "error")
            db.commit()
        return _back()

    @flask_app.post("/intercept/toggle")
    def toggle_intercept():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        enabled = request.form.get("enabled") == "on"
        proxy_controller.set_intercept_enabled(enabled)
        flash(f"Intercept {'enabled' if enabled else 'disabled'}.", "success")
        return redirect(url_for("index", project_id=project_id, tab="intercept"))

    @flask_app.post("/intercept/<int:item_id>/resolve")
    def resolve_intercept(item_id: int):
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        action = request.form.get("action", "")
        try:
            if action == "forward-original":
                resolved = proxy_controller.resolve_intercept(item_id, "forward")
                label = "forwarded"
            elif action == "forward-edited":
                resolved = proxy_controller.resolve_intercept(item_id, "forward", request.form.get("raw", ""))
                label = "forwarded with edits"
            elif action == "drop":
                resolved = proxy_controller.resolve_intercept(item_id, "drop")
                label = "dropped"
            else:
                raise ValueError("Invalid intercept action.")
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index", project_id=project_id, tab="intercept"))
        flash(f"Intercept #{item_id} {label}." if resolved else f"Intercept #{item_id} is no longer pending.", "success" if resolved else "error")
        return redirect(url_for("index", project_id=project_id, tab="intercept"))

    @flask_app.post("/intercept/clear")
    def clear_intercepts():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        deleted = proxy_controller.clear_resolved_intercepts(project_id)
        flash(f"Cleared {deleted} resolved intercept items.", "success")
        return redirect(url_for("index", project_id=project_id, tab="intercept"))

    @flask_app.get("/ca/export")
    def export_ca():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Open a project before exporting the CA.", "error")
            return _back()
        cert = ensure_ca(project_id)
        return flask_app.response_class(
            cert,
            mimetype="application/x-x509-ca-cert",
            headers={"Content-Disposition": 'attachment; filename="arkadroid-ca.crt"'},
        )

    @flask_app.post("/mobile/<action>")
    def mobile(action: str):
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        try:
            result = _run_mobile_action(project_id, action)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index", project_id=project_id, tab="mobile"))
        _store_mobile_result(result, "android")
        flash(f"Mobile action {'completed' if result.ok else 'failed'}: {result.title}.", "success" if result.ok else "error")
        return redirect(url_for("index", project_id=project_id, tab="mobile"))

    def ios_install_access():
        project_id = _selected_project_id()
        if project_id is None:
            abort(400, "Select a project.")
        owner = session.get("ios_install_owner")
        if not owner:
            abort(403)
        if request.method == "POST" and not secrets.compare_digest(
            request.form.get("csrf_token", ""), session.get("ios_install_csrf", "missing")
        ):
            abort(403)
        return project_id, owner

    @flask_app.get("/mobile/ios/devices")
    def mobile_ios_devices():
        ios_install_access()
        result = ios_install.devices(network=request.args.get("network") == "1")
        udids = []
        if result.ok:
            for line in result.output.splitlines():
                try:
                    udids.append(ios_install.validate_udid(line))
                except ValueError:
                    continue
        return jsonify(ok=result.ok, devices=udids, message=result.output)

    @flask_app.post("/mobile/ios/install")
    def mobile_ios_install():
        project_id, owner = ios_install_access()
        mode = request.form.get("mode", "apple_id")
        if mode == "apple_id" and not request.is_secure and request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify(ok=False, error="Apple ID authentication requires localhost or HTTPS."), 400
        try:
            job = ios_jobs.start(owner, project_id, _mobile_ipa_path(project_id),
                                 request.form.get("udid", ""), mode,
                                 network=request.form.get("network") == "on")
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        session["ios_install_job"] = job.id
        return jsonify(ok=True, job=job.snapshot()), 202

    @flask_app.route("/mobile/ios/install/<job_id>", methods=["GET", "POST"])
    def mobile_ios_install_job(job_id: str):
        project_id, owner = ios_install_access()
        job = ios_jobs.get(job_id, owner, project_id)
        if job is None:
            abort(404)
        if request.method == "POST":
            try:
                if request.form.get("action") == "cancel":
                    if job.mode != "apple_id":
                        raise ValueError("Wait for the device installation to finish.")
                    job.cancelled.set()
                elif request.form.get("action") == "answer":
                    if not request.is_secure and request.remote_addr not in {"127.0.0.1", "::1"}:
                        raise ValueError("Apple ID authentication requires localhost or HTTPS.")
                    job.answer(request.form.get("challenge", ""), request.form.get("answer", ""))
                else:
                    raise ValueError("Invalid installation action.")
            except ValueError as exc:
                return jsonify(ok=False, error=str(exc)), 400
        response = jsonify(ok=True, job=job.snapshot())
        response.headers["Cache-Control"] = "no-store"
        return response

    @flask_app.post("/mobile/ios/<action>")
    def mobile_ios(action: str):
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        try:
            result = _run_mobile_ios_action(project_id, action)
        except ValueError as exc:
            session["mobile_os"] = "ios"
            _store_mobile_result(mobile_service.MobileResult(False, "iOS IPA scan", "", str(exc)), "ios")
            flash(str(exc), "error")
            return redirect(url_for("index", project_id=project_id, tab="mobile", mobile_os="ios"))
        _store_mobile_result(result, "ios")
        flash(f"iOS action {'completed' if result.ok else 'failed'}: {result.title}.", "success" if result.ok else "error")
        return redirect(url_for("index", project_id=project_id, tab="mobile", mobile_os="ios"))

    @flask_app.get("/mobile/remote-files")
    def mobile_remote_files():
        project_id = _selected_project_id()
        if project_id is None:
            return jsonify({"ok": False, "error": "Select a project."}), 400
        current_path = _normalize_remote_path(request.args.get("path", "/sdcard"))
        entries, result = mobile_service.list_remote_dir(current_path)
        if not result.ok:
            return jsonify({"ok": False, "error": result.output or "Unable to list remote directory.", "command": result.command}), 400
        return jsonify(
            {
                "ok": True,
                "path": current_path,
                "parent": _remote_parent_path(current_path),
                "entries": [
                    {
                        "name": entry.name,
                        "path": _remote_entry_path(current_path, entry.name),
                        "is_dir": entry.is_dir,
                    }
                    for entry in entries
                    if entry.name != ".."
                ],
            }
        )

    @flask_app.get("/mobile/android-ca/download")
    def download_android_ca():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        result = mobile_service.export_android_ca(project_id)
        if not result.ok:
            _store_mobile_result(result, "android")
            flash("Unable to export Android CA.", "error")
            return redirect(url_for("index", project_id=project_id, tab="mobile"))
        path = Path(result.artifact)
        return send_file(path, mimetype="application/x-x509-ca-cert", as_attachment=True, download_name=path.name)

    @flask_app.post("/static-analysis/strings")
    def static_analysis_strings():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        uploaded = request.files.get("binary_file")
        if uploaded is None or not uploaded.filename:
            flash("Binary file is required.", "error")
            return redirect(url_for("index", project_id=project_id, tab="static-analysis"))
        try:
            path = _save_static_analysis_upload(project_id, uploaded)
            result = _extract_strings(path)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index", project_id=project_id, tab="static-analysis"))
        except FileNotFoundError:
            flash("strings command not found.", "error")
            return redirect(url_for("index", project_id=project_id, tab="static-analysis"))
        except subprocess.TimeoutExpired:
            flash("strings command timed out.", "error")
            return redirect(url_for("index", project_id=project_id, tab="static-analysis"))
        token = secrets.token_urlsafe(16)
        STATIC_ANALYSIS_RESULTS[token] = {
            "filename": path.name,
            "path": str(path),
            "returncode": result.returncode,
            "strings": result.stdout.decode("utf-8", errors="replace"),
            "error": result.stderr.decode("utf-8", errors="replace"),
        }
        session["static_analysis_result"] = token
        if result.returncode == 0:
            flash(f"Extracted strings from {path.name}.", "success")
        else:
            flash(f"strings exited with code {result.returncode}.", "error")
        return redirect(url_for("index", project_id=project_id, tab="static-analysis"))

    @flask_app.post("/exchanges/<int:exchange_id>/to-repeater")
    def exchange_to_repeater(exchange_id: int):
        with SessionLocal() as db:
            exchange = db.get(HttpExchange, exchange_id)
            if exchange is None:
                flash("Request not found.", "error")
                return _back()
            item = RepeaterRequest(
                project_id=exchange.project_id,
                source_exchange_id=exchange.id,
                name=f"Exchange #{exchange.id}",
                method=exchange.method,
                url=exchange_url(exchange),
                request_raw=exchange.request_raw,
            )
            db.add(item)
            db.commit()
            flash(f"Request #{exchange.id} sent to the repeater.", "success")
            return redirect(url_for("index", project_id=exchange.project_id, tab="repeater"))

    @flask_app.post("/authorize/exchanges/<int:exchange_id>/to-repeater")
    def authorize_to_repeater(exchange_id: int):
        with SessionLocal() as db:
            exchange = db.get(AuthorizeExchange, exchange_id)
            if exchange is None:
                flash("Request not found.", "error")
                return _back()
            item = RepeaterRequest(
                project_id=exchange.project_id,
                name=f"Authorize #{exchange.id} · {exchange.user_name}",
                method=exchange.method,
                url=exchange.url,
                request_raw=exchange.request_raw,
            )
            db.add(item)
            db.commit()
            flash(f"Authorize request #{exchange.id} sent to the repeater.", "success")
            return redirect(url_for("index", project_id=exchange.project_id, tab="repeater"))

    @flask_app.get("/dashboard/exchanges/<int:exchange_id>/raw")
    def dashboard_exchange_raw(exchange_id: int):
        project_id = request.args.get("project_id", type=int)
        with SessionLocal() as db:
            exchange = db.get(HttpExchange, exchange_id)
            if exchange is None or (project_id is not None and exchange.project_id != project_id):
                return jsonify({"ok": False, "error": "Request not found."}), 404
            return jsonify(
                {
                    "ok": True,
                    "request_raw": exchange.request_raw or "",
                    "response_raw": exchange.response_raw or "",
                }
            )

    @flask_app.get("/raw/<source_type>/<int:source_id>")
    def raw_exchange(source_type: str, source_id: int):
        project_id = request.args.get("project_id", type=int)
        model = {"http-exchange": HttpExchange, "authorize": AuthorizeExchange}.get(source_type)
        if model is None:
            return jsonify({"ok": False, "error": "Unsupported raw source."}), 404
        with SessionLocal() as db:
            item = db.get(model, source_id)
            if item is None or (project_id is not None and item.project_id != project_id):
                return jsonify({"ok": False, "error": "Request not found."}), 404
            return jsonify(
                {"ok": True, "request_raw": item.request_raw or "", "response_raw": item.response_raw or ""}
            )

    @flask_app.get("/fuzzer/<int:job_id>/results/<int:result_index>/raw")
    def fuzzer_result_raw(job_id: int, result_index: int):
        project_id = request.args.get("project_id", type=int)
        with FUZZ_LOCK:
            job = FUZZ_JOBS.get(job_id)
            if job is None or (project_id is not None and job["project_id"] != project_id):
                return jsonify({"ok": False, "error": "Fuzzer job not found."}), 404
            results = job["results"]
            if result_index < 1 or result_index > len(results):
                return jsonify({"ok": False, "error": "Fuzzer result not found."}), 404
            result = dict(results[result_index - 1])
        return jsonify(
            {
                "ok": True,
                "request_raw": result.get("request_raw") or "",
                "response_raw": result.get("response_raw") or "",
            }
        )

    @flask_app.post("/exchanges/<int:exchange_id>/to-fuzzer")
    def exchange_to_fuzzer(exchange_id: int):
        with SessionLocal() as db:
            exchange = db.get(HttpExchange, exchange_id)
            if exchange is None:
                flash("Request not found.", "error")
                return _back()
            session["fuzzer_prefill"] = {
                "range": "1-500",
                "max_thread": 1,
                "delay": 0,
                "request_raw": exchange.request_raw,
                "show_response": False,
            }
            flash(f"Request #{exchange.id} sent to the fuzzer.", "success")
            return redirect(url_for("index", project_id=exchange.project_id, tab="fuzzer"))

    @flask_app.post("/repeater/create")
    def create_repeater():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        request_raw = request.form.get("request_raw", "")
        if not request_raw.strip():
            flash("Raw request is required.", "error")
            return _back()
        try:
            method, url = method_and_url(request_raw)
        except ValueError as exc:
            flash(str(exc), "error")
            return _back()
        with SessionLocal() as db:
            item = RepeaterRequest(
                project_id=project_id,
                name=request.form.get("name", "").strip(),
                method=method,
                url=url,
                request_raw=request_raw,
            )
            db.add(item)
            db.commit()
            flash(f"Created repeater #{item.id}.", "success")
        return redirect(url_for("index", project_id=project_id, tab="repeater"))

    @flask_app.post("/repeater/clear")
    def clear_repeater():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        with SessionLocal() as db:
            deleted = (
                db.query(RepeaterRequest)
                .filter(RepeaterRequest.project_id == project_id)
                .delete(synchronize_session=False)
            )
            db.commit()
        flash(f"Cleared {deleted} repeater records.", "success")
        return redirect(url_for("index", project_id=project_id, tab="repeater"))

    @flask_app.post("/repeater/<int:item_id>/save")
    def save_repeater(item_id: int):
        with SessionLocal() as db:
            item = db.get(RepeaterRequest, item_id)
            if item is None:
                flash("Repeater record not found.", "error")
                return _back()
            try:
                _update_repeater_from_form(item)
            except ValueError as exc:
                flash(str(exc), "error")
                return _back()
            db.commit()
            flash(f"Saved repeater #{item.id}.", "success")
            return redirect(url_for("index", project_id=item.project_id, tab="repeater"))

    @flask_app.post("/repeater/<int:item_id>/send")
    def send_repeater(item_id: int):
        with SessionLocal() as db:
            item = db.get(RepeaterRequest, item_id)
            if item is None:
                flash("Repeater record not found.", "error")
                return _back()
            started = perf_counter()
            try:
                _update_repeater_from_form(item)
                response_raw = send_repeater_request(item.method, item.url, item.request_raw)
                item.response_raw = response_raw
                item.status_code = _response_status(response_raw)
                item.response_size = len(_raw_body(response_raw).encode())
                item.duration_ms = int((perf_counter() - started) * 1000)
                item.error = ""
                flash(f"Replay #{item.id} completed with status {item.status_code}.", "success")
            except Exception as exc:  # noqa: BLE001
                item.response_raw = str(exc)
                item.status_code = 0
                item.response_size = 0
                item.duration_ms = int((perf_counter() - started) * 1000)
                item.error = str(exc)
                flash(f"Repeater #{item.id} error: {exc}", "error")
            db.commit()
            return redirect(url_for("index", project_id=item.project_id, tab="repeater"))

    @flask_app.post("/repeater/<int:item_id>/clone")
    def clone_repeater(item_id: int):
        with SessionLocal() as db:
            item = db.get(RepeaterRequest, item_id)
            if item is None:
                flash("Repeater record not found.", "error")
                return _back()
            clone = RepeaterRequest(
                project_id=item.project_id,
                source_exchange_id=item.source_exchange_id,
                name=f"{item.name or 'Repeater'} copy",
                method=item.method,
                url=item.url,
                request_raw=item.request_raw,
                response_raw=item.response_raw,
                status_code=item.status_code,
                response_size=item.response_size,
                duration_ms=item.duration_ms,
                error=item.error,
            )
            db.add(clone)
            db.commit()
            flash(f"Cloned repeater #{item.id} into #{clone.id}.", "success")
            return redirect(url_for("index", project_id=item.project_id, tab="repeater"))

    @flask_app.post("/repeater/<int:item_id>/delete")
    def delete_repeater(item_id: int):
        with SessionLocal() as db:
            item = db.get(RepeaterRequest, item_id)
            if item is None:
                flash("Repeater record not found.", "error")
                return _back()
            project_id = item.project_id
            db.delete(item)
            db.commit()
            flash(f"Deleted repeater #{item_id}.", "success")
            return redirect(url_for("index", project_id=project_id, tab="repeater"))

    @flask_app.post("/repeater/<int:item_id>/to-fuzzer")
    def repeater_to_fuzzer(item_id: int):
        with SessionLocal() as db:
            item = db.get(RepeaterRequest, item_id)
            if item is None:
                flash("Repeater record not found.", "error")
                return _back()
            try:
                _update_repeater_from_form(item)
            except ValueError as exc:
                flash(str(exc), "error")
                return _back()
            db.commit()
            session["fuzzer_prefill"] = {
                "range": "1-500",
                "max_thread": 1,
                "delay": 0,
                "request_raw": item.request_raw,
                "show_response": False,
            }
            flash(f"Repeater #{item.id} sent to the fuzzer.", "success")
            return redirect(url_for("index", project_id=item.project_id, tab="fuzzer"))

    @flask_app.post("/authorize/clear")
    def clear_authorize():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        with SessionLocal() as db:
            deleted = clear_authorize_history(db, project_id)
            db.commit()
        flash(f"Cleared {deleted} authorize history records.", "success")
        return redirect(url_for("index", project_id=project_id, tab="authorize"))

    @flask_app.post("/show-response/<source_type>/<int:source_id>")
    def create_show_response(source_type: str, source_id: int):
        with SessionLocal() as db:
            source = _show_response_source(db, source_type, source_id)
            if source is None:
                flash("Response source not found.", "error")
                return _back()
            token = _new_show_response_token(db)
            link = ShowResponseLink(
                token=token,
                project_id=source.project_id,
                source_type=source_type,
                source_id=source.id,
                status_code=getattr(source, "status_code", 200) or 200,
                response_raw=source.response_raw or "",
            )
            db.add(link)
            db.commit()
            return redirect(url_for("show_response", token=token), code=303)

    @flask_app.get("/curl/<source_type>/<int:source_id>")
    def copy_as_curl(source_type: str, source_id: int):
        with SessionLocal() as db:
            source = _show_response_source(db, source_type, source_id)
            if source is None:
                return jsonify({"error": "Request source not found."}), 404
            return jsonify({"curl": build_curl(source)})

    @flask_app.get("/show-response/<token>")
    def show_response(token: str):
        with SessionLocal() as db:
            link = db.query(ShowResponseLink).filter(ShowResponseLink.token == token).one_or_none()
            if link is None:
                abort(404)
            status_code, headers, body = parse_raw_response(link.response_raw, link.status_code)
        response = flask_app.response_class(body, status=status_code)
        for key, value in headers:
            if key.lower() not in HOP_BY_HOP_HEADERS:
                response.headers.add(key, value)
        response.headers["Content-Length"] = str(len(body))
        response.headers["X-ArkaDroid-Show-Response"] = token
        return response

    @flask_app.post("/authorize/toggle")
    def toggle_authorize():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        enabled = request.form.get("enabled") == "on"
        with SessionLocal() as db:
            project = db.get(Project, project_id)
            if project is None:
                flash("Project not found.", "error")
                return _back()
            set_authorize_enabled(db, project, enabled)
            db.commit()
        flash(f"Authorize {'enabled' if enabled else 'disabled'}.", "success")
        return _back()

    @flask_app.post("/reflector/toggle")
    def toggle_reflector():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        enabled = request.form.get("enabled") == "on"
        unique_request = request.form.get("unique_request") == "on"
        with SessionLocal() as db:
            project = db.get(Project, project_id)
            if project is None:
                flash("Project not found.", "error")
                return _back()
            set_reflector_enabled(db, project, enabled, unique_request if enabled else False)
            db.commit()
        flash(f"Reflector {'enabled' if enabled else 'disabled'}.", "success")
        return _back()

    @flask_app.post("/fuzzer/start")
    def start_fuzzer():
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        try:
            config = _fuzzer_config_from_form(project_id)
            job = _create_fuzzer_job(config)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index", project_id=project_id, tab="fuzzer"))
        flash(f"Started fuzzer job #{job['id']}.", "success")
        return redirect(url_for("index", project_id=project_id, tab="fuzzer"))

    @flask_app.post("/fuzzer/<int:job_id>/stop")
    def stop_fuzzer(job_id: int):
        project_id = _selected_project_id()
        job = _fuzzer_job(job_id)
        if job is None:
            flash("Fuzzer job not found.", "error")
        else:
            job["stop_event"].set()
            if job["status"] == "running":
                job["status"] = "stopping"
            flash(f"Stopping fuzzer job #{job_id}.", "success")
        return redirect(url_for("index", project_id=project_id, tab="fuzzer"))

    @flask_app.post("/fuzzer/<int:job_id>/restart")
    def restart_fuzzer(job_id: int):
        project_id = _selected_project_id()
        job = _fuzzer_job(job_id)
        if job is None:
            flash("Fuzzer job not found.", "error")
            return redirect(url_for("index", project_id=project_id, tab="fuzzer"))
        try:
            new_job = _create_fuzzer_job(dict(job["config"]))
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index", project_id=project_id, tab="fuzzer"))
        flash(f"Restarted fuzzer job #{job_id} as #{new_job['id']}.", "success")
        return redirect(url_for("index", project_id=project_id, tab="fuzzer"))

    @flask_app.post("/fuzzer/<int:job_id>/delete")
    def delete_fuzzer(job_id: int):
        project_id = _selected_project_id()
        with FUZZ_LOCK:
            job = FUZZ_JOBS.pop(job_id, None)
        if job is None:
            flash("Fuzzer job not found.", "error")
        else:
            job["stop_event"].set()
            flash(f"Deleted fuzzer job #{job_id}.", "success")
        return redirect(url_for("index", project_id=project_id, tab="fuzzer"))

    @flask_app.post("/authorize/users/save")
    def save_authorize_user():
        project_id = _selected_project_id()
        name = request.form.get("name", "").strip()
        headers_text = request.form.get("headers", "")
        if project_id is None or not name:
            flash("Project and user name are required.", "error")
            return _back()
        try:
            headers = _parse_authorize_headers(headers_text)
        except ValueError as exc:
            flash(str(exc), "error")
            return _back()
        with SessionLocal() as db:
            user = (
                db.query(AuthorizeUser)
                .filter(AuthorizeUser.project_id == project_id, AuthorizeUser.name == name)
                .one_or_none()
            )
            if user is None:
                user = AuthorizeUser(project_id=project_id, name=name)
                db.add(user)
            user.headers = headers
            user.source_file = "droidboard"
            db.commit()
        flash(f"Authorize user {name} saved.", "success")
        return redirect(url_for("index", project_id=project_id, tab="authorize"))

    @flask_app.post("/authorize/users/<name>/delete")
    def delete_authorize_user(name: str):
        project_id = _selected_project_id()
        if project_id is None:
            flash("Select a project.", "error")
            return _back()
        with SessionLocal() as db:
            try:
                remove_authorize_user(db, project_id, name)
                db.commit()
                flash(f"Authorize user {name} removed.", "success")
            except ValueError as exc:
                db.rollback()
                flash(str(exc), "error")
        return redirect(url_for("index", project_id=project_id, tab="authorize"))

    return flask_app


def _base_context(db, project_id: int | None, tab: str) -> dict:
    projects = db.query(Project).order_by(desc(Project.updated_at)).all()
    selected_project = db.get(Project, project_id) if project_id is not None else None
    if selected_project is None and projects:
        selected_project = projects[0]
        project_id = selected_project.id
    if selected_project is not None:
        config = selected_project.proxy_config or {}
        port = int(config.get("port", 8080))
        if proxy_controller.state.active_project_id is None:
            proxy_controller.open_project(
                db,
                selected_project.id,
                port,
                listen_host=_proxy_listen_host(config),
                invisible_proxy=bool(config.get("invisible_proxy")),
            )
    return {
        "projects": projects,
        "project": selected_project,
        "project_id": project_id,
        "tab": tab,
        "methods": METHODS,
        "proxy_state": proxy_controller.state,
        "intercept_enabled": proxy_controller.intercept_enabled,
        "authorize_enabled": bool(selected_project and (selected_project.proxy_config or {}).get("authorize_enabled")),
        "reflect_enabled": bool(selected_project and (selected_project.proxy_config or {}).get("reflect_enabled")),
        "reflect_unique_request": bool(selected_project and (selected_project.proxy_config or {}).get("reflect_unique_request")),
        "invisible_proxy_enabled": bool(selected_project and (selected_project.proxy_config or {}).get("invisible_proxy")),
        "listen_all_interfaces_enabled": bool(
            selected_project and _proxy_listen_host(selected_project.proxy_config or {}) == "0.0.0.0"
        ),
        "filters": request.args,
        "url_args": _url_args,
    }


def _proxy_listen_host(config: dict) -> str:
    """Return an explicit environment override or the project's saved bind mode."""
    configured_host = getattr(get_settings(), "proxy_host", "127.0.0.1")
    if configured_host != "127.0.0.1":
        return configured_host
    return "0.0.0.0" if config.get("listen_all_interfaces") else "127.0.0.1"


def _exchanges_context(db, project_id: int) -> dict:
    filters = {
        "id": request.args.get("id", "").strip(),
        "method": request.args.get("method", "").strip(),
        "host": request.args.get("host", "").strip(),
        "path": request.args.get("path", "").strip(),
        "status": request.args.get("status", "").strip(),
        "body": request.args.get("body", "").strip(),
        "reflected": request.args.get("reflected", "").strip(),
    }
    query = db.query(HttpExchange)
    if not filters["body"]:
        query = query.options(defer(HttpExchange.request_raw), defer(HttpExchange.response_raw))
    query = query.filter(HttpExchange.project_id == project_id)
    if filters["id"].isdigit():
        query = query.filter(HttpExchange.id == int(filters["id"]))
    if filters["method"]:
        query = query.filter(HttpExchange.method.ilike(f"%{filters['method']}%"))
    if filters["host"]:
        query = query.filter(HttpExchange.host.ilike(f"%{filters['host']}%"))
    if filters["path"]:
        query = query.filter(or_(HttpExchange.path.ilike(f"%{filters['path']}%"), HttpExchange.query.ilike(f"%{filters['path']}%")))
    if filters["status"].isdigit():
        query = query.filter(HttpExchange.status_code == int(filters["status"]))
    if filters["reflected"]:
        query = query.filter(HttpExchange.reflecte_params.ilike(f"%{filters['reflected']}%"))
    if filters["body"]:
        body_needle = filters["body"].casefold()
        query = [
            row
            for row in query.order_by(desc(HttpExchange.timestamp), desc(HttpExchange.id)).all()
            if body_needle in _raw_body(row.request_raw or "").casefold()
            or body_needle in _raw_body(row.response_raw or "").casefold()
        ]
    sort = request.args.get("sort", "timestamp")
    if sort not in EXCHANGE_SORT_COLUMNS:
        sort = "timestamp"
    order = "asc" if request.args.get("order") == "asc" else "desc"
    page_size = max(1, get_settings().droidboard_page_size)
    page = max(1, _int_arg("page", 1))
    total = len(query) if isinstance(query, list) else query.count()
    page_count = max(1, (total + page_size - 1) // page_size)
    page = min(page, page_count)

    if isinstance(query, list):
        exchanges = _sort_exchange_rows(query, sort, order)
        exchanges = exchanges[(page - 1) * page_size : page * page_size]
    else:
        sort_column = EXCHANGE_SORT_COLUMNS[sort]
        order_by = asc(sort_column) if order == "asc" else desc(sort_column)
        if sort == "id":
            query = query.order_by(order_by)
        else:
            query = query.order_by(order_by, desc(HttpExchange.id))
        exchanges = query.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "exchanges": exchanges,
        "exchange_live_version": _exchange_live_version(exchanges, total),
        "exchange_sort": sort,
        "exchange_order": order,
        "exchange_page": page,
        "exchange_page_size": page_size,
        "exchange_page_count": page_count,
        "exchange_total": total,
    }


def _sort_exchange_rows(rows: list[HttpExchange], sort: str, order: str) -> list[HttpExchange]:
    reverse = order != "asc"
    key_by_sort = {
        "id": lambda row: row.id,
        "timestamp": lambda row: row.timestamp,
        "method": lambda row: row.method or "",
        "host": lambda row: row.host or "",
        "path": lambda row: row.path or "",
        "status": lambda row: row.status_code or 0,
        "reflected": lambda row: row.reflecte_params or "",
    }
    return sorted(rows, key=key_by_sort.get(sort, key_by_sort["timestamp"]), reverse=reverse)


def _exchange_live_version(rows: list[HttpExchange], total: int) -> str:
    ids = ",".join(str(row.id) for row in rows)
    statuses = ",".join(str(row.status_code) for row in rows)
    return f"{total}:{ids}:{statuses}"


def _dashboard_exchange_url(row: HttpExchange) -> str:
    scheme = "https" if row.port == 443 else "http"
    port = "" if row.port in {80, 443} else f":{row.port}"
    path = row.path or "/"
    query = f"?{row.query}" if row.query else ""
    return f"{scheme}://{row.host}{port}{path}{query}"


def _dashboard_context(db, project_id: int) -> dict:
    section = request.args.get("dashboard_section", "").strip()
    if section not in {key for key, _label in DASHBOARD_SECTIONS}:
        section = ""
    selected_status = request.args.get("dashboard_status", "").strip()
    selected_secret = request.args.get("dashboard_secret", "").strip()
    context = {
        "dashboard_sections": DASHBOARD_SECTIONS,
        "dashboard_section": section,
        "dashboard_status_groups": [],
        "dashboard_selected_status": selected_status,
        "dashboard_selected_group": None,
        "dashboard_secret_groups": [],
        "dashboard_secret_count": 0,
        "dashboard_selected_secret": selected_secret,
        "dashboard_selected_secret_group": None,
        "dashboard_api_rows": [],
        "dashboard_api_count": 0,
        "dashboard_hidden_rows": [],
        "dashboard_hidden_count": 0,
        "dashboard_hidden_page": 1,
        "dashboard_hidden_page_count": 1,
        "dashboard_authorize_groups": [],
        "dashboard_authorize_categories": [],
        "dashboard_selected_authorize": request.args.get("dashboard_authorize", "").strip(),
        "dashboard_selected_authorize_category": None,
        "dashboard_fuzzer_groups": [],
        "dashboard_selected_fuzzer_group": None,
        "dashboard_selected_fuzzer": request.args.get("dashboard_fuzzer", "").strip(),
        "dashboard_reflector_groups": [],
        "dashboard_reflector_count": 0,
        "dashboard_selected_reflector": request.args.get("dashboard_reflector", "").strip(),
        "dashboard_selected_reflector_group": None,
        "dashboard_error_groups": [],
        "dashboard_error_count": 0,
        "dashboard_selected_error": request.args.get("dashboard_error", "").strip(),
        "dashboard_selected_error_group": None,
    }

    base_query = db.query(HttpExchange).filter(HttpExchange.project_id == project_id)
    if section == "authorize":
        rows = (
            db.query(AuthorizeExchange)
            .filter(AuthorizeExchange.project_id == project_id)
            .options(defer(AuthorizeExchange.request_raw))
            .order_by(desc(AuthorizeExchange.id))
            .all()
        )
        categories = [
            {"key": "same", "label": "Same Response", "groups": _dashboard_authorize_groups(rows)},
            {"key": "different", "label": "Different Response", "groups": _dashboard_authorize_groups(rows, different=True)},
        ]
        context["dashboard_authorize_categories"] = categories
        selected = next((category for category in categories
                         if category["key"] == context["dashboard_selected_authorize"]), None)
        context["dashboard_selected_authorize_category"] = selected
        context["dashboard_authorize_groups"] = selected["groups"] if selected else []
    elif section == "status":
        counts = (
            db.query(HttpExchange.status_code, func.count(HttpExchange.id))
            .filter(HttpExchange.project_id == project_id)
            .group_by(HttpExchange.status_code)
            .all()
        )
        groups = [
            {"status": str(status) if status is not None else "-", "count": count, "rows": []}
            for status, count in counts
        ]

        def sort_key(item: dict) -> tuple[int, int | str]:
            status = item["status"]
            return (0, int(status)) if status.isdigit() else (1, status)

        groups.sort(key=sort_key)
        selected_group = next((group for group in groups if group["status"] == selected_status), None)
        if selected_group is not None:
            status_value = int(selected_status) if selected_status.isdigit() else None
            status_filter = HttpExchange.status_code == status_value if selected_status != "-" else HttpExchange.status_code.is_(None)
            selected_group["rows"] = (
                base_query.options(defer(HttpExchange.request_raw), defer(HttpExchange.response_raw))
                .filter(status_filter)
                .order_by(desc(HttpExchange.timestamp), desc(HttpExchange.id))
                .all()
            )
        context.update(dashboard_status_groups=groups, dashboard_selected_group=selected_group)
    elif section == "secrets":
        all_rows = base_query.order_by(desc(HttpExchange.id)).all()
        rows = _dashboard_unique_response_rows(all_rows)
        groups = _dashboard_secret_groups(rows, include_findings_for=selected_secret)
        groups.append(_dashboard_auth_endpoints(all_rows, include_findings=selected_secret == "auth_endpoints"))
        context.update(
            dashboard_secret_groups=groups,
            dashboard_secret_count=sum(group["count"] for group in groups),
            dashboard_selected_secret_group=next(
                (group for group in groups if group["key"] == selected_secret), None
            ),
        )
    elif section == "api":
        rows = _dashboard_unique_response_rows(base_query.order_by(desc(HttpExchange.id)).all())
        count, api_rows = _dashboard_api_rows(rows)
        context.update(dashboard_api_count=count, dashboard_api_rows=api_rows)
    elif section == "hidden":
        candidates = (
            base_query.filter(
                or_(
                    HttpExchange.path.ilike("%.js"),
                    HttpExchange.path.ilike("%.html"),
                    HttpExchange.response_raw.ilike("%content-type: text/javascript%"),
                    HttpExchange.response_raw.ilike("%content-type: application/javascript%"),
                    HttpExchange.response_raw.ilike("%content-type: text/html%"),
                )
            )
            .order_by(desc(HttpExchange.id))
            .all()
        )
        observed = base_query.with_entities(HttpExchange.host, HttpExchange.path).all()
        hidden_rows = _dashboard_hidden_endpoints(candidates, observed)
        page_count = max(1, (len(hidden_rows) + DASHBOARD_HIDDEN_PAGE_SIZE - 1) // DASHBOARD_HIDDEN_PAGE_SIZE)
        page = min(max(1, _int_arg("dashboard_hidden_page", 1)), page_count)
        start = (page - 1) * DASHBOARD_HIDDEN_PAGE_SIZE
        context.update(
            dashboard_hidden_rows=hidden_rows[start : start + DASHBOARD_HIDDEN_PAGE_SIZE],
            dashboard_hidden_count=len(hidden_rows),
            dashboard_hidden_page=page,
            dashboard_hidden_page_count=page_count,
        )
    elif section == "fuzzer":
        with FUZZ_LOCK:
            jobs = [
                _public_fuzzer_job(job)
                for job in FUZZ_JOBS.values()
                if job["project_id"] == project_id
            ]
        groups = _dashboard_fuzzer_groups(jobs)
        selected_group = next((group for group in groups if group["key"] == context["dashboard_selected_fuzzer"]), None)
        context.update(dashboard_fuzzer_groups=groups, dashboard_selected_fuzzer_group=selected_group)
    elif section == "reflector":
        rows = base_query.order_by(desc(HttpExchange.id)).all()
        groups = _dashboard_reflector_groups(rows)
        selected_group = next((group for group in groups if group["key"] == context["dashboard_selected_reflector"]), None)
        context.update(
            dashboard_reflector_groups=groups,
            dashboard_reflector_count=sum(group["count"] for group in groups),
            dashboard_selected_reflector_group=selected_group,
        )
    elif section == "error":
        rows = base_query.order_by(desc(HttpExchange.id)).all()
        groups = _dashboard_error_groups(rows)
        selected_group = next((group for group in groups if group["key"] == context["dashboard_selected_error"]), None)
        context.update(
            dashboard_error_groups=groups,
            dashboard_error_count=sum(group["count"] for group in groups),
            dashboard_selected_error_group=selected_group,
        )
    return context


def _dashboard_unique_response_rows(rows: list[HttpExchange]) -> list[HttpExchange]:
    unique_rows: list[HttpExchange] = []
    seen_responses: set[tuple[str, int, str, str, str]] = set()
    for row in rows:
        response = row.response_raw or ""
        if response:
            marker = (row.host or "", row.port, row.path or "", row.query or "", response)
            if marker in seen_responses:
                continue
            seen_responses.add(marker)
        unique_rows.append(row)
    return unique_rows


def _dashboard_auth_endpoints(rows: list[HttpExchange], include_findings: bool = False) -> dict:
    group = {"key": "auth_endpoints", "label": "Auth Endpoints", "count": 0, "findings": []}
    for row in rows:
        names = []
        for name in _raw_headers(row.response_raw or ""):
            normalized = name.casefold().replace("_", "-")
            if normalized.startswith("access-control-"):
                continue
            parts = set(normalized.split("-"))
            if (
                normalized in {"set-cookie", "set-cookie2", "cookie", "cookie2", "remote-user", "x-remote-user"}
                or parts.intersection({
                    "auth", "authenticate", "authentication", "authorization",
                    "token", "tokens", "jwt", "bearer", "oauth", "oauth2",
                    "session", "sessionid", "csrf", "xsrf", "csrftoken", "xsrftoken", "apikey",
                    "oidc", "saml", "credential", "credentials",
                })
                or "api-key" in normalized
            ):
                names.append(name)
        if not names:
            continue
        group["count"] += 1
        if include_findings:
            group["findings"].append({
                "row": row,
                "location": "Response",
                "label": "Authentication headers",
                "value": ", ".join(names),
                "match": names[0] + ":",
            })
    return group


def _dashboard_secret_groups(rows: list[HttpExchange], include_findings_for: str = "") -> list[dict]:
    groups = {
        key: {"key": key, "label": label, "count": 0, "findings": []}
        for key, label in DASHBOARD_SECRET_CATEGORY_LABELS.items()
    }
    seen: set[tuple[int, str, str, str]] = set()
    for row in rows:
        for location, raw in (("Request", row.request_raw or ""), ("Response", row.response_raw or "")):
            for category, label, pattern, value_group in DASHBOARD_SECRET_RULES:
                for match in pattern.finditer(raw):
                    value = match.group(value_group).strip().rstrip(".,;:")
                    if category == "base64" and value.isalpha() and (value.islower() or value.isupper()):
                        continue
                    marker = (row.id, location, category, value.casefold())
                    if not value or marker in seen:
                        continue
                    seen.add(marker)
                    groups[category]["count"] += 1
                    if category == include_findings_for:
                        groups[category]["findings"].append(
                            {
                                "row": row,
                                "location": location,
                                "label": label,
                                "value": _dashboard_finding_preview(value),
                                "match": value,
                            }
                        )
    return [group for group in groups.values() if group["count"]]


def _dashboard_finding_preview(value: str, limit: int = 100) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else f"{compact[:limit - 1]}…"


def _dashboard_api_rows(rows: list[HttpExchange], include_rows: bool = True) -> tuple[int, list[dict]]:
    api_rows = []
    api_count = 0
    content_type_pattern = re.compile(r"(?im)^content-type\s*:\s*([^;\r\n]+)")
    for row in rows:
        formats: list[str] = []
        locations: list[str] = []
        for location, raw in (("Request", row.request_raw or ""), ("Response", row.response_raw or "")):
            header_block = raw.replace("\r\n", "\n").partition("\n\n")[0]
            for match in content_type_pattern.finditer(header_block):
                content_type = match.group(1).strip().casefold()
                data_format = "JSON" if "json" in content_type else "XML" if "xml" in content_type else None
                if data_format and data_format not in formats:
                    formats.append(data_format)
                if data_format and location not in locations:
                    locations.append(location)
        if formats:
            api_count += 1
            if include_rows:
                api_rows.append({"row": row, "formats": formats, "locations": locations})
    return api_count, api_rows


def _dashboard_hidden_endpoints(rows: list[HttpExchange], observed_rows) -> list[dict]:
    observed = {(host.casefold(), path) for host, path in observed_rows if host and path}
    findings: dict[tuple[str, str], dict] = {}
    for row in rows:
        _headers, _separator, body = (row.response_raw or "").replace("\r\n", "\n").partition("\n\n")
        if not body:
            continue
        source_url = f"{'https' if row.port == 443 else 'http'}://{row.host}{row.path or '/'}"
        candidates = list(DASHBOARD_ABSOLUTE_ENDPOINT_PATTERN.findall(body))
        candidates.extend(match.group(1) for match in DASHBOARD_RELATIVE_ENDPOINT_PATTERN.finditer(body))
        for candidate in candidates:
            candidate = candidate.rstrip(".,;:)")
            try:
                absolute = urljoin(source_url, candidate)
                parsed = urlsplit(absolute)
            except ValueError:
                # Extracted JavaScript/HTML strings may not be valid URLs.
                continue
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.path:
                continue
            # Static assets are useful only when their path itself looks like an API or endpoint.
            if re.search(r"\.(?:css|js|map|png|jpe?g|gif|svg|webp|woff2?|ttf|ico)(?:$|[?#])", parsed.path, re.I):
                if not DASHBOARD_ENDPOINT_HINT_PATTERN.search(candidate):
                    continue
            marker = (parsed.hostname.casefold(), parsed.path)
            if marker in observed or marker in findings:
                continue
            display_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                display_url += f"?{parsed.query}"
            findings[marker] = {
                "url": display_url,
                "host": parsed.netloc,
                "path": parsed.path,
                "source": row,
                "source_kind": "JavaScript" if row.path.lower().endswith(".js") else "HTML/page",
            }
    return sorted(findings.values(), key=lambda item: (item["host"].casefold(), item["path"]))


def _dashboard_fuzzer_groups(jobs: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, int], dict] = {}
    for job in jobs:
        for index, result in enumerate(job["results"], start=1):
            status = str(result.get("status_code") or "-")
            size = int(result.get("size") or 0)
            key = (status, size)
            group = grouped.setdefault(
                key,
                {
                    "key": f"{status}:{size}",
                    "status": status,
                    "size": size,
                    "count": 0,
                    "rows": [],
                },
            )
            group["count"] += 1
            group["rows"].append({"job": job, "index": index, **result})

    def sort_key(group: dict) -> tuple[int, int | str, int]:
        status = group["status"]
        return (0, int(status), group["size"]) if status.isdigit() else (1, status, group["size"])

    return sorted(grouped.values(), key=sort_key)


def _dashboard_reflector_groups(rows: list[HttpExchange]) -> list[dict]:
    groups = {
        "query": {"key": "query", "label": "Query string", "count": 0, "findings": []},
        "post": {"key": "post", "label": "POST body", "count": 0, "findings": []},
        "json": {"key": "json", "label": "JSON body", "count": 0, "findings": []},
    }
    seen: set[tuple[int, str, str, str]] = set()
    for row in rows:
        response_body = _raw_body(row.response_raw or "")
        response_text = response_body.casefold()
        if not response_text:
            continue
        for source, name, value in _dashboard_request_values(row):
            value_text = str(value)
            if not value_text or value_text.casefold() not in response_text:
                continue
            marker = (row.id, source, name, value_text.casefold())
            if marker in seen:
                continue
            seen.add(marker)
            groups[source]["count"] += 1
            groups[source]["findings"].append(
                {
                    "row": row,
                    "source": source,
                    "name": name,
                    "value": _dashboard_finding_preview(value_text),
                    "match": value_text,
                }
            )
    return [group for group in groups.values() if group["count"]]


def _dashboard_error_groups(rows: list[HttpExchange]) -> list[dict]:
    groups: dict[str, dict] = {}
    error_signatures = _dashboard_error_signatures()
    seen: set[tuple[int, str]] = set()
    for row in rows:
        response_body = _raw_body(row.response_raw or "")
        response_text = response_body.casefold()
        if int(row.status_code or 0) >= 500:
            group = groups.setdefault("status-500", {"key": "status-500", "label": "HTTP 500", "count": 0, "findings": []})
            group["count"] += 1
            group["findings"].append({"row": row, "label": "HTTP 500", "match": str(row.status_code or 0), "value": str(row.status_code or 0)})
        for signature in error_signatures:
            if signature.casefold() not in response_text:
                continue
            key = f"signature:{hashlib.sha1(signature.casefold().encode()).hexdigest()[:12]}"
            marker = (row.id, key)
            if marker in seen:
                continue
            seen.add(marker)
            group = groups.setdefault(
                key,
                {"key": key, "label": signature, "count": 0, "findings": []},
            )
            group["count"] += 1
            group["findings"].append(
                {
                    "row": row,
                    "label": signature,
                    "match": signature,
                    "value": _dashboard_finding_preview(signature),
                }
            )
    return sorted(groups.values(), key=lambda group: (0 if group["key"] == "status-500" else 1, group["label"].casefold()))


def _dashboard_error_signatures() -> list[str]:
    try:
        content = ERROR_SIGNATURES_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    signatures = []
    seen = set()
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.casefold()
        if lowered in seen:
            continue
        seen.add(lowered)
        signatures.append(line)
    return signatures


def _dashboard_request_values(row: HttpExchange) -> list[tuple[str, str, str]]:
    values: list[tuple[str, str, str]] = []
    url = _dashboard_exchange_url(row)
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        values.append(("query", name, value))

    headers = _raw_headers(row.request_raw or "")
    body = _raw_body(row.request_raw or "")
    if not body:
        return values

    content_type = _header_value(headers, "Content-Type").casefold()
    if "json" in content_type:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return values
        values.extend(("json", name, value) for name, value in _json_scalar_values(payload))
        return values

    if "application/x-www-form-urlencoded" in content_type or "=" in body:
        values.extend(("post", name, value) for name, value in parse_qsl(body, keep_blank_values=True))
    return values


def _json_scalar_values(payload: object, prefix: str = "") -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            values.extend(_json_scalar_values(value, name))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            name = f"{prefix}[{index}]" if prefix else str(index)
            values.extend(_json_scalar_values(value, name))
    elif payload is not None:
        values.append((prefix, str(payload)))
    return values


def _raw_headers(raw_message: str) -> dict[str, str]:
    head = raw_message.replace("\r\n", "\n").partition("\n\n")[0]
    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip()] = value.strip()
    return headers


def _header_value(headers: dict[str, str], name: str) -> str:
    expected = name.casefold()
    for key, value in headers.items():
        if key.casefold() == expected:
            return value
    return ""


def _repeater_context(db, project_id: int) -> dict:
    query = db.query(RepeaterRequest).filter(RepeaterRequest.project_id == project_id)
    q = request.args.get("repeater_q", "").strip()
    method = request.args.get("repeater_method", "").strip()
    status = request.args.get("repeater_status", "").strip()
    if q:
        like = f"%{q}%"
        clauses = [RepeaterRequest.name.ilike(like), RepeaterRequest.url.ilike(like)]
        if q.isdigit():
            clauses.append(RepeaterRequest.id == int(q))
            clauses.append(RepeaterRequest.source_exchange_id == int(q))
        query = query.filter(or_(*clauses))
    if method:
        query = query.filter(RepeaterRequest.method.ilike(f"%{method}%"))
    if status.isdigit():
        query = query.filter(RepeaterRequest.status_code == int(status))
    return {"repeater_items": query.order_by(desc(RepeaterRequest.updated_at), desc(RepeaterRequest.id)).limit(100).all()}


def _intercept_context(project_id: int) -> dict:
    rows = sorted(proxy_controller.intercept_snapshot(project_id), key=lambda item: (item.resolved, -item.id))
    return {
        "intercept_rows": rows,
        "intercept_now": time.time(),
        "intercept_pending": sum(1 for row in rows if not row.resolved),
        "intercept_live_version": _intercept_live_version(rows),
    }


def _intercept_live_version(rows: list) -> str:
    return "|".join(
        f"{row.id}:{int(row.resolved)}:{row.action or ''}:{row.status_code or ''}"
        for row in rows
    )


def _authorize_context(db, project_id: int) -> dict:
    users = db.query(AuthorizeUser).filter(AuthorizeUser.project_id == project_id).order_by(AuthorizeUser.name).all()
    query = db.query(AuthorizeExchange).filter(AuthorizeExchange.project_id == project_id)
    q = request.args.get("auth_q", "").strip()
    user = request.args.get("auth_user", "").strip()
    status = request.args.get("auth_status", "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(or_(AuthorizeExchange.url.ilike(like), AuthorizeExchange.method.ilike(like)))
    if user:
        query = query.filter(AuthorizeExchange.user_name.ilike(f"%{user}%"))
    if status.isdigit():
        query = query.filter(AuthorizeExchange.status_code == int(status))
    page_size = max(1, get_settings().droidboard_page_size)
    page = max(1, _int_arg("auth_page", 1))
    total = query.count()
    page_count = max(1, (total + page_size - 1) // page_size)
    page = min(page, page_count)
    all_rows = query.order_by(desc(AuthorizeExchange.timestamp), desc(AuthorizeExchange.id)).all()
    rows = (
        query.options(defer(AuthorizeExchange.request_raw), defer(AuthorizeExchange.response_raw))
        .order_by(desc(AuthorizeExchange.timestamp), desc(AuthorizeExchange.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    groups = _authorize_groups(all_rows)
    return {
        "authorize_users": users,
        "authorize_rows": rows,
        "authorize_groups": groups,
        "authorize_page": page,
        "authorize_page_size": page_size,
        "authorize_page_count": page_count,
        "authorize_total": total,
    }


def _mobile_context(project_id: int) -> dict:
    default_proxy = f"10.0.2.2:{proxy_controller.state.listen_port or 8080}"
    default_proxy_host, _separator, default_proxy_port = default_proxy.partition(":")
    mobile_os = request.args.get("mobile_os") or session.get("mobile_os") or "android"
    if mobile_os not in {"android", "ios"}:
        mobile_os = "android"
    session["mobile_os"] = mobile_os
    result = session.get("mobile_result")
    if session.get("mobile_result_os") != mobile_os:
        result = None
    session.setdefault("ios_install_owner", secrets.token_urlsafe(24))
    session.setdefault("ios_install_csrf", secrets.token_urlsafe(24))
    android_ca_dir = mobile_service.android_ca_path(project_id)
    android_ca_files = sorted(android_ca_dir.glob("*.0")) if android_ca_dir.exists() else []
    return {
        "mobile_result": result,
        "mobile_os": mobile_os,
        "ios_install_csrf": session["ios_install_csrf"],
        "ios_install_job": session.get("ios_install_job", ""),
        "mobile_default_avd": mobile_service.DEFAULT_AVD,
        "mobile_default_emulator_command": mobile_service.DEFAULT_EMULATOR_START_COMMAND,
        "mobile_default_proxy": default_proxy,
        "mobile_default_proxy_host": default_proxy_host,
        "mobile_default_proxy_port": default_proxy_port or str(proxy_controller.state.listen_port or 8080),
        "mobile_android_ca_files": android_ca_files,
    }


def _store_mobile_result(result: mobile_service.MobileResult, mobile_os: str) -> None:
    session["mobile_result"] = {
        "ok": result.ok,
        "title": result.title,
        "command": result.command,
        "output": result.output,
        "artifact": result.artifact,
    }
    session["mobile_result_os"] = mobile_os
    session["mobile_os"] = mobile_os


def _static_analysis_context() -> dict:
    token = session.get("static_analysis_result")
    return {"static_analysis_result": STATIC_ANALYSIS_RESULTS.get(token) if token else None}


def _fuzzer_context(db, project_id: int) -> dict:
    page_size = max(1, get_settings().droidboard_page_size)
    with FUZZ_LOCK:
        jobs = [
            _public_fuzzer_job(job)
            for job in FUZZ_JOBS.values()
            if job["project_id"] == project_id
        ]
    live_version = _fuzzer_live_version(jobs)
    jobs = [_prepare_public_fuzzer_job(job, page_size) for job in jobs]
    return {
        "fuzzer_jobs": sorted(jobs, key=lambda item: item["id"], reverse=True),
        "fuzzer_prefill": session.pop("fuzzer_prefill", {}),
        "fuzzer_live_version": live_version,
    }


def _prepare_public_fuzzer_job(job: dict, page_size: int) -> dict:
    sort = request.args.get(f"fuzzer_sort_{job['id']}", "index")
    match_columns = {f"match:{term}" for term in job["config"].get("response_matches", [])}
    if sort not in FUZZER_SORT_COLUMNS | match_columns:
        sort = "index"
    order = "asc" if request.args.get(f"fuzzer_order_{job['id']}") == "asc" else "desc"
    query = request.args.get(f"fuzzer_q_{job['id']}", "").strip()
    indexed_results = [
        {"index": index, **result}
        for index, result in enumerate(job["results"], start=1)
    ]
    if query:
        needle = query.casefold()
        indexed_results = [
            result for result in indexed_results
            if _fuzzer_result_matches(result, needle)
        ]
    total = len(indexed_results)
    page_count = max(1, (total + page_size - 1) // page_size)
    page = min(max(1, _int_arg(f"fuzzer_page_{job['id']}", 1)), page_count)
    results = _sort_fuzzer_results(indexed_results, sort, order)
    start = (page - 1) * page_size
    job.update(
        completed=len(job["results"]),
        results=results[start : start + page_size],
        result_total=total,
        result_page=page,
        result_page_count=page_count,
        result_page_size=page_size,
        result_sort=sort,
        result_order=order,
        result_query=query,
    )
    return job


def _fuzzer_result_matches(result: dict, needle: str) -> bool:
    fields = (
        result.get("index"),
        result.get("source"),
        result.get("name"),
        result.get("value"),
        result.get("status_code"),
        result.get("size"),
        result.get("duration_ms"),
        result.get("url"),
        result.get("error"),
        result.get("request_raw"),
        result.get("response_raw"),
        *result.get("match_counts", {}).values(),
    )
    return any(needle in str(value if value is not None else "").casefold() for value in fields)


def _sort_fuzzer_results(results: list[dict], sort: str, order: str) -> list[dict]:
    reverse = order != "asc"
    if sort.startswith("match:"):
        term = sort.removeprefix("match:")
        return sorted(results, key=lambda row: row.get("match_counts", {}).get(term, 0), reverse=reverse)
    key_by_sort = {
        "index": lambda row: int(row.get("index") or 0),
        "source": lambda row: f"{row.get('source') or ''}:{row.get('name') or ''}",
        "value": lambda row: str(row.get("value") or ""),
        "status": lambda row: int(row.get("status_code") or 0),
        "size": lambda row: int(row.get("size") or 0),
        "duration": lambda row: int(row.get("duration_ms") or 0),
        "url": lambda row: str(row.get("url") or ""),
        "error": lambda row: str(row.get("error") or ""),
    }
    return sorted(results, key=key_by_sort.get(sort, key_by_sort["index"]), reverse=reverse)


def _fuzzer_live_version(jobs: list[dict]) -> str:
    return "|".join(
        f"{job['id']}:{job['status']}:{len(job['results'])}:{job.get('result_total', 0)}:{job['total']}"
        for job in jobs
    )


def _fuzzer_config_from_form(project_id: int) -> dict:
    range_expression = request.form.get("range", "1-500").strip()
    max_thread = max(1, _int_form("max_thread", 1))
    delay_ms = max(0, _int_form("delay", 0))
    show_response = request.form.get("show_response") == "on"
    raw_request = request.form.get("request_raw", "")
    if not raw_request.strip():
        raise ValueError("Raw request is required.")
    if fuzzer.FUZZ_TOKEN not in raw_request:
        raise ValueError("Raw request must contain FUZZ.")
    config = {
        "project_id": project_id,
        "range": range_expression,
        "max_thread": max_thread,
        "delay": delay_ms,
        "show_response": show_response,
        "request_raw": raw_request,
        "response_matches": _fuzzer_match_terms(request.form.get("response_matches", "")),
    }
    wordlist = request.files.get("wordlist")
    if wordlist is not None and wordlist.filename:
        try:
            content = wordlist.read().decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Wordlist must be a UTF-8 text file.") from exc
        values = [line for line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line]
        if not values:
            raise ValueError("Wordlist must contain at least one non-empty line.")
        config["values"] = values
        config["wordlist_name"] = wordlist.filename
    return config


def _fuzzer_match_terms(text: str) -> list[str]:
    terms = {}
    for line in text.splitlines():
        term = line.strip()
        if term:
            terms.setdefault(term.casefold(), term)
    return list(terms.values())


def _fuzzer_match_counts(result: dict, terms: list[str]) -> dict[str, int]:
    response = "" if result.get("error") else str(result.get("response_raw") or "").casefold()
    return {term: response.count(term.casefold()) for term in terms}


def _create_fuzzer_job(config: dict) -> dict:
    global FUZZ_JOB_COUNTER
    attempts = _build_fuzzer_attempts(config)
    if not attempts:
        raise ValueError("No selected parameters found in the URL or body.")
    with FUZZ_LOCK:
        FUZZ_JOB_COUNTER += 1
        job_id = FUZZ_JOB_COUNTER
        job = {
            "id": job_id,
            "project_id": config["project_id"],
            "config": config,
            "status": "running",
            "total": len(attempts),
            "created_at": _now_label(),
            "finished_at": "",
            "results": [],
            "error": "",
            "stop_event": threading.Event(),
            "thread": None,
        }
        FUZZ_JOBS[job_id] = job
    thread = threading.Thread(target=_run_fuzzer_job, args=(job_id, attempts), daemon=True)
    job["thread"] = thread
    thread.start()
    return job


def _build_fuzzer_attempts(config: dict) -> list[fuzzer.FuzzAttempt]:
    values = config["values"] if "values" in config else fuzzer.parse_fuzz_range(str(config["range"]))
    method, url = fuzzer.method_and_url(str(config["request_raw"]))
    source = fuzzer.FuzzSource(label="raw request", method=method, url=url, raw_request=str(config["request_raw"]))
    return fuzzer.build_keyword_attempts(source, values)


def _run_fuzzer_job(job_id: int, attempts: list[fuzzer.FuzzAttempt]) -> None:
    job = _fuzzer_job(job_id)
    if job is None:
        return
    try:
        for result in fuzzer.run_attempts(
            attempts,
            max_workers=int(job["config"]["max_thread"]),
            delay_ms=int(job["config"]["delay"]),
            stop_event=job["stop_event"],
        ):
            result["match_counts"] = _fuzzer_match_counts(result, job["config"].get("response_matches", []))
            with FUZZ_LOCK:
                current = FUZZ_JOBS.get(job_id)
                if current is None:
                    return
                current["results"].append(result)
        with FUZZ_LOCK:
            current = FUZZ_JOBS.get(job_id)
            if current is not None:
                current["status"] = "stopped" if current["stop_event"].is_set() else "done"
                current["finished_at"] = _now_label()
    except Exception as exc:  # noqa: BLE001 - job errors need to be visible in the board.
        with FUZZ_LOCK:
            current = FUZZ_JOBS.get(job_id)
            if current is not None:
                current["status"] = "error"
                current["error"] = str(exc)
                current["finished_at"] = _now_label()


def _fuzzer_job(job_id: int) -> dict | None:
    with FUZZ_LOCK:
        return FUZZ_JOBS.get(job_id)


def _public_fuzzer_job(job: dict) -> dict:
    return {
        "id": job["id"],
        "project_id": job["project_id"],
        "config": job["config"],
        "status": job["status"],
        "total": job["total"],
        "created_at": job["created_at"],
        "finished_at": job["finished_at"],
        "results": list(job["results"]),
        "error": job["error"],
    }


def _now_label() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _run_mobile_action(project_id: int, action: str) -> mobile_service.MobileResult:
    session["mobile_os"] = "android"
    if action == "start":
        return mobile_service.start_emulator(request.form.get("avd", mobile_service.DEFAULT_AVD))
    if action == "start-command":
        return mobile_service.start_emulator_with_command(
            request.form.get("emulator_command", mobile_service.DEFAULT_EMULATOR_START_COMMAND)
        )
    if action == "stop":
        return mobile_service.stop_emulator()
    if action == "proxy":
        return mobile_service.set_http_proxy(request.form.get("proxy_address", ""))
    if action == "unset-proxy":
        return mobile_service.unset_http_proxy()
    if action == "firewall-proxy":
        return mobile_service.enable_iptables_proxy(
            request.form.get("firewall_proxy_host", ""),
            _int_form("firewall_proxy_port", proxy_controller.state.listen_port or 8080),
        )
    if action == "disable-firewall-proxy":
        return mobile_service.disable_iptables_proxy()
    if action == "root":
        return mobile_service.root()
    if action == "remount":
        return mobile_service.remount()
    if action == "reboot":
        return mobile_service.reboot()
    if action == "logcat":
        return mobile_service.logcat(_int_form("lines", 500))
    if action == "install":
        return mobile_service.install_apk(_mobile_apk_path(project_id))
    if action == "uninstall":
        return mobile_service.uninstall_apk(_mobile_apk_path(project_id))
    if action == "get-pkg":
        return mobile_service.get_package_name(_mobile_apk_path(project_id))
    if action == "inspect-manifest":
        return mobile_service.inspect_manifest(_mobile_apk_path(project_id))
    if action == "unpack-apk":
        apk = _mobile_apk_path(project_id)
        return mobile_service.unpack_apk(apk, _mobile_unpack_destination_path(project_id, apk))
    if action == "push":
        destination = request.form.get("destination", "").strip()
        if not destination:
            raise ValueError("Destination is required.")
        return mobile_service.push_file(_mobile_source_path(project_id), destination)
    if action == "pull":
        source = request.form.get("source", "").strip()
        if not source:
            raise ValueError("Source is required.")
        destination = _mobile_destination_path(project_id)
        return mobile_service.pull_file(source, destination)
    if action == "remote-info":
        source = request.form.get("source", "").strip()
        if not source:
            raise ValueError("Remote path is required.")
        return mobile_service.remote_file_info(source)
    if action == "remote-view":
        source = request.form.get("source", "").strip()
        if not source:
            raise ValueError("Remote path is required.")
        return mobile_service.read_remote_file(source)
    if action == "remote-search":
        source = request.form.get("source", "").strip()
        if not source:
            raise ValueError("Remote path is required.")
        return mobile_service.search_remote_file(source, request.form.get("pattern", ""))
    if action == "export-ca":
        return mobile_service.export_android_ca(project_id)
    if action == "upload-ca":
        return mobile_service.upload_android_ca(project_id)
    raise ValueError("Invalid mobile action.")


def _run_mobile_ios_action(project_id: int, action: str) -> mobile_service.MobileResult:
    ipa = _mobile_ipa_path(project_id)
    output_dir = _mobile_ios_output_dir(project_id, ipa)
    if action == "scan":
        return mobile_service.analyze_ipa(ipa, output_dir)
    if action == "extract":
        return mobile_service.extract_ipa(ipa, output_dir)
    if action == "metadata":
        return mobile_service.ipa_metadata(ipa, output_dir)
    if action == "plist":
        return mobile_service.ipa_plist_analysis(ipa, output_dir)
    if action == "provisioning":
        return mobile_service.ipa_provisioning_analysis(ipa, output_dir)
    if action == "inventory":
        return mobile_service.ipa_inventory(ipa, output_dir)
    if action == "strings":
        return mobile_service.ipa_strings_analysis(ipa, output_dir)
    raise ValueError("Invalid iOS action.")


def _mobile_apk_path(project_id: int) -> Path:
    uploaded = request.files.get("apk_file")
    path = _save_mobile_upload(project_id, uploaded)
    if path is None:
        path = _form_path("apk_path")
    if path is None or not path.exists() or not path.is_file():
        raise ValueError("APK file is required.")
    return path


def _mobile_ipa_path(project_id: int) -> Path:
    uploaded = request.files.get("ipa_file")
    path = _save_mobile_upload(project_id, uploaded)
    if path is None:
        path = _form_path("ipa_path")
    if path is None or not path.exists() or not path.is_file():
        raise ValueError("IPA file is required.")
    if path.suffix.lower() != ".ipa":
        raise ValueError("IPA file must have .ipa extension.")
    return path


def _mobile_ios_output_dir(project_id: int, ipa: Path) -> Path:
    destination = request.form.get("ios_output_dir", "").strip()
    if destination:
        path = Path(destination).expanduser()
        if not path.is_absolute():
            path = mobile_service.ios_analysis_dir(project_id) / path
        path.mkdir(parents=True, exist_ok=True)
        return path
    default_name = secure_filename(ipa.stem) or "ipa"
    return mobile_service.ios_analysis_dir(project_id) / default_name


def _mobile_source_path(project_id: int) -> Path:
    uploaded = request.files.get("source_file")
    path = _save_mobile_upload(project_id, uploaded)
    if path is None:
        path = _form_path("source_path")
    if path is None or not path.exists() or not path.is_file():
        raise ValueError("Source file is required.")
    return path


def _mobile_destination_path(project_id: int) -> Path:
    destination = request.form.get("destination", "").strip()
    if destination:
        path = Path(destination).expanduser()
        if not path.is_absolute():
            path = mobile_service.project_upload_dir(project_id) / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    return mobile_service.project_upload_dir(project_id)


def _mobile_unpack_destination_path(project_id: int, apk: Path) -> Path:
    destination = request.form.get("unpack_destination", "").strip()
    if destination:
        path = Path(destination).expanduser()
        if not path.is_absolute():
            path = mobile_service.project_unpack_dir(project_id) / path
        path.mkdir(parents=True, exist_ok=True)
        return path
    return mobile_service.project_unpack_dir(project_id) / apk.stem


def _save_mobile_upload(project_id: int, uploaded) -> Path | None:
    if uploaded is None or not uploaded.filename:
        return None
    filename = secure_filename(uploaded.filename)
    if not filename:
        raise ValueError("Invalid uploaded filename.")
    path = mobile_service.project_upload_dir(project_id) / filename
    uploaded.save(path)
    return path


def _save_static_analysis_upload(project_id: int, uploaded) -> Path:
    filename = secure_filename(uploaded.filename)
    if not filename:
        raise ValueError("Invalid uploaded filename.")
    upload_dir = get_settings().resolved_data_dir / "static-analysis" / str(project_id)
    upload_dir.mkdir(parents=True, exist_ok=True)
    path = upload_dir / filename
    uploaded.save(path)
    return path


def _extract_strings(path: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["strings", str(path)],
        capture_output=True,
        check=False,
        timeout=60,
    )


def _form_path(name: str) -> Path | None:
    value = request.form.get(name, "").strip()
    return Path(value).expanduser() if value else None


def _dashboard_authorize_groups(rows: list[AuthorizeExchange], different: bool = False) -> list[dict]:
    grouped = {}
    for row in rows:
        if row.error or not row.status_code or not row.response_raw:
            continue
        signature = _response_signature(row)
        key = (row.source_exchange_id, "" if different else signature)
        group = grouped.setdefault(key, {
            "source_exchange_id": row.source_exchange_id,
            "method": row.method, "url": row.url,
            "status_code": row.status_code, "users": [], "rows": [], "signatures": set(),
        })
        group["signatures"].add(signature)
        group["rows"].append(row)
        if row.user_name not in group["users"]:
            group["users"].append(row.user_name)
    return [group for group in grouped.values()
            if len(group["users"]) > 1 and (not different or len(group["signatures"]) > 1)]


def _authorize_groups(rows: list[AuthorizeExchange]) -> list[dict]:
    grouped: dict[int, dict] = {}
    for row in rows:
        group = grouped.setdefault(
            row.source_exchange_id,
            {"source_exchange_id": row.source_exchange_id, "method": row.method, "url": row.url, "rows": [], "signatures": {}},
        )
        signature = _response_signature(row)
        group["rows"].append(row)
        group["signatures"].setdefault(signature, []).append(row.user_name)
    summaries = []
    for group in grouped.values():
        same_response_sets = [names for names in group["signatures"].values() if len(names) > 1]
        group["same_response_sets"] = same_response_sets
        group["risk"] = "same-response" if same_response_sets else "distinct"
        summaries.append(group)
    return sorted(summaries, key=lambda item: item["source_exchange_id"], reverse=True)


def _response_signature(row: AuthorizeExchange) -> str:
    body = _raw_body(row.response_raw)
    digest = hashlib.sha256(body.encode(errors="replace")).hexdigest()
    return f"{row.status_code}:{digest}"


def _update_repeater_from_form(item: RepeaterRequest) -> None:
    item.name = request.form.get("name", item.name or "").strip()
    item.request_raw = request.form.get("request_raw", item.request_raw)
    item.method, item.url = method_and_url(item.request_raw)


def _show_response_source(db, source_type: str, source_id: int):
    models = {
        "http-exchange": HttpExchange,
        "repeater": RepeaterRequest,
        "authorize": AuthorizeExchange,
    }
    model = models.get(source_type)
    return db.get(model, source_id) if model is not None else None


def _new_show_response_token(db) -> str:
    while True:
        token = secrets.token_urlsafe(18)
        exists = db.query(ShowResponseLink.id).filter(ShowResponseLink.token == token).first()
        if exists is None:
            return token


def _selected_project_id() -> int | None:
    value = request.args.get("project_id") or request.form.get("project_id") or proxy_controller.state.active_project_id
    try:
        return int(value) if value not in {None, ""} else None
    except (TypeError, ValueError):
        return None


def _normalize_remote_path(path: str) -> str:
    value = (path or "/sdcard").strip()
    if not value.startswith("/"):
        value = f"/{value}"
    normalized = posixpath.normpath(value)
    return "/" if normalized == "." else normalized


def _remote_parent_path(path: str) -> str:
    normalized = _normalize_remote_path(path)
    if normalized == "/":
        return "/"
    parent = posixpath.dirname(normalized.rstrip("/"))
    return parent or "/"


def _remote_entry_path(base_path: str, name: str) -> str:
    if name == "..":
        return _remote_parent_path(base_path)
    return _normalize_remote_path(posixpath.join(_normalize_remote_path(base_path), name))


def _int_form(name: str, default: int | None = None) -> int:
    value = request.form.get(name, "")
    if value == "" and default is not None:
        return default
    return int(value)


def _int_arg(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def _url_args(*pairs, **overrides) -> dict:
    args = request.args.to_dict(flat=True)
    if len(pairs) % 2:
        raise ValueError("url_args positional overrides must be key/value pairs.")
    for index in range(0, len(pairs), 2):
        overrides[pairs[index]] = pairs[index + 1]
    for key, value in overrides.items():
        if value is None:
            args.pop(key, None)
        else:
            args[key] = value
    return args


def _parse_authorize_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for index, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("bearer token"):
            token = line.split(":", 1)[1].strip() if ":" in line else line[len("bearer token") :].strip()
            headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
            continue
        if lowered.startswith("bearer "):
            headers["Authorization"] = line
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"Invalid header line #{index}: {raw_line!r}")
        headers[key.strip()] = value.strip()
    return headers


def _response_status(raw_response: str) -> int:
    first_line = raw_response.splitlines()[0] if raw_response else ""
    for part in first_line.split():
        if part.isdigit():
            return int(part)
    return 0


def _raw_body(raw_message: str) -> str:
    normalized = raw_message.replace("\r\n", "\n")
    return normalized.split("\n\n", 1)[1] if "\n\n" in normalized else ""


def _back():
    return redirect(request.referrer or url_for("index"))


def _wants_json_response() -> bool:
    return request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
