from __future__ import annotations

from copy import copy
import hashlib
import json
import re
import signal
import sys
import time
from typing import Any
from pathlib import Path
from urllib.parse import urlsplit

import click
import yaml
from sqlalchemy.exc import IntegrityError

PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.db.session import SessionLocal, init_db  # noqa: E402
from app.models.authorize import AuthorizeExchange, AuthorizeUser  # noqa: E402
from app.models.call_log import CallLog  # noqa: E402
from app.models.http import HttpExchange  # noqa: E402
from app.models.projects import Project  # noqa: E402
from app.models.repeater import RepeaterRequest  # noqa: E402
from app.models.show_response import ShowResponseLink  # noqa: E402
from app.services.authorize import create_authorize_user, set_authorize_enabled  # noqa: E402
from app.services.ca import ensure_ca  # noqa: E402
from app.services.call_logger import log_call  # noqa: E402
from app.services.proxy import proxy_controller  # noqa: E402
from app.services.reflector import set_reflector_enabled  # noqa: E402
from app.services.repeater import send_repeater_request  # noqa: E402


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """ArkaDroid command line interface."""
    init_db()


def _clone_command(command: click.Command, name: str, *, hidden: bool = False) -> click.Command:
    return click.Command(
        name=name,
        context_settings=command.context_settings,
        callback=command.callback,
        params=[copy(param) for param in command.params],
        help=command.help,
        short_help=command.short_help,
        epilog=command.epilog,
        hidden=hidden,
    )


@cli.group()
def project() -> None:
    """Manage ArkaDroid projects."""


@cli.group()
def proxy() -> None:
    """Run and configure the HTTP proxy."""


@cli.group()
def ca() -> None:
    """Manage project CA certificates."""


@cli.group()
def http() -> None:
    """Inspect saved HTTP exchanges."""


@cli.group()
def audit() -> None:
    """Run security checks against saved or raw requests."""


@project.command("create")
@click.argument("projectname")
def project_create(projectname: str) -> None:
    """Create a project in the ArkaDroid SQLite database."""
    newproject.callback(projectname)


@project.command("list")
def project_list() -> None:
    """List existing ArkaDroid projects."""
    listprojects.callback()


@project.command("delete")
@click.argument("projectname")
def project_delete(projectname: str) -> None:
    """Remove a project and all its saved ArkaDroid data."""
    delproject.callback(projectname)


@cli.command(hidden=True)
@click.argument("projectname")
def newproject(projectname: str) -> None:
    """Create a project in the ArkaDroid SQLite database."""
    with SessionLocal() as db:
        project = Project(name=projectname, proxy_config={"port": 8080})
        db.add(project)
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise click.ClickException(f"Project already exists: {projectname}") from exc
        log_call(db, source="cli", operation=f"newproject {projectname}", project_id=project.id)
        db.commit()
        click.echo(f"Created project #{project.id}: {project.name}")


@cli.command(hidden=True)
def listprojects() -> None:
    """List existing ArkaDroid projects."""
    with SessionLocal() as db:
        projects = db.query(Project).order_by(Project.id.asc()).all()

    if not projects:
        click.echo("No projects found.")
        return

    click.echo("ID\tName\tProxy port")
    for project in projects:
        proxy_port = (project.proxy_config or {}).get("port", "")
        click.echo(f"{project.id}\t{project.name}\t{proxy_port}")


@cli.command(hidden=True)
@click.argument("projectname")
def delproject(projectname: str) -> None:
    """Remove a project and all its saved ArkaDroid data."""
    with SessionLocal() as db:
        project = _get_project(db, projectname)
        project_id = project.id
        project_id = project.id
        project_id = project.id
        if proxy_controller.state.active_project_id == project_id:
            proxy_controller.stop(db)
            proxy_controller.state.active_project_id = None
        counts = {
            "authorize": db.query(AuthorizeExchange).filter(AuthorizeExchange.project_id == project_id).delete(synchronize_session=False),
            "authorize_users": db.query(AuthorizeUser).filter(AuthorizeUser.project_id == project_id).delete(synchronize_session=False),
            "repeater": db.query(RepeaterRequest).filter(RepeaterRequest.project_id == project_id).delete(synchronize_session=False),
            "show_response": db.query(ShowResponseLink).filter(ShowResponseLink.project_id == project_id).delete(synchronize_session=False),
            "http": db.query(HttpExchange).filter(HttpExchange.project_id == project_id).delete(synchronize_session=False),
            "logs": db.query(CallLog).filter(CallLog.project_id == project_id).delete(synchronize_session=False),
        }
        db.delete(project)
        db.commit()
    click.echo(f"Removed project #{project_id}: {projectname} ({_format_counts(counts)})")


@proxy.command("start")
@click.argument("projectname", required=False)
@click.option("--config", "config_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Load proxy start options from a YAML file.")
@click.option("--port", type=int, help="Proxy listen port. Defaults to 8080.")
@click.option("--iface", help="Proxy listen interface. Defaults to 127.0.0.1.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), help="Append proxy output to this file.")
@click.option("output_format", "--format", type=click.Choice(["text", "json"]), help="Output format. Defaults to text.")
@click.option("--authorize", "authorize_files", multiple=True, type=click.Path(exists=True, dir_okay=False), help="Authorize user header file. May be repeated.")
@click.option("--reflect", is_flag=True, help="Enable active reflected-parameter replay checks.")
@click.option("--unique-request", is_flag=True, help="Probe all reflected parameters in one replay request.")
@click.option("--print-url-only", is_flag=True, help="Print only intercepted request URLs while still saving full exchanges.")
@click.option("--print-header-only", is_flag=True, help="Print intercepted request and response headers without bodies.")
@click.option("--show-id", is_flag=True, help="Show the HTTP exchange id next to each request URL.")
def proxystart(
    projectname: str | None,
    config_file: Path | None,
    port: int | None,
    iface: str | None,
    output: Path | None,
    output_format: str | None,
    authorize_files: tuple[str, ...],
    reflect: bool,
    unique_request: bool,
    print_url_only: bool,
    print_header_only: bool,
    show_id: bool,
) -> None:
    """Start the proxy, print intercepted traffic, and keep running until Ctrl+C."""
    options = _resolve_proxy_start_options(
        config_file=config_file,
        projectname=projectname,
        port=port,
        iface=iface,
        output=output,
        output_format=output_format,
        authorize_files=authorize_files,
        reflect=reflect,
        unique_request=unique_request,
        print_url_only=print_url_only,
        print_header_only=print_header_only,
        show_id=show_id,
    )
    projectname = options["projectname"]
    port = options["port"]
    iface = options["iface"]
    output = options["output"]
    output_format = options["output_format"]
    authorize_files = options["authorize_files"]
    project_autocreate = options["project_autocreate"]
    reflect = options["reflect"]
    unique_request = options["unique_request"]
    print_url_only = options["print_url_only"]
    print_header_only = options["print_header_only"]
    show_id = options["show_id"]

    if print_url_only and print_header_only:
        raise click.ClickException("Use --print-url-only or --print-header-only, not both.")

    with SessionLocal() as db:
        project = _get_or_create_proxy_project(db, projectname, port, project_autocreate)
        project.proxy_config = {**(project.proxy_config or {}), "port": port}
        proxy_controller.open_project(db, project.id, listen_port=port, listen_host=iface)
        if authorize_files:
            _replace_authorize_users(db, project.id, authorize_files)
            set_authorize_enabled(db, project, True)
        set_reflector_enabled(db, project, reflect, unique_request if reflect else False)
        log_call(
            db,
            source="cli",
            operation=f"proxystart {projectname}",
            project_id=project.id,
            payload={
                "port": port,
                "iface": iface,
                "output": str(output) if output else "",
                "format": output_format,
                "project_autocreate": project_autocreate,
                "reflect": reflect,
                "unique_request": unique_request,
                "print_url_only": print_url_only,
                "print_header_only": print_header_only,
                "show_id": show_id,
            },
        )
        db.commit()
        last_http_id = _latest_id(db, HttpExchange, project.id)
        last_authorize_id = _latest_id(db, AuthorizeExchange, project.id)
        project_id = project.id

    output_handle = output.open("a", encoding="utf-8") if output else None
    stopping = False

    def _stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    previous_int = signal.signal(signal.SIGINT, _stop)
    previous_term = signal.signal(signal.SIGTERM, _stop)
    try:
        with SessionLocal() as db:
            state = proxy_controller.start(db)
            db.commit()
        _emit(f"Proxy started for project {projectname!r} on {state.listen_host}:{state.listen_port}", output_handle)
        _emit("Press Ctrl+C to stop.", output_handle)
        while not stopping:
            last_http_id, last_authorize_id = _print_new_activity(
                project_id,
                last_http_id,
                last_authorize_id,
                output_handle,
                output_format,
                print_url_only,
                print_header_only,
                show_id,
            )
            time.sleep(0.25)
    finally:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)
        with SessionLocal() as db:
            proxy_controller.stop(db)
            log_call(db, source="cli", operation="proxystop", project_id=project_id)
            db.commit()
        _print_new_activity(
            project_id,
            last_http_id,
            last_authorize_id,
            output_handle,
            output_format,
            print_url_only,
            print_header_only,
            show_id,
        )
        _emit("Proxy stopped.", output_handle)
        if output_handle is not None:
            output_handle.close()


cli.add_command(proxystart, "proxystart")
proxy.commands["start"] = _clone_command(proxystart, "start")
cli.commands["proxystart"] = _clone_command(proxystart, "proxystart", hidden=True)


@ca.command("export")
@click.argument("projectname")
@click.argument("cert", type=click.Path(dir_okay=False, path_type=Path))
def exportca(projectname: str, cert: Path) -> None:
    """Export the project CA certificate."""
    with SessionLocal() as db:
        project = _get_project(db, projectname)
        cert_bytes = ensure_ca(project.id)
        cert.parent.mkdir(parents=True, exist_ok=True)
        cert.write_bytes(cert_bytes)
        log_call(db, source="cli", operation=f"exportca {projectname}", project_id=project.id, payload={"path": str(cert)})
        db.commit()
    click.echo(f"CA exported to {cert}")


cli.add_command(exportca, "exportca")
ca.commands["export"] = _clone_command(exportca, "export")
cli.commands["exportca"] = _clone_command(exportca, "exportca", hidden=True)


@http.command("repeater")
@click.argument("projectname", required=False)
@click.argument("request_file_arg", required=False, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--file", "request_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Raw HTTP request file.")
@click.option("--id", "exchange_id", type=int, help="Replay one intercepted request by HTTP exchange ID.")
@click.option("--match", "match_pattern", help="Replay intercepted requests with URLs containing this text.")
@click.option("--header", "header_overrides", multiple=True, help="Add or replace a request header. May be repeated.")
@click.option("--body", "body_override", help="Replace the request body before replay.")
@click.option("--replace-in-body", "--replace-body", "body_replacements", multiple=True, help="Case-insensitive OLD:NEW replacement in the request body. May be repeated.")
@click.option("--replace-in-header", "--replace-header", "header_replacements", multiple=True, help="Case-insensitive OLD:NEW replacement in request headers. May be repeated.")
@click.option("--show-request", is_flag=True, help="Print the sent request before the response.")
def repeater(
    projectname: str | None,
    request_file_arg: Path | None,
    request_file: Path | None,
    exchange_id: int | None,
    match_pattern: str | None,
    header_overrides: tuple[str, ...],
    body_override: str | None,
    body_replacements: tuple[str, ...],
    header_replacements: tuple[str, ...],
    show_request: bool,
) -> None:
    """Send a raw HTTP request file through the ArkaDroid repeater."""
    source_count = sum(value is not None for value in (request_file_arg, request_file, exchange_id, match_pattern))
    if source_count != 1:
        raise click.ClickException("Use exactly one of REQUEST_FILE, --file, --id, or --match.")

    header_values = _parse_header_overrides(header_overrides, "header")
    header_replace_values = _parse_replacements(header_replacements, "replace-in-header")
    body_replace_values = _parse_replacements(body_replacements, "replace-in-body")
    sources = _repeater_sources(projectname, request_file_arg, request_file, exchange_id, match_pattern)

    for index, source in enumerate(sources):
        if index:
            click.echo()
        _send_repeater_source(
            source,
            header_values=header_values,
            body_override=body_override,
            body_replacements=body_replace_values,
            header_replacements=header_replace_values,
            show_request=show_request,
        )


def _send_repeater_source(
    source: dict[str, object],
    *,
    header_values: dict[str, str],
    body_override: str | None,
    body_replacements: list[tuple[str, str]],
    header_replacements: list[tuple[str, str]],
    show_request: bool,
) -> None:
    raw_request = _prepare_repeater_request(
        str(source["raw_request"]),
        header_values=header_values,
        body_override=body_override,
        body_replacements=body_replacements,
        header_replacements=header_replacements,
    )
    method = str(source["method"])
    url = str(source["url"])
    started = time.perf_counter()
    error = ""
    status_code = 0
    response_raw = ""
    try:
        response_raw = send_repeater_request(method, url, raw_request)
        status_code = _response_status(response_raw)
    except Exception as exc:  # noqa: BLE001 - network errors are recorded for the operator.
        error = str(exc)
        response_raw = error
    duration_ms = int((time.perf_counter() - started) * 1000)

    with SessionLocal() as db:
        item = RepeaterRequest(
            project_id=int(source["project_id"]),
            source_exchange_id=source["source_exchange_id"],
            name=str(source["name"]),
            method=method,
            url=url,
            request_raw=raw_request,
            response_raw=response_raw,
            status_code=status_code,
            response_size=len(response_raw.encode()),
            duration_ms=duration_ms,
            error=error,
        )
        db.add(item)
        db.flush()
        log_call(
            db,
            source="cli",
            operation=f"repeater {source['label']}",
            project_id=int(source["project_id"]),
            status=str(status_code) if not error else "error",
            message=error,
            payload={"repeater_id": item.id, "method": method, "url": url},
        )
        db.commit()
        item_id = item.id

    click.echo(f"Repeater #{item_id}: {method} {url} status={status_code or 'error'} duration={duration_ms}ms")
    if show_request:
        click.echo("--- Request ---")
        click.echo(raw_request)
        click.echo("--- Response ---")
    click.echo(response_raw)


def _repeater_sources(
    projectname: str | None,
    request_file_arg: Path | None,
    request_file: Path | None,
    exchange_id: int | None,
    match_pattern: str | None,
) -> list[dict[str, object]]:
    file_source = request_file or request_file_arg
    if file_source is not None:
        if projectname is None:
            raise click.ClickException("PROJECTNAME is required with REQUEST_FILE or --file.")
        raw_request = file_source.read_text(encoding="utf-8")
        method, url = _method_and_url(raw_request)
        with SessionLocal() as db:
            project = _get_project(db, projectname)
            project_id = project.id
        return [
            {
                "label": str(file_source),
                "name": file_source.name,
                "method": method,
                "url": url,
                "raw_request": raw_request,
                "project_id": project_id,
                "source_exchange_id": None,
            }
        ]

    with SessionLocal() as db:
        query = db.query(HttpExchange)
        if projectname is not None:
            project = _get_project(db, projectname)
            query = query.filter(HttpExchange.project_id == project.id)
        if exchange_id is not None:
            query = query.filter(HttpExchange.id == exchange_id)
        else:
            needle = (match_pattern or "").casefold()
            query = query.order_by(HttpExchange.id.asc())
            rows = [row for row in query.all() if needle in _exchange_url(row).casefold()]
            if not rows:
                raise click.ClickException("No matching HTTP exchanges found.")
            return [_repeater_source_from_exchange(row) for row in rows]
        rows = query.order_by(HttpExchange.id.asc()).all()

    if not rows:
        raise click.ClickException("No matching HTTP exchanges found.")
    return [_repeater_source_from_exchange(row) for row in rows]


def _repeater_source_from_exchange(row: HttpExchange) -> dict[str, object]:
    return {
        "label": f"exchange #{row.id}",
        "name": f"exchange-{row.id}",
        "method": row.method,
        "url": _exchange_url(row),
        "raw_request": row.request_raw,
        "project_id": row.project_id,
        "source_exchange_id": row.id,
    }


def _prepare_repeater_request(
    raw_request: str,
    *,
    header_values: dict[str, str],
    body_override: str | None,
    body_replacements: list[tuple[str, str]],
    header_replacements: list[tuple[str, str]],
) -> str:
    updated = raw_request
    if header_replacements:
        updated = _replace_in_raw_headers(updated, header_replacements)
    if header_values:
        updated = _override_raw_request_headers(updated, header_values)
    if body_override is not None:
        updated = _replace_raw_body(updated, body_override)
    if body_replacements:
        updated = _replace_in_raw_body(updated, body_replacements)
    return updated


def _parse_replacements(values: tuple[str, ...], option_name: str) -> list[tuple[str, str]]:
    replacements = []
    for value in values:
        old, separator, new = value.partition(":")
        if not separator or not old:
            raise click.ClickException(f"Invalid --{option_name}: {value!r}")
        replacements.append((old, new))
    return replacements


def _replace_in_raw_headers(raw_request: str, replacements: list[tuple[str, str]]) -> str:
    head, separator, body = _split_raw_message(raw_request)
    lines = head.replace("\r\n", "\n").split("\n")
    if len(lines) <= 1:
        return raw_request
    replaced_headers = [_apply_case_insensitive_replacements(line, replacements) for line in lines[1:]]
    rebuilt = "\n".join([lines[0], *replaced_headers])
    return f"{rebuilt}{separator}{body}" if separator else rebuilt


def _replace_raw_body(raw_request: str, body: str) -> str:
    head, separator, _old_body = _split_raw_message(raw_request)
    separator = separator or "\n\n"
    return f"{head}{separator}{body}"


def _replace_in_raw_body(raw_request: str, replacements: list[tuple[str, str]]) -> str:
    head, separator, body = _split_raw_message(raw_request)
    if not separator:
        return raw_request
    return f"{head}{separator}{_apply_case_insensitive_replacements(body, replacements)}"


def _split_raw_message(raw_message: str) -> tuple[str, str, str]:
    head, separator, body = raw_message.partition("\n\n")
    if separator:
        return head, separator, body
    head, separator, body = raw_message.partition("\r\n\r\n")
    return head, separator, body


def _apply_case_insensitive_replacements(value: str, replacements: list[tuple[str, str]]) -> str:
    replacement_by_old = {old.casefold(): new for old, new in replacements}
    pattern = "|".join(re.escape(old) for old, _new in sorted(replacements, key=lambda item: len(item[0]), reverse=True))
    return re.sub(pattern, lambda match: replacement_by_old[match.group(0).casefold()], value, flags=re.IGNORECASE)


cli.add_command(repeater, "repeater")
http.commands["repeater"] = _clone_command(repeater, "repeater")
cli.commands["repeater"] = _clone_command(repeater, "repeater", hidden=True)


@http.command("extract")
@click.argument("projectname")
@click.option("--id", "exchange_id", type=int, help="Extract one intercepted request by exchange ID.")
@click.option("--search", help="Extract requests containing text in the query string or body.")
def extract(projectname: str, exchange_id: int | None, search: str | None) -> None:
    """Extract intercepted proxy requests from a project."""
    if bool(exchange_id) == bool(search):
        raise click.ClickException("Use exactly one of --id or --search.")

    with SessionLocal() as db:
        project = _get_project(db, projectname)

        query = db.query(HttpExchange).filter(HttpExchange.project_id == project.id)
        if exchange_id is not None:
            rows = query.filter(HttpExchange.id == exchange_id).order_by(HttpExchange.id.asc()).all()
        else:
            needle = (search or "").casefold()
            rows = [
                row
                for row in query.order_by(HttpExchange.id.asc()).all()
                if needle in (row.query or "").casefold() or needle in _raw_body(row.request_raw).casefold()
            ]

    if not rows:
        raise click.ClickException("No matching requests found.")

    for index, row in enumerate(rows):
        if index:
            click.echo()
        click.echo(row.request_raw)


cli.add_command(extract, "extract")
http.commands["extract"] = _clone_command(extract, "extract")
cli.commands["extract"] = _clone_command(extract, "extract", hidden=True)


@http.command("search")
@click.argument("projectname")
@click.argument("pattern")
@click.option("--request", "request_only", is_flag=True, help="Search only request-side fields.")
@click.option("--response", "response_only", is_flag=True, help="Search only response-side fields.")
@click.option("--body", "body_only", is_flag=True, help="Search only HTTP message bodies.")
@click.option("--header", "header_only", is_flag=True, help="Search only HTTP message headers.")
@click.option("--code", "status_code", type=int, help="Only include exchanges with this HTTP status code.")
@click.option("--print-url-only", is_flag=True, help="Print only matching exchange URLs.")
def search(
    projectname: str,
    pattern: str,
    request_only: bool,
    response_only: bool,
    body_only: bool,
    header_only: bool,
    status_code: int | None,
    print_url_only: bool,
) -> None:
    """Search saved HTTP exchanges and print matching request/response blocks."""
    if request_only and response_only:
        raise click.ClickException("Use at most one of --request or --response.")

    match_all = pattern == "*"
    needle = pattern.casefold()
    with SessionLocal() as db:
        project = _get_project(db, projectname)
        query = db.query(HttpExchange).filter(HttpExchange.project_id == project.id)
        if status_code is not None:
            query = query.filter(HttpExchange.status_code == status_code)
        rows = [
            row
            for row in query.order_by(HttpExchange.id.asc()).all()
            if match_all
            or _exchange_matches(
                row,
                needle,
                request_only=request_only,
                response_only=response_only,
                body_only=body_only,
                header_only=header_only,
            )
        ]

    if not rows:
        raise click.ClickException("No matching HTTP exchanges found.")

    for index, row in enumerate(rows):
        if index:
            click.echo()
        if print_url_only:
            click.echo(_exchange_url(row))
        else:
            _emit_exchange(row, [], None, "text")


cli.add_command(search, "search")
http.commands["search"] = _clone_command(search, "search")
cli.commands["search"] = _clone_command(search, "search", hidden=True)


@audit.command("check-bac")
@click.argument("projectname")
@click.option("--file", "request_file", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Raw HTTP request file.")
@click.option("--match", "match_pattern", help="Run against saved requests matching this pattern.")
@click.option("--user1-header", multiple=True, help="Header override for user 1. May be repeated.")
@click.option("--user2-header", multiple=True, help="Header override for user 2. May be repeated.")
def check_bac(
    projectname: str,
    request_file: Path | None,
    match_pattern: str | None,
    user1_header: tuple[str, ...],
    user2_header: tuple[str, ...],
) -> None:
    """Replay requests with two user header sets and compare the responses."""
    if bool(request_file) == bool(match_pattern):
        raise click.ClickException("Use exactly one of --file or --match.")

    user1_headers = _parse_header_overrides(user1_header, "user1-header")
    user2_headers = _parse_header_overrides(user2_header, "user2-header")

    with SessionLocal() as db:
        project = _get_project(db, projectname)
        project_id = project.id

    if request_file is not None:
        raw_request = request_file.read_text(encoding="utf-8")
        method, url = _method_and_url(raw_request)
        sources = [("file", method, url, raw_request)]
    else:
        needle = (match_pattern or "").casefold()
        with SessionLocal() as db:
            exchanges = [
                row
                for row in db.query(HttpExchange).filter(HttpExchange.project_id == project_id).order_by(HttpExchange.id.asc()).all()
                if _exchange_matches(row, needle, request_only=True, response_only=False)
            ]
            sources = [(f"exchange #{row.id}", row.method, _exchange_url(row), row.request_raw) for row in exchanges]
        if not sources:
            raise click.ClickException("No matching HTTP exchanges found.")

    for index, (label, method, url, raw_request) in enumerate(sources):
        if index:
            click.echo()
        result = _run_bac_check(label, method, url, raw_request, user1_headers, user2_headers)
        _emit_bac_result(result)


cli.add_command(check_bac, "check-bac")
audit.commands["check-bac"] = _clone_command(check_bac, "check-bac")
cli.commands["check-bac"] = _clone_command(check_bac, "check-bac", hidden=True)


PROXY_START_DEFAULTS = {
    "port": 8080,
    "iface": "127.0.0.1",
    "output": None,
    "output_format": "text",
    "authorize_files": (),
    "project_autocreate": False,
    "reflect": False,
    "unique_request": False,
    "print_url_only": False,
    "print_header_only": False,
    "show_id": False,
}

PROXY_START_CONFIG_KEYS = {
    "project",
    "projectname",
    "port",
    "iface",
    "output",
    "format",
    "output_format",
    "authorize",
    "project_autocreate",
    "reflect",
    "unique_request",
    "print_url_only",
    "print_header_only",
    "show_id",
}


def _resolve_proxy_start_options(
    *,
    config_file: Path | None,
    projectname: str | None,
    port: int | None,
    iface: str | None,
    output: Path | None,
    output_format: str | None,
    authorize_files: tuple[str, ...],
    reflect: bool,
    unique_request: bool,
    print_url_only: bool,
    print_header_only: bool,
    show_id: bool,
) -> dict[str, Any]:
    config = _load_proxy_start_config(config_file) if config_file else {}
    base_dir = config_file.parent if config_file else Path.cwd()

    options: dict[str, Any] = dict(PROXY_START_DEFAULTS)
    options.update(_normalize_proxy_start_config(config, base_dir))

    if projectname is not None:
        options["projectname"] = projectname
    if port is not None:
        options["port"] = port
    if iface is not None:
        options["iface"] = iface
    if output is not None:
        options["output"] = output
    if output_format is not None:
        options["output_format"] = output_format
    if authorize_files:
        options["authorize_files"] = authorize_files
    if reflect:
        options["reflect"] = True
    if unique_request:
        options["unique_request"] = True
    if print_url_only:
        options["print_url_only"] = True
    if print_header_only:
        options["print_header_only"] = True
    if show_id:
        options["show_id"] = True

    if not options.get("projectname"):
        raise click.ClickException("Missing project name. Provide PROJECTNAME or set projectname in the YAML config.")
    return options


def _load_proxy_start_config(config_file: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise click.ClickException(f"Invalid YAML config {config_file}: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise click.ClickException("Proxy config must be a YAML mapping.")
    unknown = sorted(set(loaded) - PROXY_START_CONFIG_KEYS)
    if unknown:
        raise click.ClickException(f"Unknown proxy config option(s): {', '.join(unknown)}")
    return loaded


def _normalize_proxy_start_config(config: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    normalized: dict[str, Any] = {}

    projectname = config.get("projectname", config.get("project"))
    if projectname is not None:
        normalized["projectname"] = _require_string(projectname, "projectname")
    if "port" in config:
        normalized["port"] = _require_int(config["port"], "port")
    if "iface" in config:
        normalized["iface"] = _require_string(config["iface"], "iface")
    if "output" in config and config["output"] is not None:
        normalized["output"] = _config_path(config["output"], base_dir, "output")
    if "format" in config or "output_format" in config:
        value = config.get("format", config.get("output_format"))
        output_format = _require_string(value, "format")
        if output_format not in {"text", "json"}:
            raise click.ClickException("Proxy config format must be 'text' or 'json'.")
        normalized["output_format"] = output_format
    if "authorize" in config:
        normalized["authorize_files"] = _normalize_authorize_files(config["authorize"], base_dir)

    for key in ("project_autocreate", "reflect", "unique_request", "print_url_only", "print_header_only", "show_id"):
        if key in config:
            normalized[key] = _require_bool(config[key], key)

    return normalized


def _normalize_authorize_files(value: Any, base_dir: Path) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        items = value
    else:
        raise click.ClickException("Proxy config authorize must be a string path or a list of string paths.")

    paths = tuple(str(_config_path(item, base_dir, "authorize")) for item in items)
    for path in paths:
        if not Path(path).is_file():
            raise click.ClickException(f"Authorize file not found: {path}")
    return paths


def _config_path(value: Any, base_dir: Path, key: str) -> Path:
    path = Path(_require_string(value, key)).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path


def _require_string(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value:
        raise click.ClickException(f"Proxy config {key} must be a non-empty string.")
    return value


def _require_bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise click.ClickException(f"Proxy config {key} must be true or false.")
    return value


def _require_int(value: Any, key: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise click.ClickException(f"Proxy config {key} must be an integer.")
    return value


def _get_project(db, name: str) -> Project:
    project = db.query(Project).filter(Project.name == name).one_or_none()
    if project is None:
        raise click.ClickException(f"Project not found: {name}")
    return project


def _get_or_create_proxy_project(db, name: str, port: int, autocreate: bool) -> Project:
    project = db.query(Project).filter(Project.name == name).one_or_none()
    if project is not None:
        return project
    if not autocreate:
        raise click.ClickException(f"Project not found: {name}")

    project = Project(name=name, proxy_config={"port": port})
    db.add(project)
    db.flush()
    log_call(db, source="cli", operation=f"project autocreate {name}", project_id=project.id)
    return project


def _replace_authorize_users(db, project_id: int, authorize_files: tuple[str, ...]) -> None:
    db.query(AuthorizeUser).filter(AuthorizeUser.project_id == project_id).delete(synchronize_session=False)
    for data_file in authorize_files:
        name = Path(data_file).stem
        create_authorize_user(db, project_id, name, data_file)


def _latest_id(db, model, project_id: int) -> int:
    row_id = db.query(model.id).filter(model.project_id == project_id).order_by(model.id.desc()).limit(1).scalar()
    return int(row_id or 0)


def _print_new_activity(
    project_id: int,
    last_http_id: int,
    last_authorize_id: int,
    output_handle,
    output_format: str,
    print_url_only: bool = False,
    print_header_only: bool = False,
    show_id: bool = False,
) -> tuple[int, int]:
    with SessionLocal() as db:
        exchanges = (
            db.query(HttpExchange)
            .filter(HttpExchange.project_id == project_id, HttpExchange.id > last_http_id)
            .order_by(HttpExchange.id.asc())
            .all()
        )
        authorize_rows = (
            db.query(AuthorizeExchange)
            .filter(AuthorizeExchange.project_id == project_id, AuthorizeExchange.id > last_authorize_id)
            .order_by(AuthorizeExchange.id.asc())
            .all()
        )
        authorize_by_source: dict[int, list[AuthorizeExchange]] = {}
        for row in authorize_rows:
            authorize_by_source.setdefault(row.source_exchange_id, []).append(row)

        for exchange in exchanges:
            _emit_exchange(
                exchange,
                authorize_by_source.get(exchange.id, []),
                output_handle,
                output_format,
                print_url_only=print_url_only,
                print_header_only=print_header_only,
                show_id=show_id,
            )
            last_http_id = max(last_http_id, exchange.id)
        if not print_url_only:
            for source_id, rows in authorize_by_source.items():
                if source_id <= last_http_id:
                    continue
                _emit_authorize_summary(source_id, rows, output_handle, output_format)
        if authorize_rows:
            last_authorize_id = max(last_authorize_id, max(row.id for row in authorize_rows))
    return last_http_id, last_authorize_id


def _emit_exchange(
    exchange: HttpExchange,
    authorize_rows: list[AuthorizeExchange],
    output_handle,
    output_format: str,
    *,
    print_url_only: bool = False,
    print_header_only: bool = False,
    show_id: bool = False,
) -> None:
    if print_url_only:
        id_text = f" [{exchange.id}]" if show_id else ""
        _emit(f"[{exchange.method}]{id_text} {_exchange_url(exchange)}", output_handle)
        return

    if output_format == "json":
        request_raw = _raw_message_head(exchange.request_raw) if print_header_only else exchange.request_raw
        response_raw = _raw_message_head(exchange.response_raw) if print_header_only else exchange.response_raw
        payload = {
            "type": "exchange",
            "id": exchange.id,
            "method": exchange.method,
            "url": _exchange_url(exchange),
            "status_code": exchange.status_code,
            "response_size": exchange.response_size,
            "duration_ms": exchange.duration_ms,
            "reflected_params": exchange.reflecte_params,
            "request_raw": request_raw,
            "response_raw": response_raw,
            "authorize": [_authorize_payload(row) for row in authorize_rows],
        }
        _emit(json.dumps(payload, ensure_ascii=False), output_handle)
        return

    _emit(
        f"\n[{exchange.id}] {exchange.method} {_exchange_url(exchange)} -> "
        f"{exchange.status_code} {exchange.response_size}B {exchange.duration_ms}ms",
        output_handle,
    )
    _emit("--- Request ---", output_handle)
    _emit(_raw_message_head(exchange.request_raw) if print_header_only else exchange.request_raw, output_handle)
    _emit("--- Response ---", output_handle)
    _emit(_raw_message_head(exchange.response_raw) if print_header_only else exchange.response_raw, output_handle)
    if exchange.reflecte_params:
        _emit("--- Reflected params ---", output_handle)
        _emit(exchange.reflecte_params, output_handle)
    if authorize_rows:
        _emit_authorize_summary(exchange.id, authorize_rows, output_handle, output_format)


def _emit_authorize_summary(source_exchange_id: int, rows: list[AuthorizeExchange], output_handle, output_format: str) -> None:
    if output_format == "json":
        _emit(json.dumps({"type": "authorize", "source_exchange_id": source_exchange_id, "results": [_authorize_payload(row) for row in rows]}, ensure_ascii=False), output_handle)
        return

    _emit(f"--- Authorize comparison for exchange #{source_exchange_id} ---", output_handle)
    seen: dict[tuple[int, str], str] = {}
    for row in rows:
        signature = _response_signature(row.response_raw)
        peer = seen.get(signature)
        relation = f"same as {peer}" if peer else "baseline"
        seen.setdefault(signature, row.user_name)
        error = f" error={row.error}" if row.error else ""
        _emit(
            f"{row.user_name}: status={row.status_code} size={row.response_size} "
            f"duration={row.duration_ms}ms body_sha256={signature[1][:12]} {relation}{error}",
            output_handle,
        )


def _authorize_payload(row: AuthorizeExchange) -> dict[str, object]:
    status, body_hash = _response_signature(row.response_raw)
    return {
        "id": row.id,
        "user": row.user_name,
        "status_code": row.status_code,
        "response_size": row.response_size,
        "duration_ms": row.duration_ms,
        "same_response_key": {"status_code": status, "body_sha256": body_hash},
        "error": row.error,
        "request_raw": row.request_raw,
        "response_raw": row.response_raw,
    }


def _response_signature(response_raw: str) -> tuple[int, str]:
    header_text, _, body = response_raw.replace("\r\n", "\n").partition("\n\n")
    status = _response_status(header_text)
    return status, hashlib.sha256(body.encode()).hexdigest()


def _response_status(response_raw: str) -> int:
    first_line = response_raw.splitlines()[0] if response_raw.splitlines() else ""
    parts = first_line.split()
    for part in parts:
        if part.isdigit():
            return int(part)
    return 0


def _method_and_url(raw_request: str) -> tuple[str, str]:
    first_line = raw_request.splitlines()[0] if raw_request.splitlines() else ""
    parts = first_line.split()
    if len(parts) < 2:
        raise click.ClickException("Invalid request file: missing request line.")
    method = parts[0].upper()
    target = parts[1]
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        return method, target

    headers = _raw_headers(raw_request)
    host = headers.get("Host") or headers.get("host")
    if not host:
        raise click.ClickException("Invalid request file: relative request target requires a Host header.")
    path = target if target.startswith("/") else f"/{target}"
    return method, f"http://{host}{path}"


def _exchange_url(exchange: HttpExchange) -> str:
    query = f"?{exchange.query}" if exchange.query else ""
    scheme = "https" if exchange.port == 443 else "http"
    port = "" if exchange.port in {80, 443} else f":{exchange.port}"
    return f"{scheme}://{exchange.host}{port}{exchange.path or '/'}{query}"


def _raw_headers(raw_request: str) -> dict[str, str]:
    header_text, separator, _body = raw_request.partition("\n\n")
    if not separator:
        header_text, _separator, _body = raw_request.partition("\r\n\r\n")

    headers: dict[str, str] = {}
    for line in header_text.replace("\r\n", "\n").split("\n")[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip()] = value.strip()
    return headers


def _exchange_matches(
    row: HttpExchange,
    needle: str,
    *,
    request_only: bool,
    response_only: bool,
    body_only: bool = False,
    header_only: bool = False,
) -> bool:
    if not body_only and not header_only:
        return needle in _exchange_url(row).casefold()

    values = []
    if not response_only:
        values.extend(_message_search_values(row.request_raw or "", body_only=body_only, header_only=header_only))
    if not request_only:
        values.extend(_message_search_values(row.response_raw or "", body_only=body_only, header_only=header_only))
    return any(needle in value.casefold() for value in values)


def _message_search_values(raw_message: str, *, body_only: bool, header_only: bool) -> list[str]:
    if body_only or header_only:
        values = []
        if header_only:
            values.append(_raw_header_text(raw_message))
        if body_only:
            values.append(_raw_body(raw_message))
        return values
    return [raw_message]


def _raw_header_text(raw_message: str) -> str:
    header_text, separator, _body = raw_message.partition("\n\n")
    if not separator:
        header_text, _separator, _body = raw_message.partition("\r\n\r\n")
    return "\n".join(header_text.replace("\r\n", "\n").split("\n")[1:])


def _raw_message_head(raw_message: str) -> str:
    header_text, separator, _body = raw_message.partition("\n\n")
    if not separator:
        header_text, _separator, _body = raw_message.partition("\r\n\r\n")
    return header_text.replace("\r\n", "\n")


def _parse_header_overrides(values: tuple[str, ...], option_name: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        key, separator, header_value = value.partition(":")
        if not separator or not key.strip():
            raise click.ClickException(f"Invalid --{option_name}: {value!r}")
        headers[key.strip()] = header_value.strip()
    return headers


def _run_bac_check(
    label: str,
    method: str,
    url: str,
    raw_request: str,
    user1_headers: dict[str, str],
    user2_headers: dict[str, str],
) -> dict[str, object]:
    user1_request = _override_raw_request_headers(raw_request, user1_headers)
    user2_request = _override_raw_request_headers(raw_request, user2_headers)
    user1 = _send_bac_attempt(method, url, user1_request)
    user2 = _send_bac_attempt(method, url, user2_request)
    return {
        "label": label,
        "method": method,
        "url": url,
        "user1": user1,
        "user2": user2,
        "same_code": user1["status_code"] == user2["status_code"],
        "same_size": user1["size"] == user2["size"],
        "same_body": user1["body"] == user2["body"],
    }


def _send_bac_attempt(method: str, url: str, raw_request: str) -> dict[str, object]:
    started = time.perf_counter()
    try:
        response_raw = send_repeater_request(method, url, raw_request)
        body = _raw_body(response_raw)
        error = ""
        status_code = _response_status(response_raw)
    except Exception as exc:  # noqa: BLE001 - network failures are part of the BAC result.
        response_raw = str(exc)
        body = ""
        error = str(exc)
        status_code = 0
    return {
        "status_code": status_code,
        "size": len(body.encode()),
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "body": body,
        "error": error,
        "response_raw": response_raw,
    }


def _override_raw_request_headers(raw_request: str, overrides: dict[str, str]) -> str:
    normalized = raw_request.replace("\r\n", "\n")
    header_text, separator, body = normalized.partition("\n\n")
    lines = header_text.split("\n") if header_text else [""]
    if not lines:
        return raw_request

    overrides_by_key = {key.casefold(): (key, value) for key, value in overrides.items()}
    remaining_keys = set(overrides_by_key)
    updated_headers = []
    for line in lines[1:]:
        key, header_separator, _value = line.partition(":")
        normalized_key = key.strip().casefold()
        if header_separator and normalized_key in overrides_by_key:
            override_key, override_value = overrides_by_key[normalized_key]
            updated_headers.append(f"{override_key}: {override_value}")
            remaining_keys.discard(normalized_key)
            continue
        updated_headers.append(line)
    new_headers = [f"{overrides_by_key[key][0]}: {overrides_by_key[key][1]}" for key in overrides_by_key if key in remaining_keys]
    rebuilt = "\n".join([lines[0], *updated_headers, *new_headers])
    return f"{rebuilt}\n\n{body}" if separator else rebuilt


def _emit_bac_result(result: dict[str, object]) -> None:
    user1 = result["user1"]
    user2 = result["user2"]
    click.echo(f"{result['label']}: {result['method']} {result['url']}")
    click.echo(
        "user1: "
        f"status={user1['status_code']} size={user1['size']} duration={user1['duration_ms']}ms "
        f"body_sha256={str(user1['body_sha256'])[:12]}{_format_bac_error(user1)}"
    )
    click.echo(
        "user2: "
        f"status={user2['status_code']} size={user2['size']} duration={user2['duration_ms']}ms "
        f"body_sha256={str(user2['body_sha256'])[:12]}{_format_bac_error(user2)}"
    )
    click.echo(
        "comparison: "
        f"same_code={yes_no(bool(result['same_code']))} "
        f"same_size={yes_no(bool(result['same_size']))} "
        f"same_body={yes_no(bool(result['same_body']))}"
    )


def _format_bac_error(result: dict[str, object]) -> str:
    return f" error={result['error']}" if result.get("error") else ""


def _raw_body(raw_request: str) -> str:
    _head, separator, body = raw_request.partition("\n\n")
    if separator:
        return body
    _head, _separator, body = raw_request.partition("\r\n\r\n")
    return body


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _emit(message: str, output_handle=None) -> None:
    click.echo(message)
    if output_handle is not None:
        output_handle.write(f"{message}\n")
        output_handle.flush()


if __name__ == "__main__":
    cli()

