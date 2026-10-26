from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import click

PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.db.session import SessionLocal, init_db  # noqa: E402
from app.models.http import HttpExchange  # noqa: E402
from app.models.projects import Project  # noqa: E402
from app.services import fuzzer  # noqa: E402
from app.services.authorize import parse_authorize_data  # noqa: E402
from app.services.repeater import send_repeater_request  # noqa: E402
from app.services.security_headers import missing_owasp_security_headers  # noqa: E402
from arkadroid_cli import (  # noqa: E402
    _exchange_url,
    _override_raw_request_headers,
    _parse_header_overrides,
    _raw_body,
    _raw_headers,
    _response_status,
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """ArkaDroid audit command line interface."""
    init_db()


@cli.command("authorize")
@click.argument("projectname", required=False)
@click.option("--id", "id_expression", help="HTTP exchange id, comma list, or range.")
@click.option("--match", "match_pattern", help="Replay exchanges whose URL contains this text, case-insensitive.")
@click.option(
    "--not-match",
    "not_match_pattern",
    help="Replay exchanges whose URL does not contain this text, case-insensitive.",
)
@click.option(
    "--request",
    "request_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Raw HTTP request file to replay.",
)
@click.option(
    "--header-file",
    "header_files",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Header override file. May be repeated.",
)
@click.option("--show-request", is_flag=True, help="Print the sent request before each response summary.")
@click.option("--show-id", is_flag=True, help="Include the HTTP exchange id in output lines.")
@click.option("--proxy-ip", help="Proxy host/IP to use for replay requests, for example 127.0.0.1.")
@click.option("--proxy-port", type=click.IntRange(1, 65535), help="Proxy port to use for replay requests.")
@click.option("--force-ssl", is_flag=True, help="Force HTTPS for target requests.")
def authorize(
    projectname: str | None,
    id_expression: str | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
    request_file: Path | None,
    header_files: tuple[Path, ...],
    show_request: bool,
    show_id: bool,
    proxy_ip: str | None,
    proxy_port: int | None,
    force_ssl: bool,
) -> None:
    """Replay saved requests with alternate authorization headers."""
    has_url_filters = bool(match_pattern or not_match_pattern)
    source_count = int(id_expression is not None) + int(has_url_filters) + int(request_file is not None)
    if source_count != 1:
        raise click.ClickException("Use exactly one of --id, URL filters, or --request.")
    if not header_files:
        raise click.ClickException("Use at least one --header-file.")

    header_sets = [(str(path), parse_authorize_data(str(path))) for path in header_files]
    proxy = _proxy_url(proxy_ip, proxy_port)
    sources = _audit_sources(
        projectname,
        id_expression=id_expression,
        match_pattern=match_pattern,
        not_match_pattern=not_match_pattern,
        request_file=request_file,
    )
    if force_ssl:
        sources = [_force_ssl_source(source) for source in sources]

    for source_index, source in enumerate(sources):
        if source_index:
            click.echo()
        _run_authorize_source(source, header_sets, show_request=show_request, show_id=show_id, proxy=proxy)


@cli.command("reflect")
@click.argument("projectname", required=False)
@click.option("--id", "id_expression", help="HTTP exchange id, comma list, or range.")
@click.option("--match", "match_pattern", help="Probe exchanges whose URL contains this text, case-insensitive.")
@click.option(
    "--not-match",
    "not_match_pattern",
    help="Probe exchanges whose URL does not contain this text, case-insensitive.",
)
@click.option(
    "--request",
    "request_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Raw HTTP request file to probe.",
)
@click.option(
    "--reflect-param",
    "reflect_params",
    multiple=True,
    required=True,
    help="Parameter name to replace. Use ALL to probe every parameter.",
)
@click.option(
    "--reflect-string",
    required=True,
    help="Marker value to send and search in the response body.",
)
@click.option("--header", "header_overrides", multiple=True, help="Add or replace a request header. May be repeated.")
@click.option("--show-request", is_flag=True, help="Print the sent request before each response summary.")
@click.option("--show-id", is_flag=True, help="Include the HTTP exchange id in output lines.")
@click.option("--proxy-ip", help="Proxy host/IP to use for replay requests, for example 127.0.0.1.")
@click.option("--proxy-port", type=click.IntRange(1, 65535), help="Proxy port to use for replay requests.")
@click.option("--force-ssl", is_flag=True, help="Force HTTPS for target requests.")
def reflect(
    projectname: str | None,
    id_expression: str | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
    request_file: Path | None,
    reflect_params: tuple[str, ...],
    reflect_string: str,
    header_overrides: tuple[str, ...],
    show_request: bool,
    show_id: bool,
    proxy_ip: str | None,
    proxy_port: int | None,
    force_ssl: bool,
) -> None:
    """Probe selected request parameters for body reflection."""
    has_url_filters = bool(match_pattern or not_match_pattern)
    source_count = int(id_expression is not None) + int(has_url_filters) + int(request_file is not None)
    if source_count != 1:
        raise click.ClickException("Use exactly one of --id, URL filters, or --request.")

    header_values = _parse_header_overrides(header_overrides, "header")
    sources = _audit_sources(
        projectname,
        id_expression=id_expression,
        match_pattern=match_pattern,
        not_match_pattern=not_match_pattern,
        request_file=request_file,
    )
    proxy = _proxy_url(proxy_ip, proxy_port)
    if force_ssl:
        sources = [_force_ssl_source(source) for source in sources]
    if header_values:
        sources = [_with_header_overrides(source, header_values) for source in sources]
    selected_params = set(reflect_params)
    if "ALL" in selected_params:
        selected_params.add("*")
    found_attempt = False
    for source in sources:
        attempts = _reflect_attempts(source, selected_params, reflect_string)
        if not attempts:
            continue
        found_attempt = True
        _run_reflect_source(source, attempts, reflect_string, show_request=show_request, show_id=show_id, proxy=proxy)

    if not found_attempt:
        raise click.ClickException("No selected parameters found in the URL or body.")


@cli.command("fuzz")
@click.argument("projectname", required=False)
@click.option("--id", "exchange_id", type=int, help="HTTP exchange id to fuzz.")
@click.option("--match", "match_pattern", help="Fuzz exchanges whose URL contains this text, case-insensitive.")
@click.option(
    "--not-match",
    "not_match_pattern",
    help="Fuzz exchanges whose URL does not contain this text, case-insensitive.",
)
@click.option("--url", "target_url", help="Explicit GET URL containing FUZZ.")
@click.option(
    "--request",
    "request_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Raw HTTP request file containing FUZZ.",
)
@click.option("--fuzz-param", "fuzz_params", multiple=True, help="Parameter name to fuzz in query, form body, or JSON body.")
@click.option("--range", "range_expression", required=True, help="Inclusive numeric range, for example 1-500.")
@click.option("--max-thread", default=1, show_default=True, type=click.IntRange(1), help="Number of active threads.")
@click.option("--delay", default=0, show_default=True, type=click.IntRange(0), help="Delay in milliseconds after each request.")
@click.option("--show-response", is_flag=True, help="Print the complete response for each attempt.")
@click.option("--show-id", is_flag=True, help="Include the HTTP exchange id in output lines.")
@click.option("--proxy-ip", help="Proxy host/IP to use for fuzz requests, for example 127.0.0.1.")
@click.option("--proxy-port", type=click.IntRange(1, 65535), help="Proxy port to use for fuzz requests.")
@click.option("--force-ssl", is_flag=True, help="Force HTTPS for target requests.")
def fuzz(
    projectname: str | None,
    exchange_id: int | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
    target_url: str | None,
    request_file: Path | None,
    fuzz_params: tuple[str, ...],
    range_expression: str,
    max_thread: int,
    delay: int,
    show_response: bool,
    show_id: bool,
    proxy_ip: str | None,
    proxy_port: int | None,
    force_ssl: bool,
) -> None:
    """Fuzz a saved request parameter or FUZZ marker with numeric payloads."""
    has_url_filters = bool(match_pattern or not_match_pattern)
    source_count = sum(value is not None for value in (exchange_id, target_url, request_file)) + int(has_url_filters)
    if source_count != 1:
        raise click.ClickException("Use exactly one of --id, URL filters, --url, or --request.")
    uses_saved_exchanges = exchange_id is not None or has_url_filters
    if uses_saved_exchanges and not fuzz_params:
        raise click.ClickException("Use at least one --fuzz-param with saved exchange selectors.")
    if not uses_saved_exchanges and fuzz_params:
        raise click.ClickException("--fuzz-param can only be used with saved exchange selectors.")

    try:
        values = fuzzer.parse_fuzz_range(range_expression)
        sources = _fuzz_sources(projectname, exchange_id, match_pattern, not_match_pattern, target_url, request_file)
        if force_ssl:
            sources = [fuzzer.force_ssl_source(source) for source in sources]
        attempts = []
        for source in sources:
            if uses_saved_exchanges:
                attempts.extend(fuzzer.build_param_attempts(source, set(fuzz_params), values))
            else:
                attempts.extend(fuzzer.build_keyword_attempts(source, values))
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if not attempts:
        raise click.ClickException("No selected parameters found in the URL or body.")

    proxy = _proxy_url(proxy_ip, proxy_port)
    click.echo(f"Fuzzing {len(attempts)} attempts with {max_thread} thread(s).")
    for result in fuzzer.run_attempts(attempts, max_workers=max_thread, delay_ms=delay, proxy=proxy):
        _emit_fuzz_result(result, show_response=show_response, show_id=show_id)


@cli.command("check-headers")
@click.argument("projectname", required=False)
@click.option("--id", "id_expression", help="HTTP exchange id, comma list, or range.")
@click.option("--match", "match_pattern", help="Check exchanges whose URL contains this text, case-insensitive.")
@click.option(
    "--not-match",
    "not_match_pattern",
    help="Check exchanges whose URL does not contain this text, case-insensitive.",
)
@click.option("--url", "target_url", help="Explicit GET URL to request and check.")
@click.option(
    "--request",
    "request_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Raw HTTP request file to send and check.",
)
@click.option("--show-id", is_flag=True, help="Include the HTTP exchange id in output lines.")
@click.option("--show-response", is_flag=True, help="Print the complete response for each check.")
@click.option("--proxy-ip", help="Proxy host/IP to use for live check requests, for example 127.0.0.1.")
@click.option("--proxy-port", type=click.IntRange(1, 65535), help="Proxy port to use for live check requests.")
@click.option("--force-ssl", is_flag=True, help="Force HTTPS for target requests.")
def check_headers(
    projectname: str | None,
    id_expression: str | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
    target_url: str | None,
    request_file: Path | None,
    show_id: bool,
    show_response: bool,
    proxy_ip: str | None,
    proxy_port: int | None,
    force_ssl: bool,
) -> None:
    """Report missing security headers in saved or live HTTP responses."""
    has_url_filters = bool(match_pattern or not_match_pattern)
    source_count = sum(value is not None for value in (id_expression, target_url, request_file)) + int(has_url_filters)
    if source_count != 1:
        raise click.ClickException("Use exactly one of --id, URL filters, --url, or --request.")

    proxy = _proxy_url(proxy_ip, proxy_port)
    sources = _check_header_sources(
        projectname,
        id_expression,
        match_pattern,
        not_match_pattern,
        target_url,
        request_file,
        proxy,
        force_ssl=force_ssl,
    )
    for source in sources:
        _emit_check_headers_result(source, show_id=show_id, show_response=show_response)


def _fuzz_sources(
    projectname: str | None,
    exchange_id: int | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
    target_url: str | None,
    request_file: Path | None,
) -> list[fuzzer.FuzzSource]:
    if exchange_id is not None or match_pattern is not None or not_match_pattern is not None:
        if not projectname:
            raise click.ClickException("PROJECTNAME is required with --id, --match, or --not-match.")
        with SessionLocal() as db:
            project = _get_project(db, projectname)
            if exchange_id is not None:
                row = (
                    db.query(HttpExchange)
                    .filter(HttpExchange.project_id == project.id, HttpExchange.id == exchange_id)
                    .one_or_none()
                )
                if row is None:
                    raise click.ClickException("No matching HTTP exchange found.")
                return [fuzzer.source_from_exchange(row)]
            rows = _matching_exchange_rows(
                db.query(HttpExchange).filter(HttpExchange.project_id == project.id),
                match_pattern,
                not_match_pattern,
            )
            if not rows:
                raise click.ClickException("No matching HTTP exchanges found.")
            return [fuzzer.source_from_exchange(row) for row in rows]
    if target_url is not None:
        return [fuzzer.source_from_url(target_url)]
    if request_file is not None:
        return [fuzzer.source_from_request_file(request_file)]
    raise click.ClickException("Use exactly one of --id, URL filters, --url, or --request.")


def _check_header_sources(
    projectname: str | None,
    id_expression: str | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
    target_url: str | None,
    request_file: Path | None,
    proxy: str | None,
    force_ssl: bool = False,
) -> list[dict[str, object]]:
    if id_expression is not None or match_pattern is not None or not_match_pattern is not None:
        if not projectname:
            raise click.ClickException("PROJECTNAME is required with --id, --match, or --not-match.")
        rows = _selected_sources(
            projectname,
            id_expression=id_expression,
            match_pattern=match_pattern,
            not_match_pattern=not_match_pattern,
        )
        return [
            {
                **(_force_ssl_source(source) if force_ssl else source),
                "response_raw": _saved_response_raw(projectname, int(source["id"])),
                "error": "",
            }
            for source in rows
        ]
    if target_url is not None:
        if not projectname:
            raise click.ClickException("PROJECTNAME is required with --url.")
        with SessionLocal() as db:
            _get_project(db, projectname)
        url = _force_ssl_url(target_url) if force_ssl else target_url
        raw_request = f"GET {url} HTTP/1.1\n\n"
        result = _send_attempt("GET", url, raw_request, proxy=proxy)
        return [
            {
                "label": "url",
                "id": None,
                "method": "GET",
                "url": url,
                "response_raw": result["response_raw"],
                "error": result["error"],
            }
        ]
    if request_file is not None:
        source = _source_from_request_file(request_file)
        if force_ssl:
            source = _force_ssl_source(source)
        method = str(source["method"])
        url = str(source["url"])
        raw_request = str(source["raw_request"])
        result = _send_attempt(method, url, raw_request, proxy=proxy)
        return [
            {
                "label": str(request_file),
                "id": None,
                "method": method,
                "url": url,
                "response_raw": result["response_raw"],
                "error": result["error"],
            }
        ]
    raise click.ClickException("Use exactly one of --id, URL filters, --url, or --request.")


def _saved_response_raw(projectname: str, exchange_id: int) -> str:
    with SessionLocal() as db:
        project = _get_project(db, projectname)
        row = (
            db.query(HttpExchange)
            .filter(HttpExchange.project_id == project.id, HttpExchange.id == exchange_id)
            .one_or_none()
        )
        if row is None:
            raise click.ClickException("No matching HTTP exchange found.")
        return row.response_raw or ""


def _emit_check_headers_result(source: dict[str, object], *, show_id: bool, show_response: bool) -> None:
    response_raw = str(source["response_raw"])
    headers = _response_headers(response_raw)
    missing = missing_owasp_security_headers(str(source["url"]), headers)
    error = str(source.get("error") or "")
    prefix = f"{_id_prefix(source.get('id'), show_id)}{source['method']} {source['url']}"
    if error:
        click.secho(f"{prefix} error={error}", fg="red")
    elif missing:
        click.secho(f"{prefix} missing={missing}", fg="red")
    else:
        click.secho(f"{prefix} ok", fg="green")
    if show_response:
        click.echo("--- Response ---")
        click.echo(response_raw)


def _emit_fuzz_result(result: dict[str, object], *, show_response: bool, show_id: bool) -> None:
    error = f" error={result['error']}" if result.get("error") else ""
    click.echo(
        f"{_id_prefix(result.get('source_exchange_id'), show_id)}{result['source']}:{result['name']}={result['value']} "
        f"status={result['status_code']} size={result['size']} "
        f"duration={result['duration_ms']}ms{error}"
    )
    if show_response:
        click.echo("--- Response ---")
        click.echo(result["response_raw"])


def _run_reflect_source(
    source: dict[str, object],
    attempts: list[dict[str, object]],
    reflect_string: str,
    *,
    show_request: bool,
    show_id: bool,
    proxy: str | None,
) -> None:
    for index, attempt in enumerate(attempts):
        if index and show_request:
            click.echo()
        result = _send_attempt(str(source["method"]), str(attempt["url"]), str(attempt["raw_request"]), proxy=proxy)
        reflected = reflect_string in str(result["body"])
        if show_request:
            click.echo("--- Request ---")
            click.echo(attempt["raw_request"])
            click.echo("--- Response ---")
        line = (
            f"{_id_prefix(source.get('id'), show_id)}{attempt['source']}:{attempt['name']} "
            f"status={result['status_code']} size={result['size']} "
            f"duration={result['duration_ms']}ms reflected={_yes_no(reflected)}"
        )
        if reflected:
            click.secho(line, fg="red")
        else:
            click.echo(line)


def _selected_sources(
    projectname: str,
    *,
    id_expression: str | None,
    match_pattern: str | None,
    not_match_pattern: str | None = None,
) -> list[dict[str, object]]:
    with SessionLocal() as db:
        project = _get_project(db, projectname)
        query = db.query(HttpExchange).filter(HttpExchange.project_id == project.id)
        if id_expression is not None:
            ids = _parse_id_expression(id_expression)
            rows = query.filter(HttpExchange.id.in_(ids)).order_by(HttpExchange.id.asc()).all()
        else:
            rows = _matching_exchange_rows(query, match_pattern, not_match_pattern)

    if not rows:
        raise click.ClickException("No matching HTTP exchanges found.")
    return [_source_from_exchange(row) for row in rows]


def _audit_sources(
    projectname: str | None,
    *,
    id_expression: str | None,
    match_pattern: str | None,
    not_match_pattern: str | None = None,
    request_file: Path | None = None,
) -> list[dict[str, object]]:
    if request_file is not None:
        return [_source_from_request_file(request_file)]
    if not projectname:
        raise click.ClickException("PROJECTNAME is required with --id, --match, or --not-match.")
    return _selected_sources(
        projectname,
        id_expression=id_expression,
        match_pattern=match_pattern,
        not_match_pattern=not_match_pattern,
    )


def _validate_saved_exchange_selector(
    id_expression: object | None,
    match_pattern: str | None,
    not_match_pattern: str | None,
) -> None:
    if id_expression and (match_pattern or not_match_pattern):
        raise click.ClickException("Use --id or URL filters, not both.")
    if not id_expression and not (match_pattern or not_match_pattern):
        raise click.ClickException("Use one of --id, --match, or --not-match.")


def _matching_exchange_rows(query, match_pattern: str | None, not_match_pattern: str | None) -> list[HttpExchange]:
    rows = query.order_by(HttpExchange.id.asc()).all()
    if match_pattern is not None:
        match_needle = match_pattern.casefold()
        rows = [row for row in rows if match_needle in _exchange_url(row).casefold()]
    if not_match_pattern is not None:
        not_match_needle = not_match_pattern.casefold()
        rows = [row for row in rows if not_match_needle not in _exchange_url(row).casefold()]
    return rows


def _source_from_exchange(row: HttpExchange) -> dict[str, object]:
    return {
        "label": f"exchange #{row.id}",
        "id": row.id,
        "method": row.method,
        "url": _exchange_url(row),
        "raw_request": row.request_raw,
    }


def _source_from_request_file(path: Path) -> dict[str, object]:
    raw_request = path.read_text(encoding="utf-8")
    method, url = fuzzer.method_and_url(raw_request)
    return {
        "label": str(path),
        "id": None,
        "method": method,
        "url": url,
        "raw_request": raw_request,
    }


def _parse_id_expression(value: str) -> list[int]:
    ids: list[int] = []
    for chunk in value.split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start_text, separator, end_text = part.partition("-")
            if not separator or not start_text.strip().isdigit() or not end_text.strip().isdigit():
                raise click.ClickException(f"Invalid --id value: {value!r}")
            start = int(start_text)
            end = int(end_text)
            if end < start:
                raise click.ClickException(f"Invalid --id range: {part!r}")
            ids.extend(range(start, end + 1))
        elif part.isdigit():
            ids.append(int(part))
        else:
            raise click.ClickException(f"Invalid --id value: {value!r}")
    if not ids:
        raise click.ClickException("Use at least one id in --id.")
    return list(dict.fromkeys(ids))


def _run_authorize_source(
    source: dict[str, object],
    header_sets: list[tuple[str, dict[str, str]]],
    *,
    show_request: bool,
    show_id: bool,
    proxy: str | None,
) -> None:
    method = str(source["method"])
    url = str(source["url"])
    raw_request = str(source["raw_request"])
    original = _send_attempt(method, url, raw_request, proxy=proxy)
    variants = []
    for label, headers in header_sets:
        variant_request = _override_raw_request_headers(raw_request, headers)
        variants.append((label, variant_request, _send_attempt(method, url, variant_request, proxy=proxy)))

    click.echo(f"{source['label']}: {method} {url}")
    _emit_authorize_attempt(
        "original",
        raw_request,
        original,
        source_id=source.get("id"),
        highlight=False,
        show_request=show_request,
        show_id=show_id,
    )
    for label, variant_request, result in variants:
        same = result["status_code"] == original["status_code"] and result["size"] == original["size"]
        _emit_authorize_attempt(
            label,
            variant_request,
            result,
            source_id=source.get("id"),
            highlight=same,
            show_request=show_request,
            show_id=show_id,
        )


def _emit_authorize_attempt(
    label: str,
    raw_request: str,
    result: dict[str, object],
    *,
    source_id: object | None,
    highlight: bool,
    show_request: bool,
    show_id: bool,
) -> None:
    if show_request:
        click.echo("--- Request ---")
        click.echo(raw_request)
        click.echo("--- Response ---")
    line = f"{_id_prefix(source_id, show_id)}{label}: status={result['status_code']} size={result['size']} duration={result['duration_ms']}ms"
    if result["error"]:
        line = f"{line} error={result['error']}"
    if highlight:
        click.secho(line, fg="red")
    else:
        click.echo(line)


def _send_attempt(method: str, url: str, raw_request: str, *, proxy: str | None = None) -> dict[str, object]:
    started = time.perf_counter()
    try:
        response_raw = send_repeater_request(method, url, raw_request, proxy=proxy)
        body = _raw_body(response_raw)
        status_code = _response_status(response_raw)
        error = ""
    except Exception as exc:  # noqa: BLE001 - audit output must include network failures.
        response_raw = str(exc)
        body = ""
        status_code = 0
        error = str(exc)
    return {
        "status_code": status_code,
        "size": len(body.encode()),
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "body": body,
        "response_raw": response_raw,
        "error": error,
    }


def _proxy_url(proxy_ip: str | None, proxy_port: int | None) -> str | None:
    if proxy_ip is None and proxy_port is None:
        return None
    if not proxy_ip or proxy_port is None:
        raise click.ClickException("Use both --proxy-ip and --proxy-port.")
    return f"http://{proxy_ip.strip()}:{proxy_port}"


def _force_ssl_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http":
        return url
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def _force_ssl_source(source: dict[str, object]) -> dict[str, object]:
    url = _force_ssl_url(str(source["url"]))
    return {
        **source,
        "url": url,
        "raw_request": _force_ssl_raw_request(str(source["raw_request"]), url),
    }


def _with_header_overrides(source: dict[str, object], headers: dict[str, str]) -> dict[str, object]:
    return {
        **source,
        "raw_request": _override_raw_request_headers(str(source["raw_request"]), headers),
    }


def _force_ssl_raw_request(raw_request: str, url: str) -> str:
    return _replace_request_target(raw_request, url)


def _reflect_attempts(
    source: dict[str, object],
    selected_names: set[str],
    marker: str,
) -> list[dict[str, object]]:
    raw_request = str(source["raw_request"])
    headers = _raw_headers(raw_request)
    body = _raw_body(raw_request)
    attempts = _query_reflect_attempts(source, selected_names, marker)
    attempts.extend(_body_reflect_attempts(source, headers, body, selected_names, marker))
    return attempts


def _query_reflect_attempts(
    source: dict[str, object],
    selected_names: set[str],
    marker: str,
) -> list[dict[str, object]]:
    include_all = "*" in selected_names
    parsed = urlsplit(str(source["url"]))
    params = parse_qsl(parsed.query, keep_blank_values=True)
    attempts = []
    for index, (name, _value) in enumerate(params):
        if not include_all and name not in selected_names:
            continue
        mutated = list(params)
        mutated[index] = (name, marker)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), parsed.fragment))
        attempts.append(
            {
                "source": "query",
                "name": name,
                "url": url,
                "raw_request": _replace_request_target(str(source["raw_request"]), url),
            }
        )
    return attempts


def _body_reflect_attempts(
    source: dict[str, object],
    headers: dict[str, str],
    body: str,
    selected_names: set[str],
    marker: str,
) -> list[dict[str, object]]:
    if not body:
        return []
    content_type = _header_value(headers, "Content-Type").casefold()
    if "json" in content_type:
        return _json_reflect_attempts(source, body, selected_names, marker)
    return _form_reflect_attempts(source, body, selected_names, marker)


def _form_reflect_attempts(
    source: dict[str, object],
    body: str,
    selected_names: set[str],
    marker: str,
) -> list[dict[str, object]]:
    include_all = "*" in selected_names
    params = parse_qsl(body, keep_blank_values=True)
    attempts = []
    for index, (name, _value) in enumerate(params):
        if not include_all and name not in selected_names:
            continue
        mutated = list(params)
        mutated[index] = (name, marker)
        attempts.append(
            {
                "source": "body",
                "name": name,
                "url": source["url"],
                "raw_request": _replace_raw_body(str(source["raw_request"]), urlencode(mutated)),
            }
        )
    return attempts


def _json_reflect_attempts(
    source: dict[str, object],
    body: str,
    selected_names: set[str],
    marker: str,
) -> list[dict[str, object]]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []

    attempts = []
    include_all = "*" in selected_names
    for display_name, key_name, path in _json_scalar_paths(payload):
        if not include_all and display_name not in selected_names and key_name not in selected_names:
            continue
        mutated = json.loads(body)
        _set_json_path(mutated, path, marker)
        attempts.append(
            {
                "source": "body",
                "name": display_name,
                "url": source["url"],
                "raw_request": _replace_raw_body(str(source["raw_request"]), json.dumps(mutated)),
            }
        )
    return attempts


def _json_scalar_paths(payload: object, prefix: str = "", path: tuple[object, ...] = ()):
    if isinstance(payload, dict):
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from _json_scalar_paths(value, name, (*path, key))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            name = f"{prefix}[{index}]" if prefix else str(index)
            yield from _json_scalar_paths(value, name, (*path, index))
    elif path:
        yield prefix, str(path[-1]), path


def _set_json_path(payload: object, path: tuple[object, ...], value: str) -> None:
    current = payload
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value


def _replace_raw_body(raw_request: str, body: str) -> str:
    head, separator, _old_body = raw_request.replace("\r\n", "\n").partition("\n\n")
    separator = separator or "\n\n"
    return f"{head}{separator}{body}"


def _replace_request_target(raw_request: str, url: str) -> str:
    normalized = raw_request.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if not lines:
        return raw_request
    parts = lines[0].split()
    if len(parts) < 2:
        return raw_request
    parts[1] = url
    lines[0] = " ".join(parts)
    return "\n".join(lines)


def _header_value(headers: dict[str, str], name: str) -> str:
    expected = name.casefold()
    for key, value in headers.items():
        if key.casefold() == expected:
            return value
    return ""


def _response_headers(raw_response: str) -> dict[str, str]:
    header_text, separator, _body = raw_response.partition("\n\n")
    if not separator:
        header_text, _separator, _body = raw_response.partition("\r\n\r\n")
    headers: dict[str, str] = {}
    for line in header_text.replace("\r\n", "\n").split("\n")[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip()] = value.strip()
    return headers


def _get_project(db, name: str) -> Project:
    project = db.query(Project).filter(Project.name == name).one_or_none()
    if project is None:
        raise click.ClickException(f"Project not found: {name}")
    return project


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _id_prefix(source_id: object | None, show_id: bool) -> str:
    if not show_id or source_id is None:
        return ""
    return f"id={source_id} "


if __name__ == "__main__":
    cli()
