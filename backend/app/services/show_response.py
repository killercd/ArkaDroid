HOP_BY_HOP_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def parse_raw_response(raw_response: str, fallback_status: int = 200) -> tuple[int, list[tuple[str, str]], bytes]:
    normalized = (raw_response or "").replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    if not separator:
        return _valid_status(fallback_status), [("Content-Type", "text/plain; charset=utf-8")], normalized.encode()

    lines = head.split("\n")
    status_code = _status_from_status_line(lines[0] if lines else "", fallback_status)
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if separator and key.strip() and key.strip().lower() not in HOP_BY_HOP_HEADERS:
            headers.append((key.strip(), value.strip()))
    if not any(key.lower() == "content-type" for key, _ in headers):
        headers.append(("Content-Type", "text/html; charset=utf-8"))
    return status_code, headers, body.encode()


def _status_from_status_line(status_line: str, fallback_status: int) -> int:
    for part in status_line.split():
        if part.isdigit():
            return _valid_status(int(part))
    return _valid_status(fallback_status)


def _valid_status(status_code: int) -> int:
    return status_code if 100 <= status_code <= 599 else 200
