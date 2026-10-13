from urllib.parse import urlsplit


OWASP_RESPONSE_SECURITY_HEADERS = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
)


def missing_owasp_security_headers(url: str, response_headers: dict) -> str:
    present = {str(key).lower() for key in response_headers}
    missing = [header for header in OWASP_RESPONSE_SECURITY_HEADERS if header.lower() not in present]

    csp = _header_value(response_headers, "Content-Security-Policy")
    if "x-frame-options" not in present and "frame-ancestors" not in csp.lower():
        missing.append("X-Frame-Options")

    if urlsplit(url).scheme == "https" and "strict-transport-security" not in present:
        missing.append("Strict-Transport-Security")

    return ", ".join(missing)


def _header_value(headers: dict, name: str) -> str:
    expected = name.lower()
    for key, value in headers.items():
        if str(key).lower() == expected:
            return str(value)
    return ""
