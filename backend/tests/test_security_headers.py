from app.services.security_headers import missing_owasp_security_headers


def test_missing_owasp_security_headers_reports_absent_headers_for_https():
    missing = missing_owasp_security_headers(
        "https://example.test/",
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )

    assert missing == (
        "Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, "
        "Cross-Origin-Resource-Policy, Strict-Transport-Security"
    )


def test_missing_owasp_security_headers_accepts_x_frame_options_without_frame_ancestors():
    missing = missing_owasp_security_headers(
        "http://example.test/",
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )

    assert missing == ""
