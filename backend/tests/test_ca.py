from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

import app.services.ca as ca_module
from app.services.ca import ensure_ca, ensure_host_certificate


def test_ensure_ca_reuses_existing_certificate(tmp_path, monkeypatch):
    monkeypatch.setattr(ca_module, "get_settings", lambda: SimpleNamespace(resolved_data_dir=tmp_path))

    first_cert = ensure_ca(1)
    second_cert = ensure_ca(1)

    assert first_cert == second_cert
    assert x509.load_pem_x509_certificate(first_cert).serial_number == x509.load_pem_x509_certificate(
        second_cert
    ).serial_number


def test_host_certificate_includes_server_tls_extensions(tmp_path, monkeypatch):
    monkeypatch.setattr(ca_module, "get_settings", lambda: SimpleNamespace(resolved_data_dir=tmp_path))

    cert_path, _key_path = ensure_host_certificate(1, "api.example.test")
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["api.example.test"]

    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature is True
    assert key_usage.key_encipherment is True
    assert key_usage.key_cert_sign is False

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
