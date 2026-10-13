from datetime import UTC, datetime, timedelta
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core.config import get_settings


def _cert_paths(project_id: int) -> tuple[Path, Path]:
    base = get_settings().resolved_data_dir / "certs" / str(project_id)
    base.mkdir(parents=True, exist_ok=True)
    return base / "arkadroid-ca.pem", base / "arkadroid-ca-key.pem"


def _host_cert_paths(project_id: int, host: str) -> tuple[Path, Path]:
    safe_host = "".join(char if char.isalnum() or char in ".-" else "_" for char in host)
    base = get_settings().resolved_data_dir / "certs" / str(project_id) / "hosts"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{safe_host}.pem", base / f"{safe_host}-key.pem"


def ensure_ca(project_id: int) -> bytes:
    cert_path, key_path = _cert_paths(project_id)
    if cert_path.exists() and key_path.exists():
        return cert_path.read_bytes()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ArkaDroid"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"ArkaDroid Project {project_id} CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_path.write_bytes(cert_bytes)
    key_path.write_bytes(key_bytes)
    return cert_bytes


def ensure_host_certificate(project_id: int, host: str) -> tuple[str, str]:
    ensure_ca(project_id)
    cert_path, key_path = _host_cert_paths(project_id, host)
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    ca_cert_path, ca_key_path = _cert_paths(project_id)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ArkaDroid"),
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ]
    )

    san_entries: list[x509.GeneralName] = [x509.DNSName(host)]
    try:
        san_entries = [x509.IPAddress(ipaddress.ip_address(host))]
    except ValueError:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def import_ca(project_id: int, cert_pem: bytes, key_pem: bytes) -> None:
    cert_path, key_path = _cert_paths(project_id)
    x509.load_pem_x509_certificate(cert_pem)
    serialization.load_pem_private_key(key_pem, password=None)
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
