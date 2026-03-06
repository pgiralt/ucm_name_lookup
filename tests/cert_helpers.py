"""Test certificate generation helpers.

Generates ephemeral CA, server, and client certificates using the
``cryptography`` library for mTLS testing. All keys use ECDSA P-256
with SHA-256 signatures. Certificates are valid for 1 day and are
never persisted outside of pytest ``tmp_path`` fixtures.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _generate_key() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


def _one_day() -> datetime.timedelta:
    return datetime.timedelta(days=1)


def generate_ca(
    cn: str = "Test CA",
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Generate a self-signed CA certificate and private key."""
    key = _generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _one_day())
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def generate_leaf(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    cn: str = "localhost",
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Generate a leaf certificate signed by the given CA.

    Args:
        ca_cert: The CA certificate to sign with.
        ca_key: The CA private key.
        cn: Common Name for the leaf certificate.
        san_dns: Optional list of DNS SAN entries.
        san_ips: Optional list of IP address SAN entries.
    """
    import ipaddress as _ipaddress

    key = _generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _one_day())
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    # Add SANs
    san_entries: list[x509.GeneralName] = []
    if san_dns:
        for dns in san_dns:
            san_entries.append(x509.DNSName(dns))
    if san_ips:
        for ip in san_ips:
            san_entries.append(x509.IPAddress(_ipaddress.ip_address(ip)))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, key


def write_pem_cert(cert: x509.Certificate, path) -> str:
    """Write a certificate to a PEM file. Returns the path as a string."""
    path = str(path)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return path


def write_pem_key(key: ec.EllipticCurvePrivateKey, path) -> str:
    """Write a private key to a PEM file (unencrypted). Returns the path."""
    path = str(path)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return path


def write_pem_bundle(certs: list[x509.Certificate], path) -> str:
    """Write multiple certificates to a single PEM bundle file."""
    path = str(path)
    with open(path, "wb") as f:
        for cert in certs:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return path
