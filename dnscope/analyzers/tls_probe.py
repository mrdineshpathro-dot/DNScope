"""Safe TLS inspection.

DNScope performs a standard TLS handshake and reads the certificate the server
presents. It does **not**:

* attempt protocol downgrade or cipher attacks
* send exploit payloads
* test for known-vulnerable implementations

Inspection must be explicitly authorized by the operator (``dnscope tls`` or the
``tls_inspection`` scan flag) because it opens a connection to the target.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
from typing import Any

from dnscope.models.certificates import CertificateChain, CertificateInfo, TLSHandshakeResult
from dnscope.models.common import Confidence
from dnscope.security.ssrf import SSRFValidator
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import parse_timestamp, utc_now_iso

_log = get_logger("analyzers.tls")

#: Cipher suites we never negotiate (we do not test them, we simply avoid them).
DEFAULT_MINIMUM_VERSION = ssl.TLSVersion.TLSv1_2


class TLSProbe:
    """Performs authorized TLS handshakes and normalizes the result."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        verify: bool = True,
        alpn: list[str] | None = None,
        ssrf: SSRFValidator | None = None,
        allow_private: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verify = verify
        self.alpn = alpn or ["h2", "http/1.1"]
        self.ssrf = ssrf or SSRFValidator(block_private=True, allow_private=allow_private)
        self.allow_private = allow_private

    def inspect(
        self,
        host: str,
        port: int = 443,
        *,
        server_name: str | None = None,
        authorized: bool = False,
    ) -> TLSHandshakeResult:
        """Connect to ``host:port`` and record TLS metadata.

        Args:
            authorized: must be ``True`` for the probe to run. DNScope refuses
                to connect to targets the operator has not authorized.
        """
        hostname = normalize_hostname(host)
        result = TLSHandshakeResult(host=hostname, port=port, authorized=authorized)
        if not authorized:
            result.error = "TLS inspection requires explicit authorization"
            return result
        if not hostname:
            result.error = "empty host"
            return result

        sni = normalize_hostname(server_name or hostname)
        result.server_name = sni
        result.sni_sent = bool(sni)

        validation = self.ssrf.validate(f"https://{hostname}:{port}")
        if not validation.ok:
            result.error = f"blocked by SSRF policy: {validation.reason}"
            return result

        context = ssl.create_default_context()
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.minimum_version = DEFAULT_MINIMUM_VERSION
        with contextlib.suppress(NotImplementedError, ssl.SSLError):
            # Some platforms/OpenSSL builds expose no ALPN support; the handshake
            # still works, it just negotiates nothing.
            context.set_alpn_protocols(self.alpn)

        import time

        started = time.monotonic()
        try:
            with (
                socket.create_connection((hostname, port), timeout=self.timeout) as raw,
                context.wrap_socket(raw, server_hostname=sni or None) as connection,
            ):
                    result.tls_version = connection.version() or ""
                    cipher = connection.cipher()
                    if cipher:
                        result.cipher = cipher[0]
                        result.cipher_bits = int(cipher[2]) if len(cipher) > 2 else None
                    try:
                        negotiated = connection.selected_alpn_protocol()
                        result.alpn = [negotiated] if negotiated else []
                    except (NotImplementedError, ssl.SSLError):
                        result.alpn = []
                    der = connection.getpeercert(binary_form=True)
                    parsed = connection.getpeercert()
                    result.verified = bool(parsed) and self.verify
                    if der:
                        result.peer_certificate = _certificate_from_der(der, parsed)
                        result.chain = [result.peer_certificate] if result.peer_certificate else []
                    elif parsed:
                        result.peer_certificate = _certificate_from_parsed(parsed)
                        result.chain = [result.peer_certificate] if result.peer_certificate else []
                    result.ok = True
        except ssl.SSLCertVerificationError as exc:
            result.error = f"certificate verification failed: {exc.reason or exc}"
            result.verify_error = str(exc)
        except ssl.SSLError as exc:
            result.error = f"TLS handshake failed: {exc}"
        except TimeoutError:
            result.error = f"connection to {hostname}:{port} timed out"
        except OSError as exc:
            result.error = f"connection to {hostname}:{port} failed: {exc}"
        finally:
            result.duration_ms = (time.monotonic() - started) * 1000.0
        return result

    def chain(self, host: str, port: int = 443, *, authorized: bool = False) -> CertificateChain:
        """Return the presented chain as a :class:`CertificateChain`."""
        result = self.inspect(host, port, authorized=authorized)
        return CertificateChain(
            host=result.host,
            certificates=result.chain,
            leaf=result.peer_certificate,
            root_issuer=result.chain[-1].issuer_cn if result.chain else "",
            verified=result.verified,
            error=result.error,
        )


def _certificate_from_parsed(parsed: dict[str, Any]) -> CertificateInfo:
    """Convert ``ssl`` parsed-certificate data into :class:`CertificateInfo`."""
    subject_cn = ""
    for rdn in parsed.get("subject", ()) or ():
        for key, value in rdn:
            if key == "commonName":
                subject_cn = str(value)
    issuer_cn = ""
    issuer_org = ""
    for rdn in parsed.get("issuer", ()) or ():
        for key, value in rdn:
            if key == "commonName":
                issuer_cn = str(value)
            elif key == "organizationName":
                issuer_org = str(value)
    sans = [str(value) for _type, value in parsed.get("subjectAltName", ()) or []]
    return CertificateInfo(
        subject_cn=normalize_hostname(subject_cn),
        issuer_cn=normalize_hostname(issuer_cn),
        issuer_organization=issuer_org,
        subject_alternative_names=sans,
        serial_number=str(parsed.get("serialNumber", "")),
        not_before=parse_timestamp(_ssl_date(parsed.get("notBefore", ""))),
        not_after=parse_timestamp(_ssl_date(parsed.get("notAfter", ""))),
        version=int(parsed.get("version", 3)) if str(parsed.get("version", "")).isdigit() else None,
        source="tls",
        source_detail="live handshake",
        confidence=Confidence.HIGH,
    )


def _certificate_from_der(der: bytes, parsed: dict[str, Any] | None) -> CertificateInfo:
    """Parse a DER certificate with ``cryptography`` for full detail."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes


    certificate = x509.load_der_x509_certificate(der)
    try:
        subject_cn = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        subject_cn = ""
    try:
        issuer_cn = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        issuer_cn = ""
    try:
        issuer_org = certificate.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        issuer_org = ""

    sans: list[str] = []
    with contextlib.suppress(x509.ExtensionNotFound):
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(name.value) for name in extension.value]

    public_key = certificate.public_key()
    key_bits = getattr(public_key, "key_size", None)
    algorithm_name = type(public_key).__name__.replace("PublicKey", "")

    basic_constraints_ca = False
    with contextlib.suppress(x509.ExtensionNotFound):
        basic_constraints_ca = bool(
            certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )

    info = CertificateInfo(
        subject_cn=normalize_hostname(str(subject_cn)),
        issuer_cn=normalize_hostname(str(issuer_cn)),
        issuer_organization=str(issuer_org),
        subject_alternative_names=sans,
        serial_number=format(certificate.serial_number, "x"),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        fingerprint_sha1=certificate.fingerprint(hashes.SHA1()).hex(),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        signature_algorithm=certificate.signature_algorithm_oid._name,
        public_key_algorithm=algorithm_name,
        public_key_bits=int(key_bits) if key_bits else None,
        is_ca=basic_constraints_ca,
        version=certificate.version.value + 1,
        source="tls",
        source_detail=f"live handshake at {utc_now_iso()}",
        confidence=Confidence.HIGH,
    )
    if parsed:
        # ``ssl`` already validated the chain; keep that signal.
        info.raw["validated_by_ssl_module"] = True
    return info


def _ssl_date(value: str) -> str:
    """Convert ``ssl``'s ``'Mon DD HH:MM:SS YYYY GMT'`` into ISO-8601."""
    from datetime import UTC, datetime

    if not value:
        return ""
    try:
        moment = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_expiry(certificate: CertificateInfo | None) -> str:
    """Human description of a certificate's remaining validity."""
    if certificate is None:
        return "no certificate presented"
    remaining = certificate.days_until_expiry()
    if remaining is None:
        return "unknown expiry"
    if remaining < 0:
        return f"expired {abs(remaining):.0f} day(s) ago"
    return f"expires in {remaining:.0f} day(s)"


__all__ = ["TLSProbe", "describe_expiry"]
