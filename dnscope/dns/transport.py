"""DNS query transports: UDP, TCP, DoH and DoT.

The transport layer is deliberately thin: it sends a ``dns.message.Message`` and
returns ``(response, timing)``. All retry, caching and normalization logic lives
in :mod:`dnscope.dns.engine` so transports stay easy to test and swap.

Encrypted transports (DoH/DoT) are only used when the operator configures them
explicitly - DNScope never silently redirects queries through a third party.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import dns.message
import dns.query

from dnscope.exceptions import DNSError, DNSTimeout
from dnscope.models.dns import DNSTransport
from dnscope.utils.logging import get_logger

_log = get_logger("dns.transport")

#: Fallback payload size when EDNS is negotiated but the server is silent.
DEFAULT_EDNS_PAYLOAD = 1232


@dataclass
class TransportResult:
    """A raw response plus the metadata DNScope records about it."""

    response: Any
    duration_ms: float
    transport: str
    resolver: str
    truncated: bool = False
    tcp_fallback: bool = False
    attempts: int = 1
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.response is not None and not self.error


class DNSTransportError(DNSError):
    """A transport-level failure (no usable response)."""


class DNSTransportLayer:
    """Sends DNS messages over the configured transport."""

    def __init__(
        self,
        *,
        transport: str = DNSTransport.UDP,
        timeout: float = 5.0,
        port: int = 53,
        doh_url: str = "",
        dot_host: str = "",
        verify_tls: bool = True,
        edns_payload: int = DEFAULT_EDNS_PAYLOAD,
        tcp_fallback: bool = True,
    ) -> None:
        self.transport = transport.upper()
        self.timeout = timeout
        self.port = port
        self.doh_url = doh_url
        self.dot_host = dot_host
        self.verify_tls = verify_tls
        self.edns_payload = edns_payload
        self.tcp_fallback = tcp_fallback

    # ------------------------------------------------------------------ public

    def send(self, message: Any, resolver: str) -> TransportResult:
        """Send ``message`` to ``resolver`` using the configured transport."""
        transport = self.transport
        if transport == DNSTransport.SYSTEM:
            transport = DNSTransport.UDP
        handler = {
            DNSTransport.UDP: self._send_udp,
            DNSTransport.TCP: self._send_tcp,
            DNSTransport.DOH: self._send_doh,
            DNSTransport.DOT: self._send_dot,
        }.get(transport)
        if handler is None:
            raise DNSTransportError(f"unsupported transport {self.transport!r}")
        return handler(message, resolver)

    # --------------------------------------------------------------- transports

    def _send_udp(self, message: Any, resolver: str) -> TransportResult:
        """UDP with optional TCP fallback on truncation."""
        started = time.monotonic()
        try:
            response = dns.query.udp(message, resolver, timeout=self.timeout, port=self.port)
        except dns.exception.Timeout as exc:
            raise DNSTimeout(f"UDP query to {resolver} timed out") from exc
        except OSError as exc:
            raise DNSTransportError(f"UDP query to {resolver} failed: {exc}") from exc
        duration = (time.monotonic() - started) * 1000.0
        result = TransportResult(
            response=response,
            duration_ms=duration,
            transport=DNSTransport.UDP,
            resolver=resolver,
            truncated=bool(response.flags & dns.flags.TC),
        )
        if result.truncated and self.tcp_fallback:
            # Re-issue over TCP so the caller sees the complete answer set.
            tcp_result = self._send_tcp(message, resolver)
            tcp_result.tcp_fallback = True
            tcp_result.duration_ms += duration
            return tcp_result
        return result

    def _send_tcp(self, message: Any, resolver: str) -> TransportResult:
        """TCP query (used directly or as a truncation fallback)."""
        started = time.monotonic()
        try:
            response = dns.query.tcp(message, resolver, timeout=self.timeout, port=self.port)
        except dns.exception.Timeout as exc:
            raise DNSTimeout(f"TCP query to {resolver} timed out") from exc
        except OSError as exc:
            raise DNSTransportError(f"TCP query to {resolver} failed: {exc}") from exc
        return TransportResult(
            response=response,
            duration_ms=(time.monotonic() - started) * 1000.0,
            transport=DNSTransport.TCP,
            resolver=resolver,
            truncated=bool(response.flags & dns.flags.TC),
        )

    def _send_doh(self, message: Any, resolver: str) -> TransportResult:
        """DNS over HTTPS (RFC 8484) using an explicitly configured endpoint."""
        if not self.doh_url:
            raise DNSTransportError("DoH transport requires an explicit doh_url")
        started = time.monotonic()
        try:
            response = dns.query.https(
                message,
                self.doh_url,
                timeout=self.timeout,
                verify=self.verify_tls,
                post=True,
            )
        except dns.exception.Timeout as exc:
            raise DNSTimeout(f"DoH query to {self.doh_url} timed out") from exc
        except Exception as exc:  # noqa: BLE001 - httpx/dns exceptions vary
            raise DNSTransportError(f"DoH query to {self.doh_url} failed: {exc}") from exc
        return TransportResult(
            response=response,
            duration_ms=(time.monotonic() - started) * 1000.0,
            transport=DNSTransport.DOH,
            resolver=self.doh_url,
            truncated=bool(response.flags & dns.flags.TC),
        )

    def _send_dot(self, message: Any, resolver: str) -> TransportResult:
        """DNS over TLS (RFC 7858) to an explicitly configured host."""
        target = self.dot_host or resolver
        if not target:
            raise DNSTransportError("DoT transport requires an explicit dot_host")
        started = time.monotonic()
        try:
            response = dns.query.tls(
                message,
                target,
                timeout=self.timeout,
                port=self.port if self.port != 53 else 853,
                verify=self.verify_tls,
            )
        except dns.exception.Timeout as exc:
            raise DNSTimeout(f"DoT query to {target} timed out") from exc
        except Exception as exc:  # noqa: BLE001 - ssl errors vary by platform
            raise DNSTransportError(f"DoT query to {target} failed: {exc}") from exc
        return TransportResult(
            response=response,
            duration_ms=(time.monotonic() - started) * 1000.0,
            transport=DNSTransport.DOT,
            resolver=target,
            truncated=bool(response.flags & dns.flags.TC),
        )

    # ----------------------------------------------------------------- probing

    def probe(self, resolver: str, *, name: str = ".", rtype: str = "NS") -> TransportResult:
        """Send a minimal query to measure resolver availability/latency."""
        message = dns.message.make_query(name, rtype, want_dnssec=False)
        return self.send(message, resolver)


def transport_label(transport: str) -> str:
    """Display label for a transport."""
    return {
        DNSTransport.UDP: "UDP/53",
        DNSTransport.TCP: "TCP/53",
        DNSTransport.DOH: "DoH",
        DNSTransport.DOT: "DoT",
        DNSTransport.SYSTEM: "system",
    }.get(transport.upper(), transport.upper())


__all__ = [
    "DEFAULT_EDNS_PAYLOAD",
    "DNSTransportError",
    "DNSTransportLayer",
    "TransportResult",
    "transport_label",
]
