"""HTTP transport shared by all providers and alert channels.

One implementation covers every API-security requirement: timeouts, retries with
backoff, rate limiting, 429/5xx handling, a circuit breaker, response-size
limits, redirect limits and SSRF validation before connect.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from dnscope.constants import USER_AGENT
from dnscope.exceptions import (
    ProviderRateLimited,
    ProviderResponseError,
    ProviderTimeout,
    SecurityPolicyViolation,
)
from dnscope.security.ssrf import SSRFValidator, ValidationResult
from dnscope.security.validators import looks_like_html, safe_json_loads
from dnscope.utils.async_utils import RateLimiter, SyncRateLimiter
from dnscope.utils.logging import get_logger

_log = get_logger("http")

#: Status codes worth retrying.
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class CircuitOpenError(ProviderRateLimited):
    """Raised when a provider's circuit breaker is open."""


@dataclass
class CircuitBreaker:
    """Simple failure-count circuit breaker.

    After ``failure_threshold`` consecutive failures the circuit opens for
    ``cooldown`` seconds, during which calls fail fast instead of hammering a
    broken endpoint.
    """

    failure_threshold: int = 5
    cooldown: float = 300.0
    failures: int = 0
    opened_at: float | None = None
    last_error: str = ""

    @property
    def is_open(self) -> bool:
        """``True`` when calls should be rejected."""
        if self.opened_at is None:
            return False
        if time.monotonic() - self.opened_at >= self.cooldown:
            # Half-open: allow a probe.
            self.opened_at = None
            self.failures = 0
            return False
        return True

    def record_success(self) -> None:
        """Reset the failure counter."""
        self.failures = 0
        self.opened_at = None

    def record_failure(self, error: str = "") -> None:
        """Count a failure and open the circuit when the threshold is hit."""
        self.failures += 1
        self.last_error = error[:200]
        if self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic()
            _log.warning("circuit opened after %d failures: %s", self.failures, self.last_error)

    def seconds_until_close(self) -> float:
        """Remaining cooldown (0 when closed)."""
        if self.opened_at is None:
            return 0.0
        return max(0.0, self.cooldown - (time.monotonic() - self.opened_at))

    def reset(self) -> None:
        """Close the circuit manually."""
        self.failures = 0
        self.opened_at = None
        self.last_error = ""


@dataclass
class HttpResponse:
    """Normalized HTTP response."""

    status_code: int
    text: str = ""
    json: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""
    elapsed_ms: float = 0.0
    attempts: int = 1
    from_cache: bool = False
    #: Set when the provider returned 429 with a usable retry hint.
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class SafeHTTPClient:
    """HTTP client with DNScope's API-security policy applied.

    Example::

        client = SafeHTTPClient(timeout=15.0, rate_limit=4.0)
        response = client.get_json("https://crt.sh/", params={"q": "example.com"})
    """

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        connect_timeout: float = 10.0,
        retries: int = 2,
        backoff_factor: float = 1.5,
        max_body: int = 5 * 1024 * 1024,
        rate_limit: float = 0.0,
        user_agent: str = "",
        verify_tls: bool = True,
        allow_redirects: bool = True,
        max_redirects: int = 3,
        ssrf: SSRFValidator | None = None,
        breaker: CircuitBreaker | None = None,
        circuit_failure_threshold: int = 5,
        circuit_cooldown: float = 300.0,
        jitter: bool = True,
    ) -> None:
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.retries = max(0, retries)
        self.backoff_factor = max(1.0, backoff_factor)
        self.max_body = max(1024, max_body)
        self.rate_limit = rate_limit
        self.user_agent = user_agent or USER_AGENT
        self.verify_tls = verify_tls
        self.allow_redirects = allow_redirects
        self.max_redirects = max(0, max_redirects)
        self.ssrf = ssrf or SSRFValidator()
        self.breaker = breaker or CircuitBreaker(
            failure_threshold=circuit_failure_threshold, cooldown=circuit_cooldown
        )
        self._limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
        self._sync_limiter = SyncRateLimiter(rate_limit) if rate_limit > 0 else None
        self._jitter = jitter
        #: Counters exposed through ``dnscope providers`` and ``dnscope benchmark``.
        self.requests = 0
        self.bytes_received = 0
        self.rate_limited_count = 0
        self.total_latency_ms = 0.0

    # ------------------------------------------------------------------ config

    def with_limits(self, *, max_body: int | None = None, rate_limit: float | None = None) -> "SafeHTTPClient":
        """Return a copy tuned for a specific provider."""
        clone = SafeHTTPClient(
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
            retries=self.retries,
            backoff_factor=self.backoff_factor,
            max_body=max_body or self.max_body,
            rate_limit=self.rate_limit if rate_limit is None else rate_limit,
            user_agent=self.user_agent,
            verify_tls=self.verify_tls,
            allow_redirects=self.allow_redirects,
            max_redirects=self.max_redirects,
            ssrf=self.ssrf,
            breaker=self.breaker,
        )
        return clone

    # ------------------------------------------------------------ URL handling

    def build_url(self, base: str, path: str = "", params: dict[str, Any] | None = None) -> str:
        """Join a base URL, path and query parameters safely."""
        split = urlsplit(base)
        combined_path = split.path.rstrip("/") + (("/" + path.lstrip("/")) if path else "")
        query = split.query
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                encoded = urlencode(filtered, doseq=True)
                query = f"{query}&{encoded}" if query else encoded
        return urlunsplit((split.scheme, split.netloc, combined_path, query, ""))

    def validate(self, url: str) -> ValidationResult:
        """SSRF-validate ``url`` (raises on rejection)."""
        return self.ssrf.validate_or_raise(url)

    # ------------------------------------------------------------------- sync

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Perform a synchronous request with the full security policy."""
        final_url = self.build_url(url, params=params) if params else url
        self.validate(final_url)
        self._ensure_circuit_closed()

        request_headers = {"User-Agent": self.user_agent, "Accept": "application/json, text/plain;q=0.9"}
        if headers:
            request_headers.update(headers)

        last_error = ""
        attempts = 0
        for attempt in range(self.retries + 1):
            attempts = attempt + 1
            if self._sync_limiter is not None:
                self._sync_limiter.wait()
            started = time.monotonic()
            self.requests += 1
            try:
                with httpx.Client(
                    timeout=httpx.Timeout(timeout or self.timeout, connect=self.connect_timeout),
                    verify=self.verify_tls,
                    follow_redirects=self.allow_redirects,
                    max_redirects=self.max_redirects,
                ) as client:
                    response = client.request(
                        method.upper(),
                        final_url,
                        headers=request_headers,
                        json=json_body,
                    )
                    # Re-validate after redirects so a 30x cannot bounce us into
                    # an internal network.
                    if self.allow_redirects and str(response.url) != final_url:
                        self.validate(str(response.url))
                    elapsed = (time.monotonic() - started) * 1000.0
                    self.total_latency_ms += elapsed
                    body = self._read_body(response)
                    self.bytes_received += len(body)
                    result = HttpResponse(
                        status_code=response.status_code,
                        text=body,
                        headers=dict(response.headers),
                        url=str(response.url),
                        elapsed_ms=elapsed,
                        attempts=attempts,
                        retry_after=_retry_after(response.headers),
                    )
                    if response.status_code == 429:
                        self.rate_limited_count += 1
                        self.breaker.record_failure("HTTP 429")
                        if attempt < self.retries:
                            self._sleep_backoff(attempt, result.retry_after)
                            continue
                        raise ProviderRateLimited(
                            f"{method} {final_url} returned 429", details={"retry_after": result.retry_after}
                        )
                    if response.status_code in RETRYABLE_STATUS and attempt < self.retries:
                        last_error = f"HTTP {response.status_code}"
                        self._sleep_backoff(attempt, result.retry_after)
                        continue
                    self.breaker.record_success()
                    return result
            except httpx.TimeoutException as exc:
                last_error = f"timeout: {exc}"
                self.breaker.record_failure(last_error)
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise ProviderTimeout(f"{method} {final_url} timed out") from exc
            except httpx.HTTPError as exc:
                last_error = f"http error: {exc}"
                self.breaker.record_failure(last_error)
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise ProviderResponseError(f"{method} {final_url} failed: {exc}") from exc
        raise ProviderResponseError(f"{method} {final_url} failed: {last_error}")

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        """Synchronous GET."""
        return self.request("GET", url, **kwargs)

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_body: int | None = None,
    ) -> Any:
        """GET a URL and parse the JSON body."""
        response = self.get(url, params=params, headers=headers, timeout=timeout)
        return self._parse_json(response, max_body=max_body or self.max_body)

    def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """POST a JSON payload and parse the JSON response."""
        response = self.request("POST", url, headers=headers, json_body=payload, timeout=timeout)
        return self._parse_json(response)

    # ------------------------------------------------------------------ async

    async def arequest(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Asynchronous counterpart of :meth:`request`."""
        final_url = self.build_url(url, params=params) if params else url
        self.validate(final_url)
        self._ensure_circuit_closed()

        request_headers = {"User-Agent": self.user_agent, "Accept": "application/json, text/plain;q=0.9"}
        if headers:
            request_headers.update(headers)

        last_error = ""
        attempts = 0
        for attempt in range(self.retries + 1):
            attempts = attempt + 1
            if self._limiter is not None:
                await self._limiter.acquire()
            started = time.monotonic()
            self.requests += 1
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout or self.timeout, connect=self.connect_timeout),
                    verify=self.verify_tls,
                    follow_redirects=self.allow_redirects,
                    max_redirects=self.max_redirects,
                ) as client:
                    response = await client.request(
                        method.upper(), final_url, headers=request_headers, json=json_body
                    )
                    if self.allow_redirects and str(response.url) != final_url:
                        self.validate(str(response.url))
                    elapsed = (time.monotonic() - started) * 1000.0
                    self.total_latency_ms += elapsed
                    body = self._read_body(response)
                    self.bytes_received += len(body)
                    result = HttpResponse(
                        status_code=response.status_code,
                        text=body,
                        headers=dict(response.headers),
                        url=str(response.url),
                        elapsed_ms=elapsed,
                        attempts=attempts,
                        retry_after=_retry_after(response.headers),
                    )
                    if response.status_code == 429:
                        self.rate_limited_count += 1
                        self.breaker.record_failure("HTTP 429")
                        if attempt < self.retries:
                            await self._asleep_backoff(attempt, result.retry_after)
                            continue
                        raise ProviderRateLimited(f"{method} {final_url} returned 429")
                    if response.status_code in RETRYABLE_STATUS and attempt < self.retries:
                        last_error = f"HTTP {response.status_code}"
                        await self._asleep_backoff(attempt, result.retry_after)
                        continue
                    self.breaker.record_success()
                    return result
            except httpx.TimeoutException as exc:
                last_error = f"timeout: {exc}"
                self.breaker.record_failure(last_error)
                if attempt < self.retries:
                    await self._asleep_backoff(attempt)
                    continue
                raise ProviderTimeout(f"{method} {final_url} timed out") from exc
            except httpx.HTTPError as exc:
                last_error = f"http error: {exc}"
                self.breaker.record_failure(last_error)
                if attempt < self.retries:
                    await self._asleep_backoff(attempt)
                    continue
                raise ProviderResponseError(f"{method} {final_url} failed: {exc}") from exc
        raise ProviderResponseError(f"{method} {final_url} failed: {last_error}")

    async def aget_json(self, url: str, *, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """Asynchronous GET returning parsed JSON."""
        response = await self.arequest("GET", url, params=params, **kwargs)
        return self._parse_json(response)

    # --------------------------------------------------------------- internals

    def _ensure_circuit_closed(self) -> None:
        """Fail fast when the circuit breaker is open."""
        if self.breaker.is_open:
            raise CircuitOpenError(
                "provider circuit breaker is open",
                details={"retry_in_seconds": round(self.breaker.seconds_until_close(), 1)},
            )

    def _read_body(self, response: httpx.Response) -> str:
        """Read the response body with a hard size cap."""
        declared = response.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_body:
            raise ProviderResponseError(
                f"response declares {declared} bytes, exceeding the {self.max_body} byte limit"
            )
        content = response.content
        if len(content) > self.max_body:
            raise ProviderResponseError(
                f"response body exceeds the {self.max_body} byte limit ({len(content)} bytes)"
            )
        return content.decode(response.encoding or "utf-8", errors="replace")

    def _parse_json(self, response: HttpResponse, *, max_body: int | None = None) -> Any:
        """Parse a JSON body, rejecting HTML error pages with a clear message."""
        if not response.ok:
            raise ProviderResponseError(
                f"HTTP {response.status_code} from {response.url}",
                details={"body": response.text[:200]},
            )
        if looks_like_html(response.text):
            raise ProviderResponseError(
                f"expected JSON but received HTML from {response.url} "
                "(the endpoint may be down or rate limiting)"
            )
        return safe_json_loads(
            response.text, max_bytes=max_body or self.max_body, context=f"response from {response.url}"
        )

    def _sleep_backoff(self, attempt: int, retry_after: float | None = None) -> None:
        """Sleep before a retry, honouring ``Retry-After`` when present."""
        import time as _time

        delay = self._backoff_delay(attempt, retry_after)
        if delay > 0:
            _time.sleep(delay)

    async def _asleep_backoff(self, attempt: int, retry_after: float | None = None) -> None:
        """Async variant of :meth:`_sleep_backoff`."""
        delay = self._backoff_delay(attempt, retry_after)
        if delay > 0:
            await asyncio.sleep(delay)

    def _backoff_delay(self, attempt: int, retry_after: float | None) -> float:
        """Exponential backoff with optional jitter."""
        if retry_after is not None:
            return min(60.0, max(0.0, retry_after))
        delay = self.backoff_factor ** attempt
        if self._jitter:
            delay *= 0.5 + random.random()
        return min(30.0, delay)

    # -------------------------------------------------------------- statistics

    def stats(self) -> dict[str, Any]:
        """Counters for ``dnscope providers`` and ``dnscope benchmark``."""
        return {
            "requests": self.requests,
            "bytes_received": self.bytes_received,
            "rate_limited": self.rate_limited_count,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "average_latency_ms": round(self.total_latency_ms / self.requests, 2) if self.requests else 0.0,
            "circuit_open": self.breaker.is_open,
            "circuit_failures": self.breaker.failures,
            "rate_limit": self.rate_limit,
        }

    def reset_stats(self) -> None:
        """Clear counters (used by ``dnscope benchmark``)."""
        self.requests = 0
        self.bytes_received = 0
        self.rate_limited_count = 0
        self.total_latency_ms = 0.0
        self.breaker.reset()


def _retry_after(headers: dict[str, str] | Any) -> float | None:
    """Extract a ``Retry-After`` hint in seconds."""
    value = None
    try:
        value = headers.get("retry-after")
    except AttributeError:  # pragma: no cover - httpx headers always support get
        return None
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        # HTTP-date form: fall back to a conservative delay.
        return 5.0


def client_from_settings(settings: Any, *, provider: str = "") -> SafeHTTPClient:
    """Build a :class:`SafeHTTPClient` from a :class:`ProviderConfig`."""
    from dnscope.models.providers import ProviderStatus  # noqa: F401 - re-exported for callers

    timeout = float(getattr(settings, "timeout", 15.0))
    return SafeHTTPClient(
        timeout=timeout,
        connect_timeout=10.0,
        retries=int(getattr(settings, "retries", 2)),
        backoff_factor=float(getattr(settings, "backoff_factor", 1.5)),
        rate_limit=float(getattr(settings, "rate_limit", 0.0)),
        verify_tls=bool(getattr(settings, "verify_tls", True)),
        user_agent=getattr(settings, "user_agent", "") or USER_AGENT,
        circuit_failure_threshold=int(getattr(settings, "circuit_failure_threshold", 5)),
        circuit_cooldown=float(getattr(settings, "circuit_cooldown_seconds", 300.0)),
    )


def default_client(registry: Any, *, provider: str = "") -> SafeHTTPClient:
    """Build the shared HTTP client for a provider registry.

    Every HTTP-backed provider needs a client, and building one per call would
    defeat connection pooling and give each provider its own circuit breaker.
    Callers construct one client and hand it to every provider context.
    """
    return client_from_settings(getattr(registry, "settings", None), provider=provider)


__all__ = [
    "CircuitBreaker",
    "default_client",
    "CircuitOpenError",
    "HttpResponse",
    "SafeHTTPClient",
    "SecurityPolicyViolation",
    "client_from_settings",
]
