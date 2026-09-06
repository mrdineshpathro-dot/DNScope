"""Domain registration intelligence (RDAP).

RDAP (RFC 9082/9083) replaces WHOIS. This module normalizes a registry document
into one model and derives the security-relevant facts an operator actually asks
about: who is the registrar, when does the domain expire, are the registry locks
set, does the registry claim DNSSEC, and are the published nameservers the ones
we actually see in DNS.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import Field

from dnscope.models.common import SchemaVersioned, SourceRecord
from dnscope.providers.base import Provider, ProviderContext
from dnscope.providers.http import default_client
from dnscope.providers.registry import ProviderRegistry
from dnscope.utils.domains import normalize_hostname, registered_domain
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import now_utc, parse_timestamp, utc_now_iso

_log = get_logger("intelligence.registration")

#: Registry status codes that mean "the registry will refuse changes".
LOCK_STATUSES = (
    "clientdeleteprohibited",
    "clienttransferprohibited",
    "clientupdateprohibited",
    "serverdeleteprohibited",
    "servertransferprohibited",
    "serverupdateprohibited",
)

#: Statuses that indicate a dispute or a hold.
HOLD_STATUSES = ("clienthold", "serverhold", "redemptionperiod", "pendingdelete")

#: Expiry warning thresholds in days.
EXPIRY_WARNING_DAYS = 30


class RegistrationData(SchemaVersioned):
    """Normalized registration record for one domain."""

    domain: str
    found: bool = False
    handle: str = ""
    registrar: str = ""
    registrant: str = ""
    #: Registry status codes, lowercased (``client transfer prohibited`` etc.).
    status: list[str] = Field(default_factory=list)
    registration_date: str = ""
    expiration_date: str = ""
    last_changed: str = ""
    #: All dated events from the registry document.
    events: dict[str, str] = Field(default_factory=dict)
    #: Nameservers the *registry* publishes (may differ from live DNS).
    nameservers: list[str] = Field(default_factory=list)
    #: Registry DNSSEC delegation flags, when published.
    secure_dns: dict[str, Any] = Field(default_factory=dict)
    #: Redacted registration fields (GDPR): present but withheld.
    redacted: list[str] = Field(default_factory=list)
    #: Live nameservers observed in DNS, for comparison.
    observed_nameservers: list[str] = Field(default_factory=list)
    source: SourceRecord = Field(default_factory=SourceRecord)
    error: str = ""
    observed_at: str = Field(default_factory=utc_now_iso)

    # ------------------------------------------------------------- derivations

    @property
    def registry_locked(self) -> bool:
        """``True`` when at least one registry lock is set."""
        return any(code in self.status for code in LOCK_STATUSES)

    @property
    def lock_codes(self) -> list[str]:
        """The lock status codes that are set."""
        return [code for code in self.status if code in LOCK_STATUSES]

    @property
    def on_hold(self) -> bool:
        """``True`` when the domain is on hold or in a pending-delete state."""
        return any(code in self.status for code in HOLD_STATUSES)

    @property
    def dnssec_at_registry(self) -> bool:
        """``True`` when the registry reports DNSSEC delegation.

        Only the registry's own ``delegationSigned`` flag is used: DNScope never
        infers DNSSEC from the absence of a statement.
        """
        value = self.secure_dns.get("delegationSigned")
        if value is None:
            return False
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes")
        return bool(value)

    def days_until_expiry(self) -> int | None:
        """Days until the registration expires (negative when expired)."""
        moment = parse_timestamp(self.expiration_date)
        if moment is None:
            return None
        return (moment - now_utc()).days

    def expires_soon(self, days: int = EXPIRY_WARNING_DAYS) -> bool:
        """``True`` when expiry is inside the warning window (or already past)."""
        remaining = self.days_until_expiry()
        return remaining is not None and remaining < days

    def age_days(self) -> int | None:
        """Days since registration (a useful signal for freshly-registered domains)."""
        moment = parse_timestamp(self.registration_date)
        if moment is None:
            return None
        return (now_utc() - moment).days

    def newly_registered(self, days: int = 30) -> bool:
        """``True`` when the registration is younger than ``days``."""
        age = self.age_days()
        return age is not None and age < days

    def nameserver_drift(self) -> dict[str, list[str]]:
        """Compare registry nameservers with what live DNS answers.

        Drift is not automatically a problem - registries can lag - but it is
        exactly the kind of discrepancy an operator should see.
        """
        registry = {name for name in self.nameservers if name}
        observed = {name for name in self.observed_nameservers if name}
        return {
            "registry_only": sorted(registry - observed),
            "dns_only": sorted(observed - registry),
            "matching": sorted(registry & observed),
        }

    def summary(self) -> str:
        """One-line human summary."""
        parts = [self.domain]
        if self.registrar:
            parts.append(f"registrar={self.registrar}")
        remaining = self.days_until_expiry()
        if remaining is not None:
            parts.append(f"expires in {remaining}d")
        parts.append("registry-locked" if self.registry_locked else "no registry locks")
        parts.append("dnssec=yes" if self.dnssec_at_registry else "dnssec=no")
        return " ".join(parts)

    def risks(self) -> list[dict[str, Any]]:
        """Registration-level observations, each with its evidence."""
        issues: list[dict[str, Any]] = []
        if not self.found:
            issues.append(
                {
                    "id": "REG-UNKNOWN",
                    "severity": "INFO",
                    "detail": self.error or "no registration data available",
                    "evidence": f"rdap lookup for {self.domain}",
                }
            )
            return issues
        if not self.registry_locked:
            issues.append(
                {
                    "id": "REG-NO-LOCK",
                    "severity": "MEDIUM",
                    "detail": "no registry lock (clientTransferProhibited or equivalent) is set",
                    "evidence": f"rdap status={','.join(self.status) or 'none published'}",
                }
            )
        if self.on_hold:
            issues.append(
                {
                    "id": "REG-ON-HOLD",
                    "severity": "HIGH",
                    "detail": "the registration carries a hold or pending-delete status",
                    "evidence": f"rdap status={','.join(self.status)}",
                }
            )
        remaining = self.days_until_expiry()
        if remaining is not None and remaining < 0:
            issues.append(
                {
                    "id": "REG-EXPIRED",
                    "severity": "CRITICAL",
                    "detail": f"the domain registration expired {abs(remaining)} day(s) ago",
                    "evidence": f"rdap expiration={self.expiration_date}",
                }
            )
        elif self.expires_soon():
            issues.append(
                {
                    "id": "REG-EXPIRING",
                    "severity": "HIGH",
                    "detail": f"the domain registration expires in {remaining} day(s)",
                    "evidence": f"rdap expiration={self.expiration_date}",
                }
            )
        if self.newly_registered():
            issues.append(
                {
                    "id": "REG-NEW",
                    "severity": "LOW",
                    "detail": f"the domain was registered {self.age_days()} day(s) ago",
                    "evidence": f"rdap registration={self.registration_date}",
                }
            )
        drift = self.nameserver_drift()
        if self.nameservers and self.observed_nameservers and (drift["registry_only"] or drift["dns_only"]):
            issues.append(
                {
                    "id": "REG-NS-DRIFT",
                    "severity": "MEDIUM",
                    "detail": "the nameservers published by the registry differ from live DNS",
                    "evidence": (
                        "registry_only="
                        + (",".join(drift["registry_only"]) or "-")
                        + " dns_only="
                        + (",".join(drift["dns_only"]) or "-")
                    ),
                }
            )
        return issues


class RDAPClient:
    """Fetches registration data through the configured RDAP provider."""

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        *,
        provider_name: str = "rdap",
        http: Any = None,
        allow_external: bool = True,
        offline: bool = False,
    ) -> None:
        self.registry = registry or ProviderRegistry()
        self.provider_name = provider_name
        self.http = http
        self.allow_external = allow_external
        self.offline = offline

    # ------------------------------------------------------------------ public

    def lookup(self, domain: str) -> RegistrationData:
        """Return registration data for ``domain`` (or an honest failure)."""
        name = registered_domain(normalize_hostname(domain)) or normalize_hostname(domain)
        data = RegistrationData(domain=name)
        provider = self._provider()
        if provider is None:
            data.error = f"provider {self.provider_name} is not registered"
            return data
        if self.offline or not self.allow_external:
            data.error = "external lookups are disabled (offline or privacy mode)"
            return data

        context = self._context()
        try:
            result = provider.query(name, context)
        except Exception as exc:
            data.error = f"{type(exc).__name__}: {exc}"
            _log.warning("RDAP lookup for %s failed: %s", name, exc)
            return data

        data.source = SourceRecord(
            provider=result.source.provider or provider.name,
            source=result.source.source or getattr(provider, "base_url", ""),
            observed_at=result.source.observed_at or now_utc(),
            confidence=result.confidence,
            quality=result.quality,
        )
        if not result.ok:
            data.error = result.error or "RDAP request failed"
            return data

        payload = next(
            (item for item in result.generic if str(item.get("kind", "")) == "rdap"),
            None,
        )
        if payload is None:
            data.error = "RDAP response contained no registration document"
            return data
        self._apply(data, payload)
        return data

    def with_live_nameservers(self, data: RegistrationData, nameservers: Iterable[str]) -> RegistrationData:
        """Attach observed nameservers so registry/DNS drift can be computed."""
        data.observed_nameservers = sorted({normalize_hostname(item) for item in nameservers if item})
        return data

    def describe(self) -> dict[str, Any]:
        """Provider readiness (for ``dnscope doctor`` / ``providers``)."""
        provider = self._provider()
        if provider is None:
            return {"available": False, "reason": f"provider {self.provider_name} is not registered"}
        return {
            "available": True,
            "provider": provider.name,
            "configured": provider.is_configured(),
            "offline": self.offline,
            "external_allowed": self.allow_external,
        }

    # --------------------------------------------------------------- internals

    def _provider(self) -> Provider | None:
        """Resolve the RDAP provider from the registry."""
        return self.registry.get(self.provider_name)

    def _context(self) -> ProviderContext:
        """Build the provider context for this lookup."""
        return ProviderContext(
            http=self.http or default_client(self.registry),
            offline=self.offline,
            allow_external=self.allow_external,
        )

    def _apply(self, data: RegistrationData, payload: dict[str, Any]) -> None:
        """Map the normalized RDAP document onto ``data``."""
        data.found = True
        data.handle = str(payload.get("handle", ""))
        data.registrar = str(payload.get("registrar", ""))
        data.status = [str(item).lower().replace(" ", "") for item in payload.get("status", [])]
        data.registration_date = str(payload.get("registration_date", ""))
        data.expiration_date = str(payload.get("expiration_date", ""))
        data.last_changed = str(payload.get("last_changed", ""))
        events = payload.get("events")
        data.events = {str(key): str(value) for key, value in (events or {}).items()}
        data.nameservers = sorted(
            {normalize_hostname(str(item)) for item in payload.get("nameservers", []) if item}
        )
        secure = payload.get("secure_dns")
        if isinstance(secure, dict):
            data.secure_dns = secure
            for key in ("zoneSigned", "delegationSigned"):
                if key in secure and secure[key] in (None, "", False):
                    data.redacted.append(key)


__all__ = ["EXPIRY_WARNING_DAYS", "HOLD_STATUSES", "LOCK_STATUSES", "RDAPClient", "RegistrationData"]
