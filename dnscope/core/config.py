"""Layered configuration with validation.

Precedence (highest first)::

    CLI arguments  >  environment variables  >  user config  >  project config  >  defaults

Every setting here corresponds to real behaviour somewhere in DNScope; the
:func:`DNScopeConfig.validate` method is what backs ``dnscope config validate``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from dnscope.constants import (
    ENCRYPTED_DNS_ENDPOINTS,
    MIN_MONITOR_INTERVAL,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    PUBLIC_RESOLVERS,
    SCHEMA_VERSION,
)
from dnscope.exceptions import ConfigurationError
from dnscope.utils.domains import normalize_hostname, valid_hostname
from dnscope.utils.hashing import config_hash
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import parse_duration

_log = get_logger("config")

#: Default locations searched for configuration files.
PROJECT_CONFIG_NAMES = ("dnscope.yaml", "dnscope.yml", ".dnscope.yaml", "config/dnscope.yaml")
USER_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "dnscope"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
DEFAULT_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "dnscope"

#: Environment variable prefix, e.g. ``DNSCOPE_RESOLVER``.
ENV_PREFIX = "DNSCOPE_"


class ResolverConfig(BaseModel):
    """DNS resolver and transport configuration."""

    model_config = ConfigDict(extra="ignore")

    #: Explicit nameservers. Empty means "use the system resolver".
    nameservers: list[str] = Field(default_factory=list)
    port: int = 53
    timeout: float = 5.0
    retries: int = 2
    #: ``udp`` | ``tcp`` | ``doh`` | ``dot`` | ``system``.
    transport: str = "udp"
    #: ``doh`` transport endpoint (only used when transport == doh).
    doh_url: str = ""
    #: ``dot`` transport host (only used when transport == dot).
    dot_host: str = ""
    edns: bool = True
    edns_payload: int = 1232
    #: Ask resolvers to return DNSSEC records / set DO.
    dnssec: bool = False
    #: Compare answers across multiple resolvers (consistency analysis).
    compare_resolvers: bool = False
    #: Public resolver presets used when ``compare_resolvers`` is enabled.
    comparison_resolvers: list[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    rotate: bool = False
    #: Follow CNAME chains up to this depth.
    max_cname_depth: int = 8
    lifetime: float = 10.0

    @field_validator("nameservers", "comparison_resolvers", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("transport", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return str(value).lower() if isinstance(value, str) else value

    @field_validator("edns_payload")
    @classmethod
    def _payload_range(cls, value: int) -> int:
        if not 512 <= value <= 4096:
            raise ValueError("edns_payload must be between 512 and 4096")
        return value

    def resolve_preset(self, name: str) -> str:
        """Map a preset name (``google``) to an address, else pass through."""
        return PUBLIC_RESOLVERS.get(name.lower(), name)

    def effective_nameservers(self) -> list[str]:
        """Nameservers to use, with presets expanded."""
        return [self.resolve_preset(item) for item in self.nameservers]


class LimitsConfig(BaseModel):
    """Hard input and fan-out limits (the safety net for large scans)."""

    model_config = ConfigDict(extra="ignore")

    max_targets: int = 500
    max_subdomains: int = 5_000
    max_subdomains_per_source: int = 2_000
    max_records_per_query: int = 500
    max_graph_nodes: int = 20_000
    max_graph_edges: int = 60_000
    max_response_size: int = 1_048_576  # 1 MiB DNS message / response body
    max_http_body: int = 5_242_880  # 5 MiB provider response
    max_dns_depth: int = 10
    max_spf_depth: int = 5
    max_spf_lookups: int = 10
    max_cname_depth: int = 8
    max_certificate_names: int = 1_000
    max_findings: int = 10_000
    max_report_items: int = 2_000
    max_file_size: int = 20_971_520
    #: Maximum concurrent DNS queries.
    dns_concurrency: int = 20
    #: Maximum concurrent HTTP requests to providers.
    http_concurrency: int = 6
    #: Maximum concurrent targets in bulk mode.
    bulk_concurrency: int = 4
    #: Global request rate (requests/second, 0 = unlimited).
    global_rate_limit: float = 0.0

    @model_validator(mode="after")
    def _check_positive(self) -> "LimitsConfig":
        for name in (
            "max_targets",
            "max_subdomains",
            "max_records_per_query",
            "max_graph_nodes",
            "max_graph_edges",
            "max_dns_depth",
            "max_spf_depth",
            "max_cname_depth",
            "dns_concurrency",
            "http_concurrency",
            "bulk_concurrency",
        ):
            value = getattr(self, name)
            if value < 1:
                raise ValueError(f"{name} must be >= 1")
        return self


class CacheConfig(BaseModel):
    """Local cache configuration."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    path: str = ""
    #: Default freshness window in seconds for cached DNS answers.
    dns_ttl: int = 300
    ct_ttl: int = 86_400
    rdap_ttl: int = 86_400
    ip_ttl: int = 43_200
    provider_ttl: int = 3_600
    max_entries: int = 100_000
    #: ``True`` when ``--no-cache`` was passed (reads and writes both skipped).
    use_cache: bool = True


class DatabaseConfig(BaseModel):
    """SQLite storage configuration."""

    model_config = ConfigDict(extra="ignore")

    path: str = ""
    workspace: str = "default"
    #: Retention window for observations (seconds, 0 = keep forever).
    retention_seconds: int = 0
    journal_mode: str = "WAL"
    synchronous: str = "NORMAL"
    busy_timeout_ms: int = 5_000

    @field_validator("journal_mode", mode="before")
    @classmethod
    def _journal(cls, value: Any) -> Any:
        text = str(value).upper()
        allowed = {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"}
        if text not in allowed:
            raise ValueError(f"journal_mode must be one of {sorted(allowed)}")
        return text


class ScopeConfig(BaseModel):
    """Explicit scope restrictions (section 7)."""

    model_config = ConfigDict(extra="ignore")

    allowed_domains: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)
    #: Allow IP-literal targets (they cannot be scoped by domain).
    allow_ip_targets: bool = True
    #: Include discovered subdomains of allowed domains.
    include_subdomains: bool = True
    #: Refuse to process assets outside scope (vs. tagging them only).
    enforce: bool = True
    #: Extra hosts explicitly in scope (e.g. a separate staging domain).
    extra_hosts: list[str] = Field(default_factory=list)

    @field_validator("allowed_domains", "excluded_domains", "extra_hosts", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("allowed_domains", "excluded_domains", "extra_hosts")
    @classmethod
    def _validate_names(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            text = str(item).strip().lower()
            if not text:
                continue
            if text.startswith("*."):
                text = text[2:]
            if not valid_hostname(text):
                raise ValueError(f"invalid domain in scope configuration: {item!r}")
            cleaned.append(normalize_hostname(text))
        return cleaned


class DiscoveryConfig(BaseModel):
    """Subdomain discovery pipeline configuration."""

    model_config = ConfigDict(extra="ignore")

    #: Passive sources enabled by default (no credentials required).
    sources: list[str] = Field(default_factory=lambda: ["ct", "dns", "rdap"])
    #: Sources that need credentials; enabled automatically when configured.
    credentialed_sources: list[str] = Field(
        default_factory=lambda: ["virustotal", "securitytrails", "otx", "urlscan"]
    )
    #: Active DNS resolution of candidates (still bounded and rate limited).
    validate_dns: bool = True
    #: Brute-force a small built-in wordlist (bounded).
    wordlist_enabled: bool = False
    wordlist_path: str = ""
    wordlist_max: int = 1_000
    #: Generate name permutations (typos/prefixes) - bounded.
    permutations_enabled: bool = False
    permutation_max: int = 200
    #: Drop hosts that resolve to a wildcard A record.
    filter_wildcards: bool = True
    #: Maximum candidates kept after merging all sources.
    max_results: int = 5_000


class ProviderConfig(BaseModel):
    """Per-provider API settings (credentials come from the environment)."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    timeout: float = 15.0
    retries: int = 2
    backoff_factor: float = 1.5
    #: Requests per minute sent to this provider (0 = provider default).
    rate_limit: float = 0.0
    #: Circuit breaker settings.
    circuit_failure_threshold: int = 5
    circuit_cooldown_seconds: float = 300.0
    #: Disable TLS verification - never recommended, exists for lab use.
    verify_tls: bool = True
    #: Providers explicitly disabled by the user.
    disabled: list[str] = Field(default_factory=list)
    #: Providers explicitly enabled (empty = all configured).
    only: list[str] = Field(default_factory=list)
    user_agent: str = ""

    @field_validator("disabled", "only", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


class SecurityConfig(BaseModel):
    """SSRF and hardening settings."""

    model_config = ConfigDict(extra="ignore")

    #: Block private/loopback/link-local addresses in provider + webhook URLs.
    block_private_networks: bool = True
    #: Opt-in override for lab deployments.
    allow_private_networks: bool = False
    allow_redirects: bool = True
    max_redirects: int = 3
    #: Reject non-HTTPS URLs for webhooks (Slack/Discord are always HTTPS).
    require_https_webhooks: bool = True
    allowed_webhook_hosts: list[str] = Field(default_factory=list)
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    #: Reject DNS names that resolve to blocked ranges (rebinding protection).
    resolve_and_validate: bool = True

    @model_validator(mode="after")
    def _coherent(self) -> "SecurityConfig":
        if self.allow_private_networks and self.block_private_networks:
            # ``allow_private_networks`` is the explicit opt-in; it wins, but we
            # log so the operator sees the decision.
            _log.warning("allow_private_networks is enabled - private ranges will be reachable")
        return self


class AlertsConfig(BaseModel):
    """Notification engine configuration."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    channels: list[str] = Field(default_factory=list)
    #: De-duplication cooldown in seconds.
    cooldown: int = 3_600
    timeout: float = 10.0
    retries: int = 2
    #: Event types that trigger notifications.
    events: list[str] = Field(default_factory=lambda: list(_ALERT_DEFAULT_EVENTS))
    #: Minimum significance that triggers an alert.
    min_significance: str = "MEDIUM"
    #: HMAC signing for generic webhooks.
    hmac_algorithm: str = "sha256"
    hmac_header: str = "X-DNScope-Signature"
    #: File channel output path.
    file_path: str = ""
    email_to: list[str] = Field(default_factory=list)
    email_from: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_starttls: bool = True

    @field_validator("channels", "events", "email_to", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


_ALERT_DEFAULT_EVENTS = (
    "DNS_CHANGE",
    "CERTIFICATE_CHANGE",
    "NS_CHANGE",
    "MX_CHANGE",
    "SECURITY_FINDING",
    "TAKEOVER_INDICATOR",
    "POLICY_VIOLATION",
    "PROVIDER_FAILURE",
)


class MonitoringConfig(BaseModel):
    """Continuous monitoring configuration."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    interval: str = "1h"
    min_interval: int = MIN_MONITOR_INTERVAL
    #: Stop after N runs (0 = run until stopped).
    max_runs: int = 0
    jitter_seconds: int = 30
    alert_on: list[str] = Field(default_factory=lambda: list(_ALERT_DEFAULT_EVENTS))

    @field_validator("interval", mode="before")
    @classmethod
    def _validate_interval(cls, value: Any) -> Any:
        return str(value)

    def interval_seconds(self) -> int:
        """Parsed interval, clamped to the safe minimum."""
        seconds = int(parse_duration(self.interval))
        return max(self.min_interval, seconds)


class PolicyConfig(BaseModel):
    """Organizational DNS policy."""

    model_config = ConfigDict(extra="ignore")

    #: Named pack (``enterprise``, ``email``, ``dnssec``, ``baseline``...).
    pack: str = ""
    require_dnssec: bool | None = None
    require_caa: bool | None = None
    require_dmarc: bool | None = None
    require_spf: bool | None = None
    require_mta_sts: bool | None = None
    require_tls_rpt: bool | None = None
    require_https_record: bool | None = None
    minimum_nameservers: int = 2
    maximum_nameservers: int = 13
    allowed_mail_providers: list[str] = Field(default_factory=list)
    allowed_nameserver_providers: list[str] = Field(default_factory=list)
    allowed_cas: list[str] = Field(default_factory=list)
    forbidden_cname_targets: list[str] = Field(default_factory=list)
    max_certificate_age_days: int = 398
    min_dkim_key_bits: int = 1024
    require_dual_stack: bool | None = None
    #: Extra user rules loaded from ``policy_rules`` paths.
    rule_files: list[str] = Field(default_factory=list)
    #: Severity floor that fails ``dnscope ci``.
    fail_on: str = "HIGH"

    @field_validator(
        "allowed_mail_providers",
        "allowed_nameserver_providers",
        "allowed_cas",
        "forbidden_cname_targets",
        "rule_files",
        mode="before",
    )
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    def explicit_checks(self) -> dict[str, bool]:
        """Only the checks the operator actually configured."""
        checks: dict[str, bool] = {}
        for name in (
            "require_dnssec",
            "require_caa",
            "require_dmarc",
            "require_spf",
            "require_mta_sts",
            "require_tls_rpt",
            "require_https_record",
            "require_dual_stack",
        ):
            value = getattr(self, name)
            if value is not None:
                checks[name] = bool(value)
        return checks


class AIConfig(BaseModel):
    """Optional AI interpretation adapter (disabled by default)."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    base_url: str = ""
    model: str = ""
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.2
    max_tokens: int = 1_200
    #: Maximum characters of evidence sent to the model.
    max_input_chars: int = 24_000
    #: Redact secrets/hostnames before sending.
    redact_before_send: bool = True
    timeout: float = 60.0
    #: ``True`` when ``--no-ai`` was passed.
    allow: bool = True


class OutputConfig(BaseModel):
    """Reporting defaults."""

    model_config = ConfigDict(extra="ignore")

    format: str = "terminal"  # terminal | json | csv | markdown | html | sarif
    directory: str = ""
    file: str = ""
    #: Include full evidence blocks in reports.
    include_evidence: bool = True
    #: Minimum severity included in reports.
    min_severity: str = "INFO"
    #: Add the DNScope banner to terminal output.
    banner: bool = True
    color: bool = True
    quiet: bool = False
    verbose: bool = False
    debug: bool = False


class PrivacyConfig(BaseModel):
    """Privacy and offline behaviour."""

    model_config = ConfigDict(extra="ignore")

    #: DNScope never sends telemetry; this flag documents the guarantee.
    telemetry: bool = False
    #: ``--privacy``: disable optional external enrichment.
    privacy_mode: bool = False
    #: ``--offline``: local database/cache + DNS only.
    offline_mode: bool = False
    #: Log every outbound request (used by ``--privacy`` reporting).
    log_external_requests: bool = True
    #: Redact hostnames in debug logs.
    redact_logs: bool = False


class ScanConfig(BaseModel):
    """Scan behaviour defaults (also settable per profile)."""

    model_config = ConfigDict(extra="ignore")

    profile: str = "standard"
    workers: int = 8
    #: Record types queried during a scan.
    record_types: list[str] = Field(
        default_factory=lambda: ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    )
    dnssec: bool = False
    email_security: bool = True
    certificates: bool = True
    rdap: bool = True
    ip_intelligence: bool = True
    cloud_detection: bool = True
    takeover_check: bool = True
    correlation: bool = True
    graph: bool = True
    subdomains: bool = False
    tls_inspection: bool = False
    threat_intelligence: bool = False
    ai_summary: bool = False
    #: Persist observations to the database.
    persist: bool = True
    #: Compare against stored history and emit changes.
    history: bool = True
    #: Run the policy engine during scans.
    policy: bool = False

    @field_validator("record_types", mode="before")
    @classmethod
    def _split(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip().upper() for item in value.split(",") if item.strip()]
        return value


class DNScopeConfig(BaseModel):
    """Root configuration object."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str = SCHEMA_VERSION
    tool_version: str = PRODUCT_VERSION
    #: Logical namespace for stored data (multi-tenant ready).
    workspace: str = "default"
    data_dir: str = ""
    resolver: ResolverConfig = Field(default_factory=ResolverConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    providers: ProviderConfig = Field(default_factory=ProviderConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    dkim: dict[str, Any] = Field(default_factory=lambda: {"selectors": ["google", "selector1", "selector2"]})
    #: Files this configuration was loaded from (for ``config validate``).
    loaded_from: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------- validation

    def validate(self) -> list[str]:
        """Return human-readable configuration problems (empty == valid)."""
        problems: list[str] = []

        # resolvers
        from dnscope.utils.domains import is_ip_literal

        for name in self.resolver.effective_nameservers():
            if not is_ip_literal(name) and not valid_hostname(name):
                problems.append(f"resolver: invalid nameserver {name!r}")
        if self.resolver.transport not in ("udp", "tcp", "doh", "dot", "system"):
            problems.append(f"resolver: unsupported transport {self.resolver.transport!r}")
        if self.resolver.transport == "doh" and not self.resolver.doh_url:
            problems.append("resolver: transport 'doh' requires doh_url")
        if self.resolver.transport == "dot" and not self.resolver.dot_host:
            problems.append("resolver: transport 'dot' requires dot_host")
        if self.resolver.doh_url and not self.resolver.doh_url.startswith(("https://", "http://")):
            problems.append("resolver: doh_url must be an http(s) URL")
        if self.resolver.timeout <= 0:
            problems.append("resolver: timeout must be > 0")
        if not 53 <= self.resolver.port <= 65535:
            problems.append("resolver: port out of range")

        # database / cache paths
        for label, path in (("database.path", self.database.path), ("cache.path", self.cache.path)):
            if not path:
                continue
            try:
                expanded = Path(path).expanduser()
                if expanded.exists() and not expanded.is_file():
                    problems.append(f"{label}: exists but is not a file")
                else:
                    expanded.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                problems.append(f"{label}: not usable ({exc})")

        # rate limits
        if self.limits.global_rate_limit < 0:
            problems.append("limits: global_rate_limit cannot be negative")
        if self.providers.rate_limit < 0:
            problems.append("providers: rate_limit cannot be negative")
        if self.providers.timeout <= 0:
            problems.append("providers: timeout must be > 0")

        # scope
        overlap = set(self.scope.allowed_domains) & set(self.scope.excluded_domains)
        if overlap:
            problems.append(f"scope: domain is both allowed and excluded: {sorted(overlap)}")

        # alerts
        from dnscope.models.alerts import AlertChannel, AlertEventType

        for channel in self.alerts.channels:
            if channel not in AlertChannel.ALL:
                problems.append(f"alerts: unknown channel {channel!r}")
        for event in self.alerts.events:
            if event.upper() not in AlertEventType.ALL:
                problems.append(f"alerts: unknown event {event!r}")
        if self.alerts.cooldown < 0:
            problems.append("alerts: cooldown cannot be negative")

        # monitoring
        try:
            seconds = self.monitoring.interval_seconds()
            if seconds < self.monitoring.min_interval:
                problems.append(
                    f"monitoring: interval {seconds}s is below the safe minimum "
                    f"{self.monitoring.min_interval}s"
                )
        except Exception as exc:  # noqa: BLE001 - report as a config problem
            problems.append(f"monitoring: invalid interval ({exc})")

        # policy
        if self.policy.minimum_nameservers > self.policy.maximum_nameservers:
            problems.append("policy: minimum_nameservers exceeds maximum_nameservers")
        if self.policy.fail_on.upper() not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            problems.append(f"policy: invalid fail_on {self.policy.fail_on!r}")

        # ai
        if self.ai.enabled and not self.ai.base_url:
            problems.append("ai: enabled but base_url is not configured")
        if self.ai.enabled and not self.ai.model:
            problems.append("ai: enabled but model is not configured")

        # output
        allowed_formats = ("terminal", "json", "csv", "markdown", "md", "html", "sarif", "ndjson", "table")
        if self.output.format.lower() not in allowed_formats:
            problems.append(f"output: unsupported format {self.output.format!r}")

        # providers
        from dnscope.providers.registry import ProviderRegistry

        registry = ProviderRegistry()
        known = {info.name.lower() for info in registry.all()}
        for name in [*self.providers.disabled, *self.providers.only]:
            if name.lower() not in known:
                problems.append(f"providers: unknown provider {name!r}")

        return problems

    def assert_valid(self) -> None:
        """Raise :class:`ConfigurationError` when the configuration is invalid."""
        problems = self.validate()
        if problems:
            raise ConfigurationError(
                "invalid configuration: " + "; ".join(problems[:5]),
                details={"problems": problems},
            )

    # ---------------------------------------------------------------- helpers

    def hash(self) -> str:
        """Redacted hash of the effective configuration (reproducibility)."""
        return config_hash(self)

    def resolved_data_dir(self) -> Path:
        """Directory used for database, cache and reports."""
        candidate = Path(self.data_dir).expanduser() if self.data_dir else DEFAULT_DATA_DIR
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    def database_path(self) -> Path:
        """Absolute path to the SQLite database."""
        if self.database.path:
            return Path(self.database.path).expanduser()
        return self.resolved_data_dir() / "dnscope.db"

    def cache_path(self) -> Path:
        """Absolute path to the cache database."""
        if self.cache.path:
            return Path(self.cache.path).expanduser()
        return self.resolved_data_dir() / "cache.db"

    def dkim_selectors(self) -> list[str]:
        """Selectors to test for DKIM (explicit configuration only)."""
        selectors = self.dkim.get("selectors", [])
        if isinstance(selectors, str):
            selectors = [item.strip() for item in selectors.split(",")]
        return [str(item).strip().lower() for item in selectors if str(item).strip()]

    def clone(self, **overrides: Any) -> "DNScopeConfig":
        """Return a copy with nested overrides applied."""
        data = self.model_dump()
        _deep_update(data, overrides)
        return DNScopeConfig.model_validate(data)

    def effective_profile_settings(self) -> dict[str, Any]:
        """Profile preset merged into the scan settings."""
        return apply_profile(self.scan.profile, base=self.model_dump())

    def redacted_dict(self) -> dict[str, Any]:
        """Configuration dictionary safe to print or persist."""
        from dnscope.utils.redact import redact_mapping

        return redact_mapping(self.model_dump())


def _deep_update(target: dict[str, Any], updates: dict[str, Any]) -> None:
    """Recursively merge ``updates`` into ``target``."""
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value


# ------------------------------------------------------------------- profiles

#: Built-in scan profiles. Each entry only overrides what differs.
PROFILES: dict[str, dict[str, Any]] = {
    "passive": {
        "scan": {
            "subdomains": True,
            "certificates": True,
            "rdap": False,
            "ip_intelligence": False,
            "tls_inspection": False,
            "threat_intelligence": False,
            "takeover_check": True,
        },
        "privacy": {"privacy_mode": True},
        "discovery": {"validate_dns": False},
    },
    "quick": {
        "scan": {
            "record_types": ["A", "AAAA", "NS", "MX", "SOA"],
            "certificates": False,
            "rdap": False,
            "ip_intelligence": False,
            "subdomains": False,
        },
    },
    "standard": {},
    "deep": {
        "scan": {
            "record_types": [
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "NS",
                "TXT",
                "SOA",
                "CAA",
                "SRV",
                "NAPTR",
                "TLSA",
                "SSHFP",
                "SVCB",
                "HTTPS",
            ],
            "dnssec": True,
            "certificates": True,
            "rdap": True,
            "ip_intelligence": True,
            "subdomains": True,
            "takeover_check": True,
            "correlation": True,
        },
        "resolver": {"compare_resolvers": True},
        "discovery": {"sources": ["ct", "dns", "rdap", "otx", "urlscan"]},
    },
    "bugbounty": {
        "scan": {
            "record_types": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"],
            "subdomains": True,
            "certificates": True,
            "takeover_check": True,
            "ip_intelligence": True,
            "correlation": True,
            "graph": True,
        },
        "discovery": {
            "sources": ["ct", "dns", "rdap", "otx", "urlscan", "virustotal", "securitytrails"],
            "wordlist_enabled": False,
            "permutations_enabled": False,
            "filter_wildcards": True,
        },
        "limits": {"max_subdomains": 20_000},
    },
    "enterprise": {
        "scan": {
            "record_types": [
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "NS",
                "TXT",
                "SOA",
                "CAA",
                "SRV",
                "NAPTR",
                "TLSA",
                "SSHFP",
                "SVCB",
                "HTTPS",
            ],
            "dnssec": True,
            "email_security": True,
            "certificates": True,
            "rdap": True,
            "ip_intelligence": True,
            "subdomains": True,
            "correlation": True,
            "policy": True,
            "history": True,
            "persist": True,
        },
        "resolver": {"compare_resolvers": True},
        "policy": {"pack": "enterprise"},
    },
    "full": {
        "scan": {
            "record_types": list(
                [
                    "A",
                    "AAAA",
                    "CNAME",
                    "MX",
                    "NS",
                    "TXT",
                    "SOA",
                    "CAA",
                    "PTR",
                    "SRV",
                    "NAPTR",
                    "DNAME",
                    "TLSA",
                    "SSHFP",
                    "LOC",
                    "SVCB",
                    "HTTPS",
                ]
            ),
            "dnssec": True,
            "subdomains": True,
            "certificates": True,
            "rdap": True,
            "ip_intelligence": True,
            "tls_inspection": True,
            "threat_intelligence": True,
            "takeover_check": True,
            "correlation": True,
            "policy": True,
            "history": True,
        },
        "discovery": {
            "sources": ["ct", "dns", "rdap", "otx", "urlscan", "virustotal", "securitytrails"],
            "permutations_enabled": True,
        },
        "resolver": {"compare_resolvers": True},
    },
}


def apply_profile(profile: str, *, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the settings dictionary for ``profile`` merged onto ``base``."""
    data = dict(base or DNScopeConfig().model_dump())
    preset = PROFILES.get(profile.lower())
    if preset is None:
        raise ConfigurationError(
            f"unknown profile {profile!r}",
            details={"available": sorted(PROFILES)},
        )
    _deep_update(data, preset)
    data["scan"]["profile"] = profile.lower()
    return data


def profile_names() -> list[str]:
    """Available profile names."""
    return sorted(PROFILES)


# ------------------------------------------------------------------- env vars

#: Mapping of ``DNSCOPE_*`` environment variables to config paths.
ENV_MAP: dict[str, tuple[str, ...]] = {
    "DNSCOPE_WORKSPACE": ("workspace",),
    "DNSCOPE_DATA_DIR": ("data_dir",),
    "DNSCOPE_RESOLVER": ("resolver", "nameservers"),
    "DNSCOPE_RESOLVERS": ("resolver", "nameservers"),
    "DNSCOPE_TIMEOUT": ("resolver", "timeout"),
    "DNSCOPE_RETRIES": ("resolver", "retries"),
    "DNSCOPE_TRANSPORT": ("resolver", "transport"),
    "DNSCOPE_DOH_URL": ("resolver", "doh_url"),
    "DNSCOPE_DOT_HOST": ("resolver", "dot_host"),
    "DNSCOPE_DNSSEC": ("resolver", "dnssec"),
    "DNSCOPE_WORKERS": ("scan", "workers"),
    "DNSCOPE_PROFILE": ("scan", "profile"),
    "DNSCOPE_RATE_LIMIT": ("limits", "global_rate_limit"),
    "DNSCOPE_MAX_SUBDOMAINS": ("limits", "max_subdomains"),
    "DNSCOPE_MAX_TARGETS": ("limits", "max_targets"),
    "DNSCOPE_DNS_CONCURRENCY": ("limits", "dns_concurrency"),
    "DNSCOPE_HTTP_CONCURRENCY": ("limits", "http_concurrency"),
    "DNSCOPE_DATABASE": ("database", "path"),
    "DNSCOPE_CACHE": ("cache", "path"),
    "DNSCOPE_CACHE_DISABLED": ("cache", "enabled"),
    "DNSCOPE_OUTPUT_DIR": ("output", "directory"),
    "DNSCOPE_FORMAT": ("output", "format"),
    "DNSCOPE_SCOPE": ("scope", "allowed_domains"),
    "DNSCOPE_EXCLUDE": ("scope", "excluded_domains"),
    "DNSCOPE_ALERT_CHANNELS": ("alerts", "channels"),
    "DNSCOPE_ALERT_COOLDOWN": ("alerts", "cooldown"),
    "DNSCOPE_ALERTS_ENABLED": ("alerts", "enabled"),
    "DNSCOPE_DISCORD_WEBHOOK_URL": ("alerts", "_discord_webhook"),
    "DNSCOPE_SLACK_WEBHOOK_URL": ("alerts", "_slack_webhook"),
    "DNSCOPE_MONITOR_INTERVAL": ("monitoring", "interval"),
    "DNSCOPE_PRIVACY": ("privacy", "privacy_mode"),
    "DNSCOPE_OFFLINE": ("privacy", "offline_mode"),
    "DNSCOPE_AI_ENABLED": ("ai", "enabled"),
    "AI_BASE_URL": ("ai", "base_url"),
    "AI_MODEL": ("ai", "model"),
    "DNSCOPE_PROVIDER_TIMEOUT": ("providers", "timeout"),
    "DNSCOPE_PROVIDERS_DISABLED": ("providers", "disabled"),
    "DNSCOPE_PROVIDERS_ONLY": ("providers", "only"),
    "DNSCOPE_BLOCK_PRIVATE": ("security", "block_private_networks"),
    "DNSCOPE_POLICY_PACK": ("policy", "pack"),
    "DNSCOPE_FAIL_ON": ("policy", "fail_on"),
    "DNSCOPE_DKIM_SELECTORS": ("dkim", "selectors"),
}

_BOOL_TRUE = {"1", "true", "yes", "on", "y"}


def _coerce_scalar(text: str) -> Any:
    """Best-effort scalar coercion for environment values."""
    lowered = text.strip().lower()
    if lowered in _BOOL_TRUE:
        return True
    if lowered in {"0", "false", "no", "off", "n"}:
        return False
    try:
        if "." in text:
            return float(text)
        return int(text)
    except ValueError:
        if "," in text:
            return [item.strip() for item in text.split(",") if item.strip()]
        return text


def _set_path(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    """Write ``value`` into ``data`` following ``path``."""
    cursor = data
    for key in path[:-1]:
        cursor = cursor.setdefault(key, {})
    cursor[path[-1]] = value


def apply_environment(config: DNScopeConfig, environ: dict[str, str] | None = None) -> DNScopeConfig:
    """Overlay ``DNSCOPE_*`` environment variables onto ``config``."""
    env = dict(os.environ if environ is None else environ)
    data = config.model_dump()
    changed = False
    for variable, path in ENV_MAP.items():
        if variable not in env:
            continue
        raw = env[variable]
        if raw == "":
            continue
        # Alert webhook URLs are secrets; they are consumed by the alert engine
        # directly from the environment and never written into config.
        if path[-1].startswith("_"):
            continue
        _set_path(data, path, _coerce_scalar(raw))
        changed = True
    if not changed:
        return config
    return DNScopeConfig.model_validate(data)


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load a YAML mapping, raising a helpful error on malformed input."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigurationError(f"configuration file {path} must contain a mapping")
    # Allow a top-level ``dnscope:`` wrapper.
    if set(data) == {"dnscope"} and isinstance(data["dnscope"], dict):
        return dict(data["dnscope"])
    return dict(data)


def find_project_config(start: Path | None = None) -> Path | None:
    """Search the current directory (and parents) for a project config."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        for name in PROJECT_CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
        # Stop at the filesystem root or a git repository boundary.
        if (directory / ".git").exists():
            break
    return None


def default_config() -> DNScopeConfig:
    """Configuration containing only built-in defaults."""
    return DNScopeConfig()


def load_config(
    path: str | Path | None = None,
    *,
    profile: str | None = None,
    use_env: bool = True,
    overrides: dict[str, Any] | None = None,
    load_dotenv: bool = True,
) -> DNScopeConfig:
    """Build the effective configuration.

    Args:
        path: explicit configuration file (highest file precedence).
        profile: profile preset to apply on top.
        use_env: apply ``DNSCOPE_*`` environment variables.
        overrides: CLI-supplied overrides (highest precedence).
        load_dotenv: load ``.env`` from the project root when present.
    """
    if load_dotenv:
        _maybe_load_dotenv()

    config = DNScopeConfig()
    loaded_from: list[str] = []

    # 1. project config (lowest file precedence)
    project_config = find_project_config()
    if project_config is not None:
        data = _load_yaml_file(project_config)
        config = DNScopeConfig.model_validate(_merge_model(config, data))
        loaded_from.append(str(project_config))

    # 2. user config
    if USER_CONFIG_PATH.is_file():
        data = _load_yaml_file(USER_CONFIG_PATH)
        config = DNScopeConfig.model_validate(_merge_model(config, data))
        loaded_from.append(str(USER_CONFIG_PATH))

    # 3. explicit --config file
    if path:
        explicit = Path(path).expanduser()
        if not explicit.is_file():
            raise ConfigurationError(f"configuration file not found: {path}")
        data = _load_yaml_file(explicit)
        config = DNScopeConfig.model_validate(_merge_model(config, data))
        loaded_from.append(str(explicit))

    # 4. profile preset
    if profile:
        data = apply_profile(profile, base=config.model_dump())
        config = DNScopeConfig.model_validate(data)

    # 5. environment
    if use_env:
        config = apply_environment(config)

    # 6. CLI overrides
    if overrides:
        merged = config.model_dump()
        _deep_update(merged, overrides)
        config = DNScopeConfig.model_validate(merged)

    config.loaded_from = loaded_from
    config.assert_valid()
    return config


def _merge_model(config: DNScopeConfig, data: dict[str, Any]) -> dict[str, Any]:
    """Merge raw mapping ``data`` onto an existing configuration."""
    merged = config.model_dump()
    cleaned = {k: v for k, v in data.items() if not str(k).startswith("_")}
    _deep_update(merged, cleaned)
    return merged


def _maybe_load_dotenv() -> None:
    """Load ``.env`` from the current or parent directory when present."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - python-dotenv is a hard dependency
        return
    for directory in (Path.cwd(), *Path.cwd().parents):
        candidate = directory / ".env"
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return
        if (directory / ".git").exists():
            break


def write_example_config(path: str | Path) -> Path:
    """Write a fully commented example configuration file."""
    from pathlib import Path as _Path

    target = _Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    template = _Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
    if template.is_file():
        target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    else:  # pragma: no cover - only when running from an sdist without the file
        target.write_text(
            "# DNScope example configuration\n" + yaml.safe_dump(default_config().redacted_dict(), sort_keys=True),
            encoding="utf-8",
        )
    return target


__all__ = [
    "AIConfig",
    "AlertsConfig",
    "CacheConfig",
    "DEFAULT_DATA_DIR",
    "DNScopeConfig",
    "DatabaseConfig",
    "DiscoveryConfig",
    "ENV_PREFIX",
    "LimitsConfig",
    "MonitoringConfig",
    "OutputConfig",
    "POLICY_PACKS_PLACEHOLDER",
    "PROFILES",
    "PrivacyConfig",
    "ProviderConfig",
    "ResolverConfig",
    "ScanConfig",
    "ScopeConfig",
    "SecurityConfig",
    "USER_CONFIG_PATH",
    "apply_environment",
    "apply_profile",
    "default_config",
    "find_project_config",
    "load_config",
    "profile_names",
    "write_example_config",
]

#: Kept for documentation tooling; policy packs live in :mod:`dnscope.policies`.
POLICY_PACKS_PLACEHOLDER = ("enterprise", "email", "dnssec", "baseline", "custom")

ENCRYPTED_ENDPOINTS = ENCRYPTED_DNS_ENDPOINTS
PRODUCT = PRODUCT_NAME
VERSION = PRODUCT_VERSION
