"""Product identity, branding and shared protocol constants.

Keeping identity in a single module means README, HTML reports, terminal
footers, REST metadata and SARIF output can never drift apart.
"""

from __future__ import annotations

PRODUCT_NAME = "DNScope"
PRODUCT_VERSION = "4.0.0"
SCHEMA_VERSION = "4.0"
PRODUCT_TAGLINE = "DNS Intelligence, Clearly Scoped."
PRODUCT_DESCRIPTION = "Advanced DNS Attack Surface Intelligence Platform"

AUTHOR = "Dinesh Pathro"
GITHUB_USER_URL = "https://github.com/mrdineshpathro-dot"
GITHUB_URL = f"{GITHUB_USER_URL}/DNScope"
YOUTUBE_URL = "https://www.youtube.com/@GithubHacker"
YOUTUBE_HANDLE = "@GithubHacker"
ISSUES_URL = f"{GITHUB_URL}/issues"
LICENSE_NAME = "MIT"

USER_AGENT = f"{PRODUCT_NAME}/{PRODUCT_VERSION} (+{GITHUB_URL})"

#: Every persisted/exported structure carries these so consumers can detect
#: incompatible payloads instead of silently mis-parsing them.
TOOL_METADATA: dict[str, str] = {
    "name": PRODUCT_NAME,
    "version": PRODUCT_VERSION,
    "schema_version": SCHEMA_VERSION,
}

BANNER_LINES = (
    "DNScope",
    "Advanced DNS Attack Surface Intelligence",
)

BANNER = f"""
+==========================================================+
|                         DNScope                          |
|       Advanced DNS Attack Surface Intelligence           |
+==========================================================+

Author : {AUTHOR}
GitHub : {GITHUB_URL}
YouTube: {YOUTUBE_URL}

Authorized Security Research - DNS Intelligence - OSINT
"""

RICH_BANNER = (
    "[bold cyan]+==========================================================+[/bold cyan]\n"
    "[bold cyan]|[/bold cyan]                         [bold white]DNScope[/bold white]"
    "                          [bold cyan]|[/bold cyan]\n"
    "[bold cyan]|[/bold cyan]       [cyan]Advanced DNS Attack Surface Intelligence[/cyan]           "
    "[bold cyan]|[/bold cyan]\n"
    "[bold cyan]+==========================================================+[/bold cyan]\n"
    "\n"
    f"Author : [bold]{AUTHOR}[/bold]\n"
    f"GitHub : [link={GITHUB_URL}]{GITHUB_URL}[/link]\n"
    f"YouTube: [link={YOUTUBE_URL}]{YOUTUBE_URL}[/link]\n"
    "\n"
    "[dim]Authorized Security Research - DNS Intelligence - OSINT[/dim]\n"
)

#: Footer appended to terminal report output.
TERMINAL_FOOTER = (
    f"{PRODUCT_NAME} {PRODUCT_VERSION} by {AUTHOR} - "
    f"{GITHUB_URL} - {YOUTUBE_URL}"
)

HTML_FOOTER = (
    f'<a href="{GITHUB_URL}">{PRODUCT_NAME} {PRODUCT_VERSION}</a> by {AUTHOR} &middot; '
    f'<a href="{GITHUB_USER_URL}">GitHub</a> &middot; '
    f'<a href="{YOUTUBE_URL}">YouTube {YOUTUBE_HANDLE}</a>'
)

REPORT_METADATA = {
    "tool": TOOL_METADATA,
    "product": PRODUCT_NAME,
    "description": PRODUCT_DESCRIPTION,
    "tagline": PRODUCT_TAGLINE,
    "author": AUTHOR,
    "github": GITHUB_URL,
    "youtube": YOUTUBE_URL,
    "license": LICENSE_NAME,
}


class ExitCode:
    """Predictable CLI exit codes (used by CI integrations)."""

    SUCCESS = 0
    #: Findings/policy threshold exceeded.
    THRESHOLD_EXCEEDED = 1
    CONFIGURATION_ERROR = 2
    EXECUTION_ERROR = 3

    @classmethod
    def describe(cls, code: int) -> str:
        return {
            cls.SUCCESS: "success",
            cls.THRESHOLD_EXCEEDED: "findings/policy threshold exceeded",
            cls.CONFIGURATION_ERROR: "configuration error",
            cls.EXECUTION_ERROR: "execution failure",
        }.get(code, f"unknown exit code ({code})")


#: Severity ordering used for ``--fail-on`` thresholds.
SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

#: Canonical DNS record types supported by the DNS engine.
SUPPORTED_RECORD_TYPES = (
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
    "DNSKEY",
    "DS",
    "RRSIG",
    "NSEC",
    "NSEC3",
    "TLSA",
    "SSHFP",
    "LOC",
    "SVCB",
    "HTTPS",
)

#: Record types queried by the default ``scan`` profile.
DEFAULT_SCAN_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

#: Record types queried when DNSSEC analysis is requested.
DNSSEC_TYPES = ("DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3")

#: Public resolvers offered by the configuration schema. Never used unless the
#: user explicitly selects them - DNScope never silently redirects queries
#: through a third party.
PUBLIC_RESOLVERS = {
    "google": "8.8.8.8",
    "google-secondary": "8.8.4.4",
    "cloudflare": "1.0.0.1",
    "cloudflare-secondary": "1.1.1.1",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}

#: Encrypted DNS endpoints. Only used when explicitly configured.
ENCRYPTED_DNS_ENDPOINTS = {
    "cloudflare-doh": "https://cloudflare-dns.com/dns-query",
    "google-doh": "https://dns.google/dns-query",
    "quad9-doh": "https://dns.quad9.net:5053/dns-query",
}

#: Minimum safe monitoring interval in seconds.
MIN_MONITOR_INTERVAL = 300

#: Alert event types.
ALERT_EVENTS = (
    "DNS_CHANGE",
    "CERTIFICATE_CHANGE",
    "NS_CHANGE",
    "MX_CHANGE",
    "SECURITY_FINDING",
    "TAKEOVER_INDICATOR",
    "POLICY_VIOLATION",
    "PROVIDER_FAILURE",
)

#: Alert channels.
ALERT_CHANNELS = (
    "slack",
    "discord",
    "telegram",
    "email",
    "webhook",
    "teams",
    "stdout",
    "file",
)

#: Job states for the SQLite-backed queue.
JOB_STATES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")

#: Job priorities.
JOB_PRIORITIES = ("LOW", "NORMAL", "HIGH")

#: Logical roles reserved for future RBAC enforcement.
ROLES = ("viewer", "analyst", "operator", "administrator")

#: Built-in profiles.
PROFILES = ("passive", "quick", "standard", "deep", "bugbounty", "enterprise", "full")
