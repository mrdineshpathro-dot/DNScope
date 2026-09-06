"""Database schema and migrations.

The schema is designed so every observation has a lifetime (``first_seen`` /
``last_seen``) and provenance (``source``). That is what makes historical
queries, change detection and baseline comparison possible without a separate
time-series store.

Every table carries ``workspace`` so a single database can hold several logical
tenants without schema changes.
"""

from __future__ import annotations

#: Current schema version. Bumped by migrations, never edited in place.
SCHEMA_VERSION = 4

#: SQL executed when creating a fresh database.
SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace    TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    domain       TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'DOMAIN',
    port         INTEGER,
    is_ip        INTEGER NOT NULL DEFAULT 0,
    scope_status TEXT NOT NULL DEFAULT 'UNKNOWN',
    state        TEXT NOT NULL DEFAULT 'UNKNOWN',
    attributes   TEXT NOT NULL DEFAULT '{}',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE (workspace, hostname)
);
CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets (workspace, domain);

CREATE TABLE IF NOT EXISTS subdomains (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace      TEXT NOT NULL,
    domain         TEXT NOT NULL,
    hostname       TEXT NOT NULL,
    state          TEXT NOT NULL DEFAULT 'DISCOVERED',
    previous_state TEXT NOT NULL DEFAULT '',
    confidence     TEXT NOT NULL DEFAULT 'LOW',
    confidence_score REAL NOT NULL DEFAULT 0,
    sources        TEXT NOT NULL DEFAULT '[]',
    ips            TEXT NOT NULL DEFAULT '[]',
    cname_target   TEXT NOT NULL DEFAULT '',
    rcode          TEXT NOT NULL DEFAULT '',
    ttl            INTEGER,
    dangling       INTEGER NOT NULL DEFAULT 0,
    dangling_provider TEXT NOT NULL DEFAULT '',
    scope_status   TEXT NOT NULL DEFAULT 'UNKNOWN',
    state_changed_at TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE (workspace, hostname)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains (workspace, domain);
CREATE INDEX IF NOT EXISTS idx_subdomains_state ON subdomains (workspace, state);

CREATE TABLE IF NOT EXISTS state_transitions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    from_state  TEXT NOT NULL,
    to_state    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transitions_host ON state_transitions (workspace, hostname, observed_at);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    rtype       TEXT NOT NULL,
    rdata       TEXT NOT NULL,
    ttl         INTEGER NOT NULL DEFAULT 0,
    resolver    TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'dns',
    observed_at TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (workspace, hostname, rtype, rdata)
);
CREATE INDEX IF NOT EXISTS idx_dns_records_host ON dns_records (workspace, hostname, rtype);

CREATE TABLE IF NOT EXISTS ip_addresses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace    TEXT NOT NULL,
    ip           TEXT NOT NULL,
    version      INTEGER NOT NULL DEFAULT 4,
    ptr          TEXT NOT NULL DEFAULT '[]',
    asn          TEXT NOT NULL DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    provider     TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE (workspace, ip)
);
CREATE INDEX IF NOT EXISTS idx_ip_asn ON ip_addresses (workspace, asn);

CREATE TABLE IF NOT EXISTS ip_host_map (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL,
    ip          TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (workspace, ip, hostname)
);

CREATE TABLE IF NOT EXISTS asns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace    TEXT NOT NULL,
    asn          TEXT NOT NULL,
    organization TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    prefixes     TEXT NOT NULL DEFAULT '[]',
    ip_count     INTEGER NOT NULL DEFAULT 0,
    domain_count INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE (workspace, asn)
);

CREATE TABLE IF NOT EXISTS certificates (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace        TEXT NOT NULL,
    serial_number    TEXT NOT NULL DEFAULT '',
    fingerprint      TEXT NOT NULL,
    subject_cn       TEXT NOT NULL DEFAULT '',
    sans             TEXT NOT NULL DEFAULT '[]',
    issuer_cn        TEXT NOT NULL DEFAULT '',
    not_before       TEXT NOT NULL DEFAULT '',
    not_after        TEXT NOT NULL DEFAULT '',
    signature_algorithm TEXT NOT NULL DEFAULT '',
    public_key_algorithm TEXT NOT NULL DEFAULT '',
    public_key_bits  INTEGER,
    source           TEXT NOT NULL DEFAULT 'ct',
    source_detail    TEXT NOT NULL DEFAULT '',
    expired          INTEGER NOT NULL DEFAULT 0,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    UNIQUE (workspace, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_certificates_cn ON certificates (workspace, subject_cn);

CREATE TABLE IF NOT EXISTS certificate_hostnames (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (workspace, fingerprint, hostname)
);
CREATE INDEX IF NOT EXISTS idx_cert_hostname ON certificate_hostnames (workspace, hostname);

CREATE TABLE IF NOT EXISTS nameservers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace     TEXT NOT NULL,
    domain        TEXT NOT NULL,
    nameserver    TEXT NOT NULL,
    provider      TEXT NOT NULL DEFAULT '',
    asn           TEXT NOT NULL DEFAULT '',
    organization  TEXT NOT NULL DEFAULT '',
    response_time_ms REAL,
    available     INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    UNIQUE (workspace, domain, nameserver)
);

CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    value        TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    confidence   TEXT NOT NULL DEFAULT 'UNKNOWN',
    quality      TEXT NOT NULL DEFAULT 'OBSERVED',
    scope_status TEXT NOT NULL DEFAULT 'UNKNOWN',
    state        TEXT NOT NULL DEFAULT 'UNKNOWN',
    attributes   TEXT NOT NULL DEFAULT '{}',
    sources      TEXT NOT NULL DEFAULT '[]',
    tags         TEXT NOT NULL DEFAULT '[]',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE (workspace, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets (workspace, kind);

CREATE TABLE IF NOT EXISTS graph_edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL,
    source      TEXT NOT NULL,
    relation    TEXT NOT NULL,
    target      TEXT NOT NULL,
    source_kind TEXT NOT NULL DEFAULT '',
    target_kind TEXT NOT NULL DEFAULT '',
    attributes  TEXT NOT NULL DEFAULT '{}',
    quality     TEXT NOT NULL DEFAULT 'OBSERVED',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (workspace, source, relation, target)
);
CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges (workspace, source);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges (workspace, target);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace     TEXT NOT NULL,
    finding_id    TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    rule_title    TEXT NOT NULL DEFAULT '',
    rule_source   TEXT NOT NULL DEFAULT 'builtin',
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    category      TEXT NOT NULL DEFAULT '',
    target        TEXT NOT NULL DEFAULT '',
    location      TEXT NOT NULL DEFAULT '{}',
    evidence      TEXT NOT NULL DEFAULT '[]',
    recommendation TEXT NOT NULL DEFAULT '',
    reference_urls TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'OPEN',
    analysis_type TEXT NOT NULL DEFAULT 'RULE_BASED',
    context       TEXT NOT NULL DEFAULT '{}',
    needs_verification INTEGER NOT NULL DEFAULT 0,
    suppressed_reason TEXT NOT NULL DEFAULT '',
    suppressed_by TEXT NOT NULL DEFAULT '',
    suppressed_at TEXT NOT NULL DEFAULT '',
    resolved_at   TEXT NOT NULL DEFAULT '',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    UNIQUE (workspace, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (workspace, severity);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (workspace, target);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (workspace, status);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL,
    workspace   TEXT NOT NULL,
    target      TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    immutable   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    UNIQUE (workspace, snapshot_id)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_target ON snapshots (workspace, target, created_at);

CREATE TABLE IF NOT EXISTS baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    baseline_id TEXT NOT NULL,
    workspace   TEXT NOT NULL,
    target      TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT 'default',
    payload     TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (workspace, baseline_id)
);
CREATE INDEX IF NOT EXISTS idx_baselines_target ON baselines (workspace, target, label);

CREATE TABLE IF NOT EXISTS changes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id     TEXT NOT NULL,
    workspace     TEXT NOT NULL,
    target        TEXT NOT NULL,
    change_type   TEXT NOT NULL,
    field         TEXT NOT NULL DEFAULT '',
    previous      TEXT NOT NULL DEFAULT '',
    current       TEXT NOT NULL DEFAULT '',
    significance  TEXT NOT NULL DEFAULT 'LOW',
    reason        TEXT NOT NULL DEFAULT '',
    first_observation INTEGER NOT NULL DEFAULT 0,
    from_snapshot TEXT NOT NULL DEFAULT '',
    to_snapshot   TEXT NOT NULL DEFAULT '',
    context       TEXT NOT NULL DEFAULT '{}',
    alert_sent    INTEGER NOT NULL DEFAULT 0,
    acknowledged  INTEGER NOT NULL DEFAULT 0,
    detected_at   TEXT NOT NULL,
    UNIQUE (workspace, change_id)
);
CREATE INDEX IF NOT EXISTS idx_changes_target ON changes (workspace, target, detected_at);
CREATE INDEX IF NOT EXISTS idx_changes_significance ON changes (workspace, significance);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        TEXT NOT NULL,
    workspace      TEXT NOT NULL,
    target         TEXT NOT NULL,
    profile        TEXT NOT NULL DEFAULT '',
    resolver       TEXT NOT NULL DEFAULT '',
    transport      TEXT NOT NULL DEFAULT '',
    providers      TEXT NOT NULL DEFAULT '[]',
    ruleset_version TEXT NOT NULL DEFAULT '',
    configuration_hash TEXT NOT NULL DEFAULT '',
    reproducibility TEXT NOT NULL DEFAULT '{}',
    findings_count INTEGER NOT NULL DEFAULT 0,
    changes_count  INTEGER NOT NULL DEFAULT 0,
    risk_score     REAL NOT NULL DEFAULT 0,
    health         TEXT NOT NULL DEFAULT '{}',
    scores         TEXT NOT NULL DEFAULT '{}',
    duration_ms    REAL NOT NULL DEFAULT 0,
    privacy_mode   INTEGER NOT NULL DEFAULT 0,
    offline_mode   INTEGER NOT NULL DEFAULT 0,
    ai_used        INTEGER NOT NULL DEFAULT 0,
    errors         TEXT NOT NULL DEFAULT '[]',
    started_at     TEXT NOT NULL,
    finished_at    TEXT NOT NULL DEFAULT '',
    UNIQUE (workspace, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (workspace, target, started_at);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    TEXT NOT NULL,
    workspace   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL,
    message     TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'INFO',
    significance TEXT NOT NULL DEFAULT 'LOW',
    fingerprint TEXT NOT NULL,
    context     TEXT NOT NULL DEFAULT '{}',
    reference_urls TEXT NOT NULL DEFAULT '[]',
    channels    TEXT NOT NULL DEFAULT '[]',
    deliveries  TEXT NOT NULL DEFAULT '[]',
    suppressed  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    UNIQUE (workspace, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts (workspace, fingerprint, created_at);

CREATE TABLE IF NOT EXISTS alert_state (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace     TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    last_sent_at  TEXT NOT NULL,
    send_count    INTEGER NOT NULL DEFAULT 1,
    UNIQUE (workspace, fingerprint)
);

CREATE TABLE IF NOT EXISTS jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id       TEXT NOT NULL UNIQUE,
    workspace    TEXT NOT NULL DEFAULT 'default',
    kind         TEXT NOT NULL DEFAULT 'scan',
    target       TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL DEFAULT 'QUEUED',
    priority     TEXT NOT NULL DEFAULT 'NORMAL',
    profile      TEXT NOT NULL DEFAULT '',
    payload      TEXT NOT NULL DEFAULT '{}',
    result       TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    timeout_seconds INTEGER NOT NULL DEFAULT 900,
    error        TEXT NOT NULL DEFAULT '',
    progress     REAL NOT NULL DEFAULT 0,
    worker_id    TEXT NOT NULL DEFAULT '',
    lease_expires_at TEXT,
    scan_id      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs (state, priority, created_at);

CREATE TABLE IF NOT EXISTS schedules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id   TEXT NOT NULL UNIQUE,
    workspace     TEXT NOT NULL DEFAULT 'default',
    target        TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'monitor',
    interval_seconds INTEGER NOT NULL DEFAULT 3600,
    profile       TEXT NOT NULL DEFAULT '',
    report_format TEXT NOT NULL DEFAULT '',
    alert_channels TEXT NOT NULL DEFAULT '[]',
    enabled       INTEGER NOT NULL DEFAULT 1,
    payload       TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    last_run_at   TEXT,
    next_run_at   TEXT,
    last_status   TEXT NOT NULL DEFAULT '',
    run_count     INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules (enabled, next_run_at);

CREATE TABLE IF NOT EXISTS monitors (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT NOT NULL UNIQUE,
    workspace     TEXT NOT NULL DEFAULT 'default',
    target        TEXT NOT NULL,
    profile       TEXT NOT NULL DEFAULT 'standard',
    interval_seconds INTEGER NOT NULL DEFAULT 3600,
    enabled       INTEGER NOT NULL DEFAULT 1,
    last_run      TEXT,
    next_run      TEXT,
    status        TEXT NOT NULL DEFAULT 'IDLE',
    run_count     INTEGER NOT NULL DEFAULT 0,
    last_changes  INTEGER NOT NULL DEFAULT 0,
    min_significance TEXT NOT NULL DEFAULT 'MEDIUM',
    alert_channels TEXT NOT NULL DEFAULT '[]',
    error         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL DEFAULT 'default',
    actor       TEXT NOT NULL DEFAULT 'cli',
    action      TEXT NOT NULL,
    object_type TEXT NOT NULL DEFAULT '',
    object_id   TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (workspace, created_at);

CREATE TABLE IF NOT EXISTS bulk_checkpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bulk_id     TEXT NOT NULL UNIQUE,
    source_file TEXT NOT NULL DEFAULT '',
    total       INTEGER NOT NULL DEFAULT 0,
    completed   TEXT NOT NULL DEFAULT '[]',
    failed      TEXT NOT NULL DEFAULT '[]',
    skipped     TEXT NOT NULL DEFAULT '[]',
    output      TEXT NOT NULL DEFAULT '',
    started_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL DEFAULT 'default',
    target      TEXT NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    significance TEXT NOT NULL DEFAULT 'LOW',
    category    TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_target ON events (workspace, target, timestamp);

CREATE TABLE IF NOT EXISTS plugin_state (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    version     TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 0,
    manifest    TEXT NOT NULL DEFAULT '{}',
    installed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_suppressions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace   TEXT NOT NULL DEFAULT 'default',
    rule_id     TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    user        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    UNIQUE (workspace, rule_id, target)
);
"""

#: Ordered migration steps. Each entry is ``(version, sql)``; a database at
#: version N runs every step with version > N.
MIGRATIONS: list[tuple[int, str]] = [
    (
        2,
        """
        ALTER TABLE findings ADD COLUMN analysis_type TEXT NOT NULL DEFAULT 'RULE_BASED';
        """,
    ),
    (
        3,
        """
        ALTER TABLE subdomains ADD COLUMN confidence_score REAL NOT NULL DEFAULT 0;
        ALTER TABLE subdomains ADD COLUMN dangling_provider TEXT NOT NULL DEFAULT '';
        """,
    ),
    (
        4,
        """
        CREATE TABLE IF NOT EXISTS rule_suppressions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace   TEXT NOT NULL DEFAULT 'default',
            rule_id     TEXT NOT NULL,
            target      TEXT NOT NULL DEFAULT '',
            reason      TEXT NOT NULL DEFAULT '',
            user        TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL,
            expires_at  TEXT,
            UNIQUE (workspace, rule_id, target)
        );
        """,
    ),
]


def migration_statements(current_version: int) -> list[tuple[int, str]]:
    """Migration steps required to move from ``current_version`` to the latest."""
    return [(version, sql) for version, sql in MIGRATIONS if version > current_version]


def schema_tables() -> list[str]:
    """Names of the tables created by :data:`SCHEMA_SQL` (for doctor checks)."""
    import re

    return [
        match.group("name").strip('"')
        for match in re.finditer(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>\w+)",
            SCHEMA_SQL,
            re.IGNORECASE,
        )
    ]


__all__ = ["MIGRATIONS", "SCHEMA_SQL", "SCHEMA_VERSION", "migration_statements", "schema_tables"]
