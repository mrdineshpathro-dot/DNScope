"""SQLite storage layer.

A single, clean SQLite abstraction (no ORM) keeps the dependency list honest and
the queries readable. The storage interface is deliberately narrow so a future
PostgreSQL backend can be added without touching the analysis engine.

Every write is an upsert that maintains ``first_seen`` / ``last_seen`` so history
queries can reconstruct the past, and every row carries ``workspace`` for logical
multi-tenancy.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dnscope.constants import PRODUCT_VERSION
from dnscope.exceptions import MigrationError, StorageError
from dnscope.models.common import Severity, Significance
from dnscope.storage.schema import SCHEMA_SQL, SCHEMA_VERSION, migration_statements
from dnscope.utils.domains import normalize_hostname, registered_domain
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import now_utc, parse_duration, parse_timestamp, utc_now_iso

_log = get_logger("storage.database")


def _json(value: Any) -> str:
    """Serialize a value for storage."""
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return json.dumps(str(value))


def _loads(value: Any, default: Any = None) -> Any:
    """Deserialize a stored value, tolerating malformed rows."""
    if value in (None, ""):
        return default if default is not None else {}
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default if default is not None else {}


class DNScopeDatabase:
    """SQLite-backed store for all DNScope observations."""

    def __init__(
        self,
        path: str | Path,
        *,
        workspace: str = "default",
        journal_mode: str = "WAL",
        synchronous: str = "NORMAL",
        busy_timeout_ms: int = 5_000,
        readonly: bool = False,
    ) -> None:
        self.path = Path(path).expanduser()
        self.workspace = workspace
        self.journal_mode = journal_mode
        self.synchronous = synchronous
        self.busy_timeout_ms = busy_timeout_ms
        self.readonly = readonly
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None

    # -------------------------------------------------------------- connection

    @property
    def connection(self) -> sqlite3.Connection:
        """Lazily created connection."""
        if self._connection is None:
            self.connect()
        assert self._connection is not None
        return self._connection

    def connect(self) -> DNScopeDatabase:
        """Open (and initialize) the database."""
        with self._lock:
            if self._connection is not None:
                return self
            if not self.readonly:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._connection = sqlite3.connect(
                    str(self.path),
                    timeout=self.busy_timeout_ms / 1000.0,
                    check_same_thread=False,
                    isolation_level=None,
                )
            except sqlite3.Error as exc:
                raise StorageError(f"cannot open database {self.path}: {exc}") from exc
            self._connection.row_factory = sqlite3.Row
            self._apply_pragmas()
            if not self.readonly:
                self.initialize()
            return self

    def _apply_pragmas(self) -> None:
        """Apply performance/safety pragmas."""
        assert self._connection is not None
        statements = [
            f"PRAGMA journal_mode={self.journal_mode}",
            f"PRAGMA synchronous={self.synchronous}",
            f"PRAGMA busy_timeout={self.busy_timeout_ms}",
            "PRAGMA foreign_keys=ON",
        ]
        for statement in statements:
            try:
                self._connection.execute(statement)
            except sqlite3.Error as exc:  # pragma: no cover - platform dependent
                _log.debug("pragma failed (%s): %s", statement, exc)

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            if self._connection is not None:
                try:
                    self._connection.close()
                finally:
                    self._connection = None

    def __enter__(self) -> DNScopeDatabase:
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------- maintenance

    def initialize(self) -> None:
        """Create the schema (or migrate) and stamp metadata."""
        with self._lock:
            self.execute_many(SCHEMA_SQL)
            current = self.schema_version()
            if current == 0:
                self.set_meta("schema_version", str(SCHEMA_VERSION))
                self.set_meta("tool_version", PRODUCT_VERSION)
            elif current < SCHEMA_VERSION:
                self.migrate(current)
            self.set_meta("tool_version", PRODUCT_VERSION)
            self.upsert_workspace(self.workspace)

    def schema_version(self) -> int:
        """Stored schema version (0 when unversioned)."""
        row = self.query_one("SELECT value FROM meta WHERE key = 'schema_version'")
        if not row:
            return 0
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return 0

    def migrate(self, current: int) -> int:
        """Apply pending migrations; returns the new version."""
        steps = migration_statements(current)
        if not steps:
            return current
        with self._lock:
            version = current
            for target, sql in steps:
                try:
                    self.execute_many(sql)
                except sqlite3.Error as exc:
                    # Re-running a migration is safe: columns/tables are guarded
                    # with IF NOT EXISTS where possible, so duplicate-object
                    # errors mean the step was already applied.
                    if "duplicate column" in str(exc).lower() or "already exists" in str(exc).lower():
                        _log.info("migration %d already applied: %s", target, exc)
                    else:
                        raise MigrationError(f"migration to v{target} failed: {exc}") from exc
                self.set_meta("schema_version", str(target))
                version = target
            return version

    def vacuum(self) -> None:
        """Compact the database file."""
        with self._lock:
            self.connection.execute("VACUUM")
            self.connection.execute("ANALYZE")

    def integrity_check(self) -> list[str]:
        """Run SQLite's integrity check."""
        rows = self.query("PRAGMA integrity_check")
        return [str(row[0]) for row in rows]

    def stats(self) -> dict[str, Any]:
        """Row counts and file size (for ``dnscope database stats``)."""
        counts: dict[str, int] = {}
        for table in (
            "targets",
            "subdomains",
            "dns_records",
            "ip_addresses",
            "asns",
            "certificates",
            "nameservers",
            "assets",
            "graph_edges",
            "findings",
            "changes",
            "scans",
            "snapshots",
            "baselines",
            "alerts",
            "jobs",
            "schedules",
            "monitors",
            "audit_log",
            "events",
            "state_transitions",
        ):
            row = self.query_one(f"SELECT COUNT(*) AS count FROM {table}")
            counts[table] = int(row["count"]) if row else 0
        size = self.path.stat().st_size if self.path.exists() else 0
        return {
            "path": str(self.path),
            "exists": self.path.exists(),
            "size_bytes": size,
            "schema_version": self.schema_version(),
            "target_schema_version": SCHEMA_VERSION,
            "workspace": self.workspace,
            "counts": counts,
            "total_rows": sum(counts.values()),
        }

    # ------------------------------------------------------------------ low level

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        """Execute one statement."""
        with self._lock:
            try:
                return self.connection.execute(sql, tuple(params))
            except sqlite3.Error as exc:
                raise StorageError(f"query failed: {exc}", details={"sql": sql[:200]}) from exc

    def execute_many(self, sql: str) -> None:
        """Execute a multi-statement script."""
        with self._lock:
            try:
                self.connection.executescript(sql)
            except sqlite3.Error as exc:
                raise StorageError(f"script failed: {exc}") from exc

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        """Run a SELECT and return all rows."""
        return list(self.execute(sql, params))

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        """Run a SELECT and return the first row."""
        rows = self.execute(sql, params).fetchall()
        return rows[0] if rows else None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Explicit transaction context manager."""
        with self._lock:
            self.connection.execute("BEGIN")
            try:
                yield
            except BaseException:
                self.connection.execute("ROLLBACK")
                raise
            else:
                self.connection.execute("COMMIT")

    # ------------------------------------------------------------------- meta

    def set_meta(self, key: str, value: str) -> None:
        """Store a metadata value."""
        self.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def get_meta(self, key: str, default: str = "") -> str:
        """Read a metadata value."""
        row = self.query_one("SELECT value FROM meta WHERE key = ?", (key,))
        return str(row["value"]) if row else default

    def upsert_workspace(self, name: str, *, description: str = "") -> None:
        """Ensure a workspace row exists."""
        self.execute(
            "INSERT INTO workspaces (name, description, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET description = excluded.description",
            (name, description, utc_now_iso()),
        )

    # ----------------------------------------------------------------- targets

    def upsert_target(
        self,
        hostname: str,
        *,
        kind: str = "DOMAIN",
        port: int | None = None,
        is_ip: bool = False,
        scope_status: str = "UNKNOWN",
        state: str = "UNKNOWN",
        attributes: dict[str, Any] | None = None,
    ) -> int:
        """Insert or refresh a target."""
        name = normalize_hostname(hostname)
        now = utc_now_iso()
        cursor = self.execute(
            """
            INSERT INTO targets (workspace, hostname, domain, kind, port, is_ip, scope_status,
                                 state, attributes, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, hostname) DO UPDATE SET
                domain = excluded.domain,
                kind = excluded.kind,
                port = COALESCE(excluded.port, targets.port),
                scope_status = excluded.scope_status,
                state = excluded.state,
                attributes = excluded.attributes,
                last_seen = excluded.last_seen
            RETURNING id
            """,
            (
                self.workspace,
                name,
                registered_domain(name),
                kind,
                port,
                int(is_ip),
                scope_status,
                state,
                _json(attributes or {}),
                now,
                now,
            ),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def get_target(self, hostname: str) -> dict[str, Any] | None:
        """Read a target row as a dictionary."""
        row = self.query_one(
            "SELECT * FROM targets WHERE workspace = ? AND hostname = ?",
            (self.workspace, normalize_hostname(hostname)),
        )
        return _row_to_dict(row, json_fields=("attributes",)) if row else None

    def list_targets(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """All known targets, most recently seen first."""
        rows = self.query(
            "SELECT * FROM targets WHERE workspace = ? ORDER BY last_seen DESC LIMIT ?",
            (self.workspace, limit),
        )
        return [_row_to_dict(row, json_fields=("attributes",)) for row in rows]

    # ------------------------------------------------------------- subdomains

    def upsert_subdomain(
        self,
        hostname: str,
        *,
        domain: str = "",
        state: str = "DISCOVERED",
        confidence: str = "LOW",
        confidence_score: float = 0.0,
        sources: Sequence[str] = (),
        ips: Sequence[str] = (),
        cname_target: str = "",
        rcode: str = "",
        ttl: int | None = None,
        dangling: bool = False,
        dangling_provider: str = "",
        scope_status: str = "IN_SCOPE",
    ) -> None:
        """Insert or refresh a subdomain, recording state transitions."""
        name = normalize_hostname(hostname)
        base = domain or registered_domain(name)
        now = utc_now_iso()
        existing = self.query_one(
            "SELECT state FROM subdomains WHERE workspace = ? AND hostname = ?",
            (self.workspace, name),
        )
        previous_state = str(existing["state"]) if existing else ""
        state_changed = now if previous_state != state else (now if not existing else "")
        if existing and previous_state == state:
            row = self.query_one(
                "SELECT state_changed_at FROM subdomains WHERE workspace = ? AND hostname = ?",
                (self.workspace, name),
            )
            state_changed = str(row["state_changed_at"]) if row else now

        self.execute(
            """
            INSERT INTO subdomains (workspace, domain, hostname, state, previous_state, confidence,
                                    confidence_score, sources, ips, cname_target, rcode, ttl,
                                    dangling, dangling_provider, scope_status, state_changed_at,
                                    first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, hostname) DO UPDATE SET
                domain = excluded.domain,
                state = excluded.state,
                previous_state = excluded.previous_state,
                confidence = excluded.confidence,
                confidence_score = excluded.confidence_score,
                sources = excluded.sources,
                ips = excluded.ips,
                cname_target = excluded.cname_target,
                rcode = excluded.rcode,
                ttl = COALESCE(excluded.ttl, subdomains.ttl),
                dangling = excluded.dangling,
                dangling_provider = excluded.dangling_provider,
                scope_status = excluded.scope_status,
                state_changed_at = CASE WHEN excluded.state_changed_at != ''
                                        THEN excluded.state_changed_at
                                        ELSE subdomains.state_changed_at END,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                base,
                name,
                state,
                previous_state,
                confidence,
                float(confidence_score),
                _json(list(sources)),
                _json(list(ips)),
                cname_target,
                rcode,
                ttl,
                int(dangling),
                dangling_provider,
                scope_status,
                state_changed,
                now,
                now,
            ),
        )
        if previous_state and previous_state != state:
            self.record_transition(name, previous_state, state, reason="observation")

    def list_subdomains(
        self,
        domain: str | None = None,
        *,
        state: str | None = None,
        include_out_of_scope: bool = False,
        limit: int = 5_000,
    ) -> list[dict[str, Any]]:
        """List subdomains with optional filters."""
        sql = "SELECT * FROM subdomains WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if domain:
            sql += " AND domain = ?"
            params.append(normalize_hostname(domain))
        if state:
            sql += " AND state = ?"
            params.append(state.upper())
        if not include_out_of_scope:
            sql += " AND scope_status != 'OUT_OF_SCOPE'"
        sql += " ORDER BY hostname LIMIT ?"
        params.append(limit)
        rows = self.query(sql, params)
        return [_row_to_dict(row, json_fields=("sources", "ips")) for row in rows]

    def record_transition(
        self,
        hostname: str,
        from_state: str,
        to_state: str,
        *,
        reason: str = "",
        evidence: str = "",
        observed_at: str | None = None,
    ) -> None:
        """Append a state transition record."""
        self.execute(
            """
            INSERT INTO state_transitions (workspace, hostname, from_state, to_state, reason,
                                           evidence, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.workspace,
                normalize_hostname(hostname),
                from_state,
                to_state,
                reason,
                evidence,
                observed_at or utc_now_iso(),
            ),
        )

    def transitions_for(self, hostname: str, *, limit: int = 200) -> list[dict[str, Any]]:
        """State history for one host."""
        rows = self.query(
            """
            SELECT * FROM state_transitions
            WHERE workspace = ? AND hostname = ?
            ORDER BY observed_at DESC LIMIT ?
            """,
            (self.workspace, normalize_hostname(hostname), limit),
        )
        return [dict(row) for row in rows]

    # ------------------------------------------------------------ dns records

    def upsert_dns_records(
        self,
        hostname: str,
        rtype: str,
        rdata: Iterable[str],
        *,
        ttl: int = 0,
        resolver: str = "",
        source: str = "dns",
    ) -> None:
        """Store DNS answers, refreshing lifetimes for existing rows."""
        name = normalize_hostname(hostname)
        now = utc_now_iso()
        for value in rdata:
            self.execute(
                """
                INSERT INTO dns_records (workspace, hostname, rtype, rdata, ttl, resolver,
                                         source, observed_at, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace, hostname, rtype, rdata) DO UPDATE SET
                    ttl = excluded.ttl,
                    resolver = excluded.resolver,
                    observed_at = excluded.observed_at,
                    last_seen = excluded.last_seen
                """,
                (self.workspace, name, rtype.upper(), str(value), ttl, resolver, source, now, now, now),
            )

    def dns_records_for(
        self, hostname: str, *, rtype: str | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Stored DNS records for a hostname."""
        sql = "SELECT * FROM dns_records WHERE workspace = ? AND hostname = ?"
        params: list[Any] = [self.workspace, normalize_hostname(hostname)]
        if rtype:
            sql += " AND rtype = ?"
            params.append(rtype.upper())
        sql += " ORDER BY rtype, rdata LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self.query(sql, params)]

    def previous_rdata(self, hostname: str, rtype: str) -> list[str]:
        """Rdata values seen most recently before now (for change detection)."""
        rows = self.query(
            """
            SELECT rdata FROM dns_records
            WHERE workspace = ? AND hostname = ? AND rtype = ?
            ORDER BY last_seen DESC LIMIT 200
            """,
            (self.workspace, normalize_hostname(hostname), rtype.upper()),
        )
        return [str(row["rdata"]) for row in rows]

    # -------------------------------------------------------------------- ips

    def upsert_ip(
        self,
        ip: str,
        *,
        version: int = 4,
        ptr: Sequence[str] = (),
        asn: str = "",
        organization: str = "",
        prefix: str = "",
        country: str = "",
        provider: str = "",
        source: str = "",
        hostnames: Sequence[str] = (),
    ) -> None:
        """Store IP intelligence and its host associations."""
        now = utc_now_iso()
        self.execute(
            """
            INSERT INTO ip_addresses (workspace, ip, version, ptr, asn, organization, prefix,
                                      country, provider, source, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, ip) DO UPDATE SET
                ptr = excluded.ptr,
                asn = CASE WHEN excluded.asn != '' THEN excluded.asn ELSE ip_addresses.asn END,
                organization = CASE WHEN excluded.organization != ''
                                    THEN excluded.organization ELSE ip_addresses.organization END,
                prefix = CASE WHEN excluded.prefix != '' THEN excluded.prefix ELSE ip_addresses.prefix END,
                country = CASE WHEN excluded.country != ''
                               THEN excluded.country ELSE ip_addresses.country END,
                provider = CASE WHEN excluded.provider != ''
                                THEN excluded.provider ELSE ip_addresses.provider END,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                str(ip),
                version,
                _json(list(ptr)),
                asn,
                organization,
                prefix,
                country,
                provider,
                source,
                now,
                now,
            ),
        )
        for hostname in hostnames:
            self.link_ip_host(str(ip), hostname)

    def link_ip_host(self, ip: str, hostname: str) -> None:
        """Record an IP -> hostname relationship with a lifetime."""
        now = utc_now_iso()
        self.execute(
            """
            INSERT INTO ip_host_map (workspace, ip, hostname, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(workspace, ip, hostname) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (self.workspace, str(ip), normalize_hostname(hostname), now, now),
        )

    def hosts_for_ip(self, ip: str, *, limit: int = 500) -> list[str]:
        """Hostnames observed on ``ip``."""
        rows = self.query(
            "SELECT hostname FROM ip_host_map WHERE workspace = ? AND ip = ? ORDER BY hostname LIMIT ?",
            (self.workspace, str(ip), limit),
        )
        return [str(row["hostname"]) for row in rows]

    def list_ips(self, *, limit: int = 1_000) -> list[dict[str, Any]]:
        """Stored IP intelligence."""
        rows = self.query(
            "SELECT * FROM ip_addresses WHERE workspace = ? ORDER BY last_seen DESC LIMIT ?",
            (self.workspace, limit),
        )
        return [_row_to_dict(row, json_fields=("ptr",)) for row in rows]

    def upsert_asn(
        self,
        asn: str,
        *,
        organization: str = "",
        country: str = "",
        prefixes: Sequence[str] = (),
        ip_count: int = 0,
        domain_count: int = 0,
    ) -> None:
        """Store ASN intelligence."""
        now = utc_now_iso()
        self.execute(
            """
            INSERT INTO asns (workspace, asn, organization, country, prefixes, ip_count,
                              domain_count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, asn) DO UPDATE SET
                organization = CASE WHEN excluded.organization != ''
                                    THEN excluded.organization ELSE asns.organization END,
                country = CASE WHEN excluded.country != '' THEN excluded.country ELSE asns.country END,
                prefixes = excluded.prefixes,
                ip_count = excluded.ip_count,
                domain_count = excluded.domain_count,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                str(asn).upper(),
                organization,
                country,
                _json(list(prefixes)),
                ip_count,
                domain_count,
                now,
                now,
            ),
        )

    def list_asns(self, *, limit: int = 500) -> list[dict[str, Any]]:
        """Stored ASN intelligence."""
        rows = self.query(
            "SELECT * FROM asns WHERE workspace = ? ORDER BY ip_count DESC LIMIT ?",
            (self.workspace, limit),
        )
        return [_row_to_dict(row, json_fields=("prefixes",)) for row in rows]

    # ---------------------------------------------------------- certificates

    def upsert_certificate(
        self,
        *,
        fingerprint: str,
        serial_number: str = "",
        subject_cn: str = "",
        sans: Sequence[str] = (),
        issuer_cn: str = "",
        not_before: str = "",
        not_after: str = "",
        signature_algorithm: str = "",
        public_key_algorithm: str = "",
        public_key_bits: int | None = None,
        source: str = "ct",
        source_detail: str = "",
        expired: bool = False,
        hostnames: Sequence[str] = (),
    ) -> None:
        """Store a certificate observation and the names it covers."""
        now = utc_now_iso()
        digest = fingerprint.lower()
        self.execute(
            """
            INSERT INTO certificates (workspace, serial_number, fingerprint, subject_cn, sans,
                                      issuer_cn, not_before, not_after, signature_algorithm,
                                      public_key_algorithm, public_key_bits, source, source_detail,
                                      expired, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, fingerprint) DO UPDATE SET
                sans = excluded.sans,
                issuer_cn = CASE WHEN excluded.issuer_cn != ''
                                 THEN excluded.issuer_cn ELSE certificates.issuer_cn END,
                not_after = excluded.not_after,
                expired = excluded.expired,
                source = excluded.source,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                serial_number,
                digest,
                subject_cn,
                _json(list(sans)),
                issuer_cn,
                str(not_before),
                str(not_after),
                signature_algorithm,
                public_key_algorithm,
                public_key_bits,
                source,
                source_detail,
                int(expired),
                now,
                now,
            ),
        )
        for hostname in hostnames:
            self.execute(
                """
                INSERT INTO certificate_hostnames (workspace, fingerprint, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(workspace, fingerprint, hostname) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (self.workspace, digest, normalize_hostname(hostname), now, now),
            )

    def list_certificates(self, *, limit: int = 500, expired_only: bool = False) -> list[dict[str, Any]]:
        """Stored certificates."""
        sql = "SELECT * FROM certificates WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if expired_only:
            sql += " AND expired = 1"
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        return [_row_to_dict(row, json_fields=("sans",)) for row in self.query(sql, params)]

    def certificates_for_host(self, hostname: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """Certificates covering ``hostname``."""
        rows = self.query(
            """
            SELECT c.* FROM certificates c
            JOIN certificate_hostnames h ON h.fingerprint = c.fingerprint AND h.workspace = c.workspace
            WHERE c.workspace = ? AND h.hostname = ?
            ORDER BY c.last_seen DESC LIMIT ?
            """,
            (self.workspace, normalize_hostname(hostname), limit),
        )
        return [_row_to_dict(row, json_fields=("sans",)) for row in rows]

    def upsert_nameserver(
        self,
        domain: str,
        nameserver: str,
        *,
        provider: str = "",
        asn: str = "",
        organization: str = "",
        response_time_ms: float | None = None,
        available: bool = False,
    ) -> None:
        """Store a nameserver observation."""
        now = utc_now_iso()
        self.execute(
            """
            INSERT INTO nameservers (workspace, domain, nameserver, provider, asn, organization,
                                     response_time_ms, available, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, domain, nameserver) DO UPDATE SET
                provider = excluded.provider,
                asn = excluded.asn,
                organization = excluded.organization,
                response_time_ms = excluded.response_time_ms,
                available = excluded.available,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                normalize_hostname(domain),
                normalize_hostname(nameserver),
                provider,
                asn,
                organization,
                response_time_ms,
                int(available),
                now,
                now,
            ),
        )

    def list_nameservers(self, domain: str | None = None, *, limit: int = 500) -> list[dict[str, Any]]:
        """Stored nameservers."""
        sql = "SELECT * FROM nameservers WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if domain:
            sql += " AND domain = ?"
            params.append(normalize_hostname(domain))
        sql += " ORDER BY domain, nameserver LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self.query(sql, params)]

    # ----------------------------------------------------------------- assets

    def upsert_asset(
        self,
        kind: str,
        value: str,
        *,
        label: str = "",
        confidence: str = "UNKNOWN",
        quality: str = "OBSERVED",
        scope_status: str = "UNKNOWN",
        state: str = "UNKNOWN",
        attributes: dict[str, Any] | None = None,
        sources: Sequence[str] = (),
        tags: Sequence[str] = (),
    ) -> None:
        """Insert or refresh an asset row."""
        now = utc_now_iso()
        self.execute(
            """
            INSERT INTO assets (workspace, kind, value, label, confidence, quality, scope_status,
                                state, attributes, sources, tags, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, kind, value) DO UPDATE SET
                label = CASE WHEN excluded.label != '' THEN excluded.label ELSE assets.label END,
                confidence = excluded.confidence,
                quality = excluded.quality,
                scope_status = excluded.scope_status,
                state = excluded.state,
                attributes = excluded.attributes,
                sources = excluded.sources,
                tags = excluded.tags,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                kind.upper(),
                str(value).lower(),
                label,
                confidence,
                quality,
                scope_status,
                state,
                _json(attributes or {}),
                _json(list(sources)),
                _json(list(tags)),
                now,
                now,
            ),
        )

    def list_assets(self, kind: str | None = None, *, limit: int = 2_000) -> list[dict[str, Any]]:
        """List assets, optionally filtered by kind."""
        sql = "SELECT * FROM assets WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if kind:
            sql += " AND kind = ?"
            params.append(kind.upper())
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        return [
            _row_to_dict(row, json_fields=("attributes", "sources", "tags"))
            for row in self.query(sql, params)
        ]

    def search_assets(self, term: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """Search assets by value/label/attribute (used by ``assets search``)."""
        needle = f"%{term.lower()}%"
        rows = self.query(
            """
            SELECT * FROM assets
            WHERE workspace = ? AND (value LIKE ? OR label LIKE ? OR attributes LIKE ?)
            ORDER BY last_seen DESC LIMIT ?
            """,
            (self.workspace, needle, needle, needle, limit),
        )
        results = [_row_to_dict(row, json_fields=("attributes", "sources", "tags")) for row in rows]

        # Also match subdomains, IPs and ASNs so the search feels complete.
        for table, column in (("subdomains", "hostname"), ("ip_addresses", "ip"), ("asns", "asn")):
            extra = self.query(
                f"SELECT * FROM {table} WHERE workspace = ? AND {column} LIKE ? LIMIT ?",
                (self.workspace, needle, limit),
            )
            for row in extra:
                item = _row_to_dict(row, json_fields=("sources", "ips", "ptr", "prefixes"))
                item["_table"] = table
                results.append(item)
        return results[:limit]

    def asset_summary(self) -> dict[str, int]:
        """Counts for the ``dnscope assets`` command."""
        counts: dict[str, int] = {}
        for kind in (
            "DOMAIN",
            "SUBDOMAIN",
            "IP",
            "ASN",
            "NS",
            "MX",
            "CNAME",
            "CERTIFICATE",
            "CLOUD_PROVIDER",
            "CDN",
            "DNS_PROVIDER",
            "REGISTRAR",
        ):
            row = self.query_one(
                "SELECT COUNT(*) AS count FROM assets WHERE workspace = ? AND kind = ?",
                (self.workspace, kind),
            )
            counts[kind] = int(row["count"]) if row else 0
        subdomains = self.query_one(
            "SELECT COUNT(*) AS count FROM subdomains WHERE workspace = ?", (self.workspace,)
        )
        counts["SUBDOMAIN_ROWS"] = int(subdomains["count"]) if subdomains else 0
        return counts

    # ------------------------------------------------------------ graph edges

    def upsert_graph_edge(
        self,
        source: str,
        relation: str,
        target: str,
        *,
        source_kind: str = "",
        target_kind: str = "",
        attributes: dict[str, Any] | None = None,
        quality: str = "OBSERVED",
    ) -> None:
        """Store a graph relationship with its observation window."""
        now = utc_now_iso()
        self.execute(
            """
            INSERT INTO graph_edges (workspace, source, relation, target, source_kind, target_kind,
                                     attributes, quality, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, source, relation, target) DO UPDATE SET
                source_kind = excluded.source_kind,
                target_kind = excluded.target_kind,
                attributes = excluded.attributes,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                source.lower(),
                relation.upper(),
                target.lower(),
                source_kind,
                target_kind,
                _json(attributes or {}),
                quality,
                now,
                now,
            ),
        )

    def graph_edges(self, *, as_of: datetime | None = None, limit: int = 20_000) -> list[dict[str, Any]]:
        """Stored graph relationships, optionally filtered to a point in time."""
        sql = "SELECT * FROM graph_edges WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if as_of is not None:
            sql += " AND first_seen <= ? AND (last_seen IS NULL OR last_seen >= ?)"
            stamp = as_of.isoformat()
            params.extend([stamp, stamp])
        sql += " LIMIT ?"
        params.append(limit)
        return [_row_to_dict(row, json_fields=("attributes",)) for row in self.query(sql, params)]

    # --------------------------------------------------------------- findings

    def upsert_finding(self, finding: Any) -> None:
        """Store a finding, preserving operator lifecycle state."""
        from dnscope.models.findings import Finding

        if not isinstance(finding, Finding):
            raise StorageError("upsert_finding expects a Finding model")
        now = utc_now_iso()
        fingerprint = finding.fingerprint()
        existing = self.query_one(
            "SELECT status, suppressed_reason, suppressed_by, suppressed_at, resolved_at, first_seen "
            "FROM findings WHERE workspace = ? AND fingerprint = ?",
            (self.workspace, fingerprint),
        )
        status = finding.status
        if existing and existing["status"] in ("ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"):
            # Never silently re-open something an operator triaged.
            status = str(existing["status"])
        self.execute(
            """
            INSERT INTO findings (workspace, finding_id, fingerprint, rule_id, rule_title, rule_source,
                                  title, description, severity, confidence, category, target, location,
                                  evidence, recommendation, reference_urls, status, analysis_type, context,
                                  needs_verification, suppressed_reason, suppressed_by, suppressed_at,
                                  resolved_at, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, fingerprint) DO UPDATE SET
                finding_id = excluded.finding_id,
                title = excluded.title,
                description = excluded.description,
                severity = excluded.severity,
                confidence = excluded.confidence,
                evidence = excluded.evidence,
                recommendation = excluded.recommendation,
                context = excluded.context,
                status = excluded.status,
                needs_verification = excluded.needs_verification,
                last_seen = excluded.last_seen
            """,
            (
                self.workspace,
                finding.finding_id,
                fingerprint,
                finding.rule.rule_id,
                finding.rule.title,
                finding.rule.source,
                finding.title,
                finding.description,
                finding.severity.value,
                finding.confidence.value,
                finding.category,
                finding.target,
                _json(finding.location),
                _json([item.to_dict() for item in finding.evidence]),
                finding.recommendation,
                _json(finding.references),
                status,
                finding.analysis_type,
                _json(finding.context),
                int(finding.needs_verification),
                finding.suppression.reason if finding.suppression else "",
                finding.suppression.user if finding.suppression else "",
                finding.suppression.suppressed_at if finding.suppression else "",
                "",
                now,
                now,
            ),
        )

    def list_findings(
        self,
        *,
        severity: str | None = None,
        target: str | None = None,
        status: str | None = None,
        include_suppressed: bool = False,
        limit: int = 1_000,
    ) -> list[dict[str, Any]]:
        """Stored findings with filters."""
        sql = "SELECT * FROM findings WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if severity:
            sql += " AND severity = ?"
            params.append(Severity.coerce(severity).value)
        if target:
            sql += " AND target = ?"
            params.append(normalize_hostname(target))
        if status:
            sql += " AND status = ?"
            params.append(status.upper())
        if not include_suppressed:
            sql += " AND status != 'SUPPRESSED'"
        sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        sql += "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, last_seen DESC LIMIT ?"
        params.append(limit)
        rows = [
            _row_to_dict(row, json_fields=("location", "evidence", "reference_urls", "context"))
            for row in self.query(sql, params)
        ]
        for row in rows:
            # Present the column under its model name so callers never see the
            # SQL-level rename.
            row["references"] = row.pop("reference_urls", [])
        return rows

    def set_finding_status(
        self,
        identifier: str,
        status: str,
        *,
        reason: str = "",
        user: str = "",
    ) -> bool:
        """Update a finding's lifecycle state (acknowledge/resolve/reopen)."""
        now = utc_now_iso()
        columns = ["status = ?"]
        values: list[Any] = [status.upper()]
        if status.upper() == "SUPPRESSED":
            columns.extend(["suppressed_reason = ?", "suppressed_by = ?", "suppressed_at = ?"])
            values.extend([reason, user, now])
        if status.upper() == "RESOLVED":
            columns.append("resolved_at = ?")
            values.append(now)
        # SET values first, then the WHERE clause bindings, in SQL order.
        values.extend([self.workspace, identifier, identifier, _as_int(identifier)])
        cursor = self.execute(
            f"UPDATE findings SET {', '.join(columns)} "
            "WHERE workspace = ? AND (finding_id = ? OR fingerprint = ? OR id = ?)",
            values,
        )
        changed = cursor.rowcount or 0
        if changed:
            self.audit("finding_status_changed", "finding", identifier, {"status": status, "reason": reason})
        return changed > 0

    def suppress_rule(
        self,
        rule_id: str,
        *,
        target: str = "",
        reason: str = "",
        user: str = "",
        expires_in: str = "",
    ) -> None:
        """Suppress a rule (optionally for one target only)."""
        expires_at = None
        if expires_in:
            expires_at = (now_utc() + timedelta(seconds=parse_duration(expires_in))).isoformat()
        self.execute(
            """
            INSERT INTO rule_suppressions (workspace, rule_id, target, reason, user, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, rule_id, target) DO UPDATE SET
                reason = excluded.reason,
                user = excluded.user,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
            """,
            (self.workspace, rule_id, normalize_hostname(target), reason, user, utc_now_iso(), expires_at),
        )
        self.audit("rule_suppressed", "rule", rule_id, {"target": target, "reason": reason})

    def suppressed_rules(self, target: str = "") -> set[str]:
        """Rule ids suppressed for ``target`` (or globally)."""
        rows = self.query(
            "SELECT rule_id, expires_at FROM rule_suppressions WHERE workspace = ? AND target IN ('', ?)",
            (self.workspace, normalize_hostname(target)),
        )
        active: set[str] = set()
        now = now_utc()
        for row in rows:
            expires = parse_timestamp(row["expires_at"]) if row["expires_at"] else None
            if expires is not None and expires < now:
                continue
            active.add(str(row["rule_id"]))
        return active

    # ---------------------------------------------------- snapshots/baselines

    def record_snapshot(
        self,
        snapshot_id: str,
        target: str,
        payload: dict[str, Any],
        *,
        label: str = "",
    ) -> str:
        """Store an immutable snapshot; returns its hash."""
        from dnscope.utils.hashing import payload_hash

        digest = payload_hash(payload)
        self.execute(
            """
            INSERT INTO snapshots (snapshot_id, workspace, target, label, payload, payload_hash,
                                   immutable, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(workspace, snapshot_id) DO NOTHING
            """,
            (
                snapshot_id,
                self.workspace,
                normalize_hostname(target),
                label,
                _json(payload),
                digest,
                utc_now_iso(),
            ),
        )
        return digest

    def get_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        """Load a snapshot by id."""
        row = self.query_one(
            "SELECT * FROM snapshots WHERE workspace = ? AND snapshot_id = ?",
            (self.workspace, snapshot_id),
        )
        if not row:
            return None
        data = _row_to_dict(row, json_fields=("payload",))
        data["payload"] = _loads(row["payload"], {})
        return data

    def latest_snapshot(self, target: str) -> dict[str, Any] | None:
        """Most recent snapshot for a target."""
        row = self.query_one(
            "SELECT * FROM snapshots WHERE workspace = ? AND target = ? ORDER BY created_at DESC LIMIT 1",
            (self.workspace, normalize_hostname(target)),
        )
        if not row:
            return None
        data = _row_to_dict(row, json_fields=())
        data["payload"] = _loads(row["payload"], {})
        return data

    def list_snapshots(self, target: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
        """Snapshot index (payloads excluded)."""
        sql = (
            "SELECT snapshot_id, workspace, target, label, payload_hash, immutable, created_at "
            "FROM snapshots WHERE workspace = ?"
        )
        params: list[Any] = [self.workspace]
        if target:
            sql += " AND target = ?"
            params.append(normalize_hostname(target))
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self.query(sql, params)]

    def record_baseline(
        self,
        baseline_id: str,
        target: str,
        payload: dict[str, Any],
        *,
        label: str = "default",
    ) -> str:
        """Store a baseline; returns its hash."""
        from dnscope.utils.hashing import payload_hash

        digest = payload_hash(payload)
        self.execute(
            """
            INSERT INTO baselines (baseline_id, workspace, target, label, payload, payload_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, baseline_id) DO UPDATE SET
                payload = excluded.payload,
                payload_hash = excluded.payload_hash,
                created_at = excluded.created_at
            """,
            (
                baseline_id,
                self.workspace,
                normalize_hostname(target),
                label,
                _json(payload),
                digest,
                utc_now_iso(),
            ),
        )
        self.audit("baseline_changed", "baseline", baseline_id, {"target": target, "label": label})
        return digest

    def get_baseline(self, target: str, *, label: str = "default") -> dict[str, Any] | None:
        """Most recent baseline for a target/label."""
        row = self.query_one(
            """
            SELECT * FROM baselines
            WHERE workspace = ? AND target = ? AND label = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (self.workspace, normalize_hostname(target), label),
        )
        if not row:
            return None
        data = _row_to_dict(row, json_fields=())
        data["payload"] = _loads(row["payload"], {})
        return data

    # ---------------------------------------------------------------- changes

    def record_change(self, change: Any) -> None:
        """Store a detected change."""
        self.execute(
            """
            INSERT INTO changes (change_id, workspace, target, change_type, field, previous, current,
                                 significance, reason, first_observation, from_snapshot, to_snapshot,
                                 context, alert_sent, acknowledged, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, change_id) DO UPDATE SET
                current = excluded.current,
                significance = excluded.significance,
                reason = excluded.reason,
                detected_at = excluded.detected_at
            """,
            (
                change.change_id,
                self.workspace,
                change.target,
                change.change_type,
                change.field,
                _json(change.previous),
                _json(change.current),
                change.significance,
                change.reason,
                int(change.first_observation),
                change.from_snapshot,
                change.to_snapshot,
                _json(change.context),
                int(change.alert_sent),
                int(change.acknowledged),
                change.detected_at,
            ),
        )

    def list_changes(
        self,
        target: str | None = None,
        *,
        minimum_significance: str = "TRIVIAL",
        since: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Stored changes, newest first."""
        threshold = Significance.coerce(minimum_significance)
        allowed = [item.value for item in Significance if item.rank >= threshold.rank]
        sql = "SELECT * FROM changes WHERE workspace = ? AND significance IN ({})".format(
            ",".join("?" for _ in allowed)
        )
        params: list[Any] = [self.workspace, *allowed]
        if target:
            sql += " AND target = ?"
            params.append(normalize_hostname(target))
        if since:
            sql += " AND detected_at >= ?"
            params.append(since)
        sql += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        return [
            _row_to_dict(row, json_fields=("previous", "current", "context"))
            for row in self.query(sql, params)
        ]

    def mark_change_alerted(self, change_id: str) -> None:
        """Flag a change as having produced an alert."""
        self.execute(
            "UPDATE changes SET alert_sent = 1 WHERE workspace = ? AND change_id = ?",
            (self.workspace, change_id),
        )

    # ------------------------------------------------------------------ scans

    def record_scan(self, scan: dict[str, Any]) -> None:
        """Store a scan record (reproducibility + results)."""
        self.execute(
            """
            INSERT INTO scans (scan_id, workspace, target, profile, resolver, transport, providers,
                               ruleset_version, configuration_hash, reproducibility, findings_count,
                               changes_count, risk_score, health, scores, duration_ms, privacy_mode,
                               offline_mode, ai_used, errors, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, scan_id) DO UPDATE SET
                findings_count = excluded.findings_count,
                changes_count = excluded.changes_count,
                risk_score = excluded.risk_score,
                health = excluded.health,
                scores = excluded.scores,
                duration_ms = excluded.duration_ms,
                errors = excluded.errors,
                finished_at = excluded.finished_at
            """,
            (
                scan["scan_id"],
                self.workspace,
                scan.get("target", ""),
                scan.get("profile", ""),
                scan.get("resolver", ""),
                scan.get("transport", ""),
                _json(scan.get("providers", [])),
                scan.get("ruleset_version", ""),
                scan.get("configuration_hash", ""),
                _json(scan.get("reproducibility", {})),
                int(scan.get("findings_count", 0)),
                int(scan.get("changes_count", 0)),
                float(scan.get("risk_score", 0.0)),
                _json(scan.get("health", {})),
                _json(scan.get("scores", {})),
                float(scan.get("duration_ms", 0.0)),
                int(bool(scan.get("privacy_mode"))),
                int(bool(scan.get("offline_mode"))),
                int(bool(scan.get("ai_used"))),
                _json(scan.get("errors", [])),
                scan.get("started_at", utc_now_iso()),
                scan.get("finished_at", ""),
            ),
        )

    def list_scans(self, target: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
        """Scan history."""
        sql = "SELECT * FROM scans WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if target:
            sql += " AND target = ?"
            params.append(normalize_hostname(target))
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        return [
            _row_to_dict(row, json_fields=("providers", "reproducibility", "health", "scores", "errors"))
            for row in self.query(sql, params)
        ]

    # ----------------------------------------------------------------- alerts

    def record_alert(self, alert: Any, deliveries: Sequence[dict[str, Any]] = ()) -> None:
        """Store an alert and its delivery outcomes."""
        self.execute(
            """
            INSERT INTO alerts (alert_id, workspace, event_type, target, title, message, severity,
                                significance, fingerprint, context, reference_urls, channels, deliveries,
                                suppressed, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace, alert_id) DO UPDATE SET
                deliveries = excluded.deliveries,
                suppressed = excluded.suppressed
            """,
            (
                alert.alert_id,
                self.workspace,
                alert.event_type,
                alert.target,
                alert.title,
                alert.message,
                alert.severity,
                alert.significance,
                alert.fingerprint,
                _json(alert.context),
                _json(alert.references),
                _json(alert.channels),
                _json(list(deliveries)),
                int(alert.suppressed),
                alert.created_at,
            ),
        )
        if not alert.suppressed:
            self.execute(
                """
                INSERT INTO alert_state (workspace, fingerprint, last_sent_at, send_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(workspace, fingerprint) DO UPDATE SET
                    last_sent_at = excluded.last_sent_at,
                    send_count = alert_state.send_count + 1
                """,
                (self.workspace, alert.fingerprint, alert.created_at),
            )

    def alert_last_sent(self, fingerprint: str) -> str | None:
        """When an alert with this fingerprint was last delivered."""
        row = self.query_one(
            "SELECT last_sent_at FROM alert_state WHERE workspace = ? AND fingerprint = ?",
            (self.workspace, fingerprint),
        )
        return str(row["last_sent_at"]) if row else None

    def list_alerts(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Stored alerts."""
        rows = self.query(
            "SELECT * FROM alerts WHERE workspace = ? ORDER BY created_at DESC LIMIT ?",
            (self.workspace, limit),
        )
        found = [
            _row_to_dict(row, json_fields=("context", "reference_urls", "channels", "deliveries"))
            for row in rows
        ]
        for row in found:
            row["references"] = row.pop("reference_urls", [])
        return found

    # ------------------------------------------------------------------- jobs

    def enqueue_job(
        self,
        job_id: str,
        *,
        kind: str = "scan",
        target: str = "",
        priority: str = "NORMAL",
        profile: str = "",
        payload: dict[str, Any] | None = None,
        timeout_seconds: int = 900,
    ) -> str:
        """Add a job to the queue."""
        self.execute(
            """
            INSERT INTO jobs (job_id, workspace, kind, target, state, priority, profile, payload,
                              created_at, timeout_seconds)
            VALUES (?, ?, ?, ?, 'QUEUED', ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                self.workspace,
                kind,
                target,
                priority.upper(),
                profile,
                _json(payload or {}),
                utc_now_iso(),
                timeout_seconds,
            ),
        )
        return job_id

    def claim_job(self, worker_id: str, *, lease_seconds: int = 900) -> dict[str, Any] | None:
        """Atomically claim the next queued job (priority first, then FIFO)."""
        with self._lock:
            row = self.query_one(
                """
                SELECT * FROM jobs
                WHERE state = 'QUEUED'
                   OR (state = 'RUNNING' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?)
                ORDER BY CASE priority WHEN 'HIGH' THEN 0 WHEN 'NORMAL' THEN 1 ELSE 2 END,
                         created_at
                LIMIT 1
                """,
                (utc_now_iso(),),
            )
            if not row:
                return None
            lease = (now_utc() + timedelta(seconds=lease_seconds)).isoformat()
            self.execute(
                """
                UPDATE jobs SET state = 'RUNNING', worker_id = ?, started_at = ?,
                                attempts = attempts + 1, lease_expires_at = ?
                WHERE job_id = ?
                """,
                (worker_id, utc_now_iso(), lease, row["job_id"]),
            )
            data = _row_to_dict(row, json_fields=("payload", "result"))
            data["state"] = "RUNNING"
            return data

    def complete_job(self, job_id: str, result: dict[str, Any] | None = None, *, scan_id: str = "") -> None:
        """Mark a job completed."""
        self.execute(
            """
            UPDATE jobs SET state = 'COMPLETED', finished_at = ?, result = ?, progress = 1.0,
                            lease_expires_at = NULL, scan_id = ?
            WHERE job_id = ?
            """,
            (utc_now_iso(), _json(result or {}), scan_id, job_id),
        )

    def fail_job(self, job_id: str, error: str) -> None:
        """Mark a job failed (or requeue when attempts remain)."""
        row = self.query_one("SELECT attempts, max_attempts FROM jobs WHERE job_id = ?", (job_id,))
        attempts = int(row["attempts"]) if row else 1
        maximum = int(row["max_attempts"]) if row else 3
        state = "FAILED" if attempts >= maximum else "QUEUED"
        self.execute(
            """
            UPDATE jobs SET state = ?, error = ?, finished_at = ?, lease_expires_at = NULL
            WHERE job_id = ?
            """,
            (state, error[:1000], utc_now_iso() if state == "FAILED" else None, job_id),
        )

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a queued or running job."""
        cursor = self.execute(
            "UPDATE jobs SET state = 'CANCELLED', finished_at = ? WHERE job_id = ? AND state != 'COMPLETED'",
            (utc_now_iso(), job_id),
        )
        return (cursor.rowcount or 0) > 0

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Read a job."""
        row = self.query_one("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
        return _row_to_dict(row, json_fields=("payload", "result")) if row else None

    def list_jobs(self, *, state: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """List jobs."""
        sql = "SELECT * FROM jobs WHERE 1 = 1"
        params: list[Any] = []
        if state:
            sql += " AND state = ?"
            params.append(state.upper())
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [_row_to_dict(row, json_fields=("payload", "result")) for row in self.query(sql, params)]

    def job_stats(self) -> dict[str, int]:
        """Job counts by state."""
        rows = self.query("SELECT state, COUNT(*) AS count FROM jobs GROUP BY state")
        return {str(row["state"]): int(row["count"]) for row in rows}

    # ------------------------------------------------------- schedules/monitor

    def upsert_monitor(
        self,
        job_id: str,
        target: str,
        *,
        profile: str = "standard",
        interval_seconds: int = 3600,
        enabled: bool = True,
        min_significance: str = "MEDIUM",
        alert_channels: Sequence[str] = (),
        next_run: str | None = None,
    ) -> None:
        """Create or update a monitoring job."""
        self.execute(
            """
            INSERT INTO monitors (job_id, workspace, target, profile, interval_seconds, enabled,
                                  status, min_significance, alert_channels, next_run, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'IDLE', ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                target = excluded.target,
                profile = excluded.profile,
                interval_seconds = excluded.interval_seconds,
                enabled = excluded.enabled,
                min_significance = excluded.min_significance,
                alert_channels = excluded.alert_channels,
                next_run = COALESCE(excluded.next_run, monitors.next_run)
            """,
            (
                job_id,
                self.workspace,
                normalize_hostname(target),
                profile,
                interval_seconds,
                int(enabled),
                min_significance,
                _json(list(alert_channels)),
                next_run,
                utc_now_iso(),
            ),
        )
        self.audit("monitor_created", "monitor", job_id, {"target": target, "interval": interval_seconds})

    def list_monitors(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        """Stored monitors."""
        sql = "SELECT * FROM monitors WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if enabled_only:
            sql += " AND enabled = 1"
        sql += " ORDER BY target"
        return [_row_to_dict(row, json_fields=("alert_channels",)) for row in self.query(sql, params)]

    def update_monitor_run(
        self,
        job_id: str,
        *,
        status: str,
        last_run: str | None = None,
        next_run: str | None = None,
        last_changes: int | None = None,
        error: str = "",
    ) -> None:
        """Record a monitor run outcome."""
        columns = ["status = ?", "run_count = run_count + 1"]
        params: list[Any] = [status]
        if last_run:
            columns.append("last_run = ?")
            params.append(last_run)
        if next_run:
            columns.append("next_run = ?")
            params.append(next_run)
        if last_changes is not None:
            columns.append("last_changes = ?")
            params.append(last_changes)
        if error:
            columns.append("error = ?")
            params.append(error[:500])
        params.append(job_id)
        self.execute(
            f"UPDATE monitors SET {', '.join(columns)} WHERE job_id = ?",
            params,
        )

    def delete_monitor(self, job_id: str) -> bool:
        """Remove a monitor."""
        cursor = self.execute("DELETE FROM monitors WHERE job_id = ?", (job_id,))
        if cursor.rowcount:
            self.audit("monitor_deleted", "monitor", job_id, {})
        return (cursor.rowcount or 0) > 0

    def upsert_schedule(
        self,
        schedule_id: str,
        target: str,
        *,
        kind: str = "monitor",
        interval_seconds: int = 3600,
        profile: str = "",
        report_format: str = "",
        alert_channels: Sequence[str] = (),
        enabled: bool = True,
        payload: dict[str, Any] | None = None,
        next_run: str | None = None,
    ) -> None:
        """Create or update a schedule."""
        self.execute(
            """
            INSERT INTO schedules (schedule_id, workspace, target, kind, interval_seconds, profile,
                                   report_format, alert_channels, enabled, payload, created_at, next_run_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(schedule_id) DO UPDATE SET
                target = excluded.target,
                kind = excluded.kind,
                interval_seconds = excluded.interval_seconds,
                profile = excluded.profile,
                report_format = excluded.report_format,
                alert_channels = excluded.alert_channels,
                enabled = excluded.enabled,
                payload = excluded.payload,
                next_run_at = COALESCE(excluded.next_run_at, schedules.next_run_at)
            """,
            (
                schedule_id,
                self.workspace,
                normalize_hostname(target),
                kind,
                interval_seconds,
                profile,
                report_format,
                _json(list(alert_channels)),
                int(enabled),
                _json(payload or {}),
                utc_now_iso(),
                next_run,
            ),
        )
        self.audit("schedule_created", "schedule", schedule_id, {"target": target, "kind": kind})

    def list_schedules(self, *, due_only: bool = False) -> list[dict[str, Any]]:
        """Stored schedules, optionally only those due to run."""
        sql = "SELECT * FROM schedules WHERE workspace = ? AND enabled = 1"
        params: list[Any] = [self.workspace]
        if due_only:
            sql += " AND (next_run_at IS NULL OR next_run_at <= ?)"
            params.append(utc_now_iso())
        sql += " ORDER BY next_run_at"
        return [
            _row_to_dict(row, json_fields=("alert_channels", "payload")) for row in self.query(sql, params)
        ]

    def update_schedule_run(self, schedule_id: str, *, status: str, next_run: str | None = None) -> None:
        """Record a schedule run."""
        columns = ["last_run_at = ?", "last_status = ?", "run_count = run_count + 1"]
        params: list[Any] = [utc_now_iso(), status]
        if status == "FAILED":
            columns.append("consecutive_failures = consecutive_failures + 1")
        else:
            columns.append("consecutive_failures = 0")
        if next_run:
            columns.append("next_run_at = ?")
            params.append(next_run)
        params.append(schedule_id)
        self.execute(
            f"UPDATE schedules SET {', '.join(columns)} WHERE schedule_id = ?",
            params,
        )

    def delete_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule."""
        cursor = self.execute("DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,))
        if cursor.rowcount:
            self.audit("schedule_deleted", "schedule", schedule_id, {})
        return (cursor.rowcount or 0) > 0

    # ------------------------------------------------------------------ events

    def record_event(
        self,
        target: str,
        event: str,
        *,
        detail: str = "",
        significance: str = "LOW",
        category: str = "",
        source: str = "",
        timestamp: str | None = None,
    ) -> None:
        """Append to the event timeline."""
        self.execute(
            """
            INSERT INTO events (workspace, target, event, detail, significance, category, source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.workspace,
                normalize_hostname(target),
                event,
                detail,
                significance,
                category,
                source,
                timestamp or utc_now_iso(),
            ),
        )

    def timeline(self, target: str | None = None, *, limit: int = 1_000) -> list[dict[str, Any]]:
        """Event timeline rows."""
        sql = "SELECT * FROM events WHERE workspace = ?"
        params: list[Any] = [self.workspace]
        if target:
            sql += " AND target = ?"
            params.append(normalize_hostname(target))
        sql += " ORDER BY timestamp LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self.query(sql, params)]

    # ------------------------------------------------------------------- audit

    def audit(
        self,
        action: str,
        object_type: str = "",
        object_id: str = "",
        detail: dict[str, Any] | None = None,
        *,
        actor: str = "cli",
    ) -> None:
        """Append an audit-log entry (secrets are never passed in)."""
        from dnscope.utils.redact import redact_mapping

        self.execute(
            """
            INSERT INTO audit_log (workspace, actor, action, object_type, object_id, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.workspace,
                actor,
                action,
                object_type,
                object_id,
                _json(redact_mapping(detail or {})),
                utc_now_iso(),
            ),
        )

    def audit_log(self, *, limit: int = 200) -> list[dict[str, Any]]:
        """Recent audit entries."""
        rows = self.query(
            "SELECT * FROM audit_log WHERE workspace = ? ORDER BY created_at DESC LIMIT ?",
            (self.workspace, limit),
        )
        return [_row_to_dict(row, json_fields=("detail",)) for row in rows]

    # ------------------------------------------------------------- checkpoints

    def save_checkpoint(
        self,
        bulk_id: str,
        *,
        source_file: str = "",
        total: int = 0,
        completed: Sequence[str] = (),
        failed: Sequence[str] = (),
        skipped: Sequence[str] = (),
        output: str = "",
    ) -> None:
        """Persist bulk-run progress so ``--resume`` can continue."""
        self.execute(
            """
            INSERT INTO bulk_checkpoints (bulk_id, source_file, total, completed, failed, skipped,
                                          output, started_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bulk_id) DO UPDATE SET
                total = excluded.total,
                completed = excluded.completed,
                failed = excluded.failed,
                skipped = excluded.skipped,
                output = excluded.output,
                updated_at = excluded.updated_at
            """,
            (
                bulk_id,
                source_file,
                total,
                _json(list(completed)),
                _json(list(failed)),
                _json(list(skipped)),
                output,
                utc_now_iso(),
                utc_now_iso(),
            ),
        )

    def load_checkpoint(self, bulk_id: str) -> dict[str, Any] | None:
        """Load a bulk-run checkpoint."""
        row = self.query_one("SELECT * FROM bulk_checkpoints WHERE bulk_id = ?", (bulk_id,))
        if not row:
            return None
        return _row_to_dict(row, json_fields=("completed", "failed", "skipped"))

    # ------------------------------------------------------------------ cleanup

    def cleanup(self, *, older_than: str = "90d", dry_run: bool = True) -> dict[str, int]:
        """Delete observations older than ``older_than``.

        Returns the number of rows that were (or would be) deleted per table.
        """
        seconds = parse_duration(older_than)
        cutoff = (now_utc() - timedelta(seconds=seconds)).isoformat()
        # Each table ages by its own timestamp column; assuming one name across
        # all of them breaks on tables like ``events`` (timestamp) and ``scans``
        # (started_at).
        tables = {
            "dns_records": "last_seen",
            "ip_addresses": "last_seen",
            "certificates": "last_seen",
            "nameservers": "last_seen",
            "assets": "last_seen",
            "graph_edges": "last_seen",
            "changes": "detected_at",
            "scans": "started_at",
            "alerts": "created_at",
            "events": "timestamp",
            "subdomains": "last_seen",
            "state_transitions": "observed_at",
        }
        deleted: dict[str, int] = {}
        with self.transaction() if not dry_run else _noop():
            for table, column in tables.items():
                row = self.query_one(
                    f"SELECT COUNT(*) AS count FROM {table} WHERE workspace = ? AND {column} < ?",
                    (self.workspace, cutoff),
                )
                count = int(row["count"]) if row else 0
                deleted[table] = count
                if not dry_run and count:
                    self.execute(
                        f"DELETE FROM {table} WHERE workspace = ? AND {column} < ?",
                        (self.workspace, cutoff),
                    )
        if not dry_run:
            self.audit(
                "data_cleanup",
                "database",
                self.workspace,
                {"older_than": older_than, "deleted": deleted},
            )
        return deleted


# --------------------------------------------------------------------- helpers


def _row_to_dict(row: sqlite3.Row | None, *, json_fields: Sequence[str] = ()) -> dict[str, Any]:
    """Convert a sqlite row to a dictionary, decoding JSON columns."""
    if row is None:
        return {}
    data = dict(row)
    for field in json_fields:
        if field in data:
            default: Any = (
                [] if field in ("sources", "ips", "sans", "prefixes", "ptr", "references", "tags") else {}
            )
            data[field] = _loads(data[field], default)
    return data


def _as_int(value: str) -> int:
    """Parse an int or return -1 (used for id-or-fingerprint lookups)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


@contextmanager
def _noop() -> Iterator[None]:
    """No-op context manager (used for dry runs)."""
    yield


__all__ = ["DNScopeDatabase"]
