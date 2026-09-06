"""Secret management.

Supports three sources, tried in order:

1. environment variables (``VIRUSTOTAL_API_KEY`` ...)
2. the OS credential store when a backend is installed (``keyring``)
3. an encrypted local file (Fernet, key from ``DNSCOPE_MASTER_KEY`` or a key file)

Credentials are never written to logs, reports, the database or exported JSON;
:func:`mask_secret` is the only supported way to display one.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from dnscope.exceptions import ConfigurationError, SecurityPolicyViolation
from dnscope.utils.logging import get_logger
from dnscope.utils.redact import mask_secret

_log = get_logger("secrets")

#: Default location of the encrypted secret store.
DEFAULT_SECRET_FILE = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "dnscope" / "secrets.enc"
#: Environment variable holding the master key (or the path to a key file).
MASTER_KEY_ENV = "DNSCOPE_MASTER_KEY"
#: Optional keyring service name.
KEYRING_SERVICE = "dnscope"

#: Credentials DNScope knows how to look up, with the providers that use them.
KNOWN_SECRETS: dict[str, tuple[str, ...]] = {
    "VIRUSTOTAL_API_KEY": ("virustotal",),
    "SECURITYTRAILS_API_KEY": ("securitytrails",),
    "SHODAN_API_KEY": ("shodan",),
    "CENSYS_API_ID": ("censys",),
    "CENSYS_API_SECRET": ("censys",),
    "URLSCAN_API_KEY": ("urlscan",),
    "ABUSEIPDB_API_KEY": ("abuseipdb",),
    "GREYNOISE_API_KEY": ("greynoise",),
    "OTX_API_KEY": ("otx",),
    "OPENAI_API_KEY": ("ai",),
    "DISCORD_WEBHOOK_URL": ("alerts",),
    "SLACK_WEBHOOK_URL": ("alerts",),
    "TELEGRAM_BOT_TOKEN": ("alerts",),
    "TELEGRAM_CHAT_ID": ("alerts",),
    "TEAMS_WEBHOOK_URL": ("alerts",),
    "DNSCOPE_WEBHOOK_SECRET": ("alerts",),
    "SMTP_PASSWORD": ("alerts",),
}


class SecretSource(StrEnum):
    """Where a secret was found."""

    ENVIRONMENT = "environment"
    KEYRING = "keyring"
    ENCRYPTED_FILE = "encrypted_file"
    NONE = "none"


@dataclass
class Secret:
    """A resolved secret plus its provenance (value is never logged)."""

    name: str
    value: str
    source: SecretSource

    @property
    def is_set(self) -> bool:
        return bool(self.value)

    def masked(self) -> str:
        """Display-safe rendering."""
        return mask_secret(self.value)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Secret(name={self.name!r}, source={self.source.value}, value={self.masked()!r})"


def _derive_key(material: str) -> bytes:
    """Derive a Fernet key from arbitrary master-key material."""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    # A ready-made Fernet key is used verbatim so operators can store one.
    try:
        candidate = material.strip()
        Fernet(candidate.encode())
        return candidate.encode()
    except Exception:
        pass

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"dnscope-v4-secret-store",
        iterations=210_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(material.encode("utf-8")))


def _load_master_key() -> bytes | None:
    """Load the master key from the environment or a key file."""
    raw = os.environ.get(MASTER_KEY_ENV, "").strip()
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if candidate.is_file():
        raw = candidate.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    return _derive_key(raw)


class SecretStore:
    """Reads (and optionally writes) DNScope credentials."""

    def __init__(
        self,
        *,
        path: str | Path | None = None,
        use_keyring: bool = True,
        use_encrypted_file: bool = True,
        environ: dict[str, str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser() if path else DEFAULT_SECRET_FILE
        self.use_keyring = use_keyring
        self.use_encrypted_file = use_encrypted_file
        self._environ = environ
        self._file_cache: dict[str, str] | None = None

    # ------------------------------------------------------------------- read

    def get(self, name: str, *, default: str = "") -> str:
        """Return the secret ``name`` or ``default``."""
        return self.lookup(name).value or default

    def lookup(self, name: str) -> Secret:
        """Resolve ``name`` across all configured sources."""
        env = self._environ if self._environ is not None else os.environ
        value = env.get(name, "").strip()
        if value:
            return Secret(name, value, SecretSource.ENVIRONMENT)

        if self.use_keyring:
            value = self._keyring_get(name)
            if value:
                return Secret(name, value, SecretSource.KEYRING)

        if self.use_encrypted_file:
            value = self._file_get(name)
            if value:
                return Secret(name, value, SecretSource.ENCRYPTED_FILE)

        return Secret(name, "", SecretSource.NONE)

    def get_all(self, names: list[str] | None = None) -> dict[str, Secret]:
        """Resolve several secrets at once (used by ``dnscope doctor``)."""
        return {name: self.lookup(name) for name in (names or sorted(KNOWN_SECRETS))}

    def is_configured(self, name: str) -> bool:
        """``True`` when the secret is available from any source."""
        return self.lookup(name).is_set

    def status_table(self, names: list[str] | None = None) -> list[dict[str, str]]:
        """Redacted status rows for terminal output."""
        rows: list[dict[str, str]] = []
        for name in names or sorted(KNOWN_SECRETS):
            secret = self.lookup(name)
            rows.append(
                {
                    "name": name,
                    "configured": "yes" if secret.is_set else "no",
                    "source": secret.source.value,
                    "value": secret.masked() if secret.is_set else "-",
                }
            )
        return rows

    # --------------------------------------------------------------- keyring

    def _keyring_get(self, name: str) -> str:
        """Read from the OS credential store when ``keyring`` is available."""
        try:
            import keyring  # type: ignore[import-not-found]
        except ImportError:
            return ""
        try:
            value = keyring.get_password(KEYRING_SERVICE, name)
        except Exception as exc:
            _log.debug("keyring lookup failed for %s: %s", name, exc)
            return ""
        return (value or "").strip()

    def keyring_set(self, name: str, value: str) -> bool:
        """Store a secret in the OS credential store."""
        try:
            import keyring  # type: ignore[import-not-found]
        except ImportError:
            return False
        try:
            keyring.set_password(KEYRING_SERVICE, name, value)
        except Exception as exc:
            _log.warning("keyring write failed: %s", exc)
            return False
        return True

    # -------------------------------------------------------- encrypted file

    def _file_data(self) -> dict[str, str]:
        """Decrypt and cache the local secret store."""
        if self._file_cache is not None:
            return self._file_cache
        self._file_cache = {}
        if not self.path.is_file():
            return self._file_cache
        key = _load_master_key()
        if key is None:
            _log.debug("secret store present but %s is not set", MASTER_KEY_ENV)
            return self._file_cache
        try:
            from cryptography.fernet import Fernet, InvalidToken

            token = self.path.read_bytes()
            payload = Fernet(key).decrypt(token)
            data = json.loads(payload.decode("utf-8"))
            if isinstance(data, dict):
                self._file_cache = {str(k): str(v) for k, v in data.items()}
        except InvalidToken:
            _log.warning("secret store could not be decrypted (wrong %s?)", MASTER_KEY_ENV)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            _log.warning("secret store is unreadable: %s", exc)
        return self._file_cache

    def _file_get(self, name: str) -> str:
        """Read a secret from the encrypted store."""
        return self._file_data().get(name, "").strip()

    def file_set(self, name: str, value: str) -> Path:
        """Write ``name`` into the encrypted store (requires a master key)."""
        key = _load_master_key()
        if key is None:
            raise SecurityPolicyViolation(
                f"{MASTER_KEY_ENV} must be set to write the encrypted secret store"
            )
        from cryptography.fernet import Fernet

        data = self._file_data()
        data[name] = value
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        token = Fernet(key).encrypt(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(token)
        with contextlib.suppress(OSError):  # platform dependent
            self.path.chmod(0o600)
        self._file_cache = data
        return self.path

    def file_delete(self, name: str) -> bool:
        """Remove a secret from the encrypted store."""
        data = self._file_data()
        if name not in data:
            return False
        del data[name]
        self._file_cache = data
        key = _load_master_key()
        if key is None:
            return False
        from cryptography.fernet import Fernet

        token = Fernet(key).encrypt(json.dumps(data, sort_keys=True).encode("utf-8"))
        self.path.write_bytes(token)
        return True

    def sources_available(self) -> dict[str, bool]:
        """Which secret backends are usable in this environment."""
        keyring_ok = False
        try:
            import keyring  # type: ignore[import-not-found]  # noqa: F401

            keyring_ok = True
        except ImportError:
            keyring_ok = False
        return {
            "environment": True,
            "keyring": keyring_ok,
            "encrypted_file": _load_master_key() is not None,
        }


def resolve_secret(name: str, *, default: str = "", store: SecretStore | None = None) -> str:
    """Resolve one credential, optionally using a supplied store."""
    if store is not None:
        return store.get(name, default=default)
    value = os.environ.get(name, "").strip()
    if value:
        return value
    try:
        return SecretStore().get(name, default=default)
    except Exception:
        return default


def secret_names_for_provider(provider: str) -> list[str]:
    """Environment variable names used by ``provider``."""
    return [name for name, providers in KNOWN_SECRETS.items() if provider in providers]


def redact_url(url: str) -> str:
    """Remove credentials from a URL before logging."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return "[invalid-url]"
    if not parts.username and not parts.password:
        return url
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def require_secret(name: str, *, store: SecretStore | None = None) -> str:
    """Resolve a secret, raising :class:`ConfigurationError` when missing."""
    value = resolve_secret(name, store=store)
    if not value:
        raise ConfigurationError(f"missing required credential: {name}")
    return value


def describe_store(store: SecretStore | None = None) -> dict[str, Any]:
    """Diagnostics block for ``dnscope doctor`` (never includes values)."""
    active = store or SecretStore()
    configured = [name for name in sorted(KNOWN_SECRETS) if active.is_configured(name)]
    return {
        "backends": active.sources_available(),
        "store_path": str(active.path),
        "store_exists": active.path.is_file(),
        "configured": configured,
        "configured_count": len(configured),
    }
