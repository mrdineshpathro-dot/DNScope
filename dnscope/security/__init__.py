"""Security guards: SSRF protection, secret handling and input validation."""

from dnscope.security.secrets import SecretSource, SecretStore, resolve_secret
from dnscope.security.ssrf import (
    SSRFProtectionError,
    SSRFValidator,
    validate_url,
)
from dnscope.security.validators import (
    clamp_int,
    ensure_bounded,
    safe_json_loads,
    validate_hostname_input,
    validate_identifier,
)

__all__ = [
    "SSRFProtectionError",
    "SSRFValidator",
    "SecretSource",
    "SecretStore",
    "clamp_int",
    "ensure_bounded",
    "resolve_secret",
    "safe_json_loads",
    "validate_hostname_input",
    "validate_identifier",
    "validate_url",
]
