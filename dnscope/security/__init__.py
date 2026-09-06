"""Security guards: SSRF protection, secret handling and input validation."""

from dnscope.security.secrets import SecretSource, SecretStore, resolve_secret
from dnscope.security.ssrf import (
    SSRFProtectionError,
    SSRFValidator,
    validate_url,
)
from dnscope.security.validators import (
    clamp_int,
    coerce_str,
    coerce_str_list,
    ensure_bounded,
    list_field,
    mapping_field,
    safe_json_loads,
    truncate,
    validate_hostname_input,
    validate_identifier,
)

__all__ = [
    "SSRFProtectionError",
    "SSRFValidator",
    "SecretSource",
    "SecretStore",
    "clamp_int",
    "coerce_str",
    "coerce_str_list",
    "ensure_bounded",
    "list_field",
    "mapping_field",
    "resolve_secret",
    "safe_json_loads",
    "truncate",
    "validate_hostname_input",
    "validate_identifier",
    "validate_url",
]
