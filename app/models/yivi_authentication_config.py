from dataclasses import dataclass
from jwcrypto.jwk import JWK


@dataclass(frozen=True, slots=True)
class YiviAuthenticationConfig:
    """Immutable object for authentication config to the Yivi service."""

    issuer: str
    priv_key: JWK
