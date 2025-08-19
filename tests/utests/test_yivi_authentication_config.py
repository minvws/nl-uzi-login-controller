from dataclasses import FrozenInstanceError
from jwcrypto.jwk import JWK

from app.models.yivi_authentication_config import YiviAuthenticationConfig


def test_yivi_auth_config() -> None:
    expected_key = JWK.generate(kty="RSA", size=1024)
    expected_issuer = "my-issuer"
    cfg = YiviAuthenticationConfig(issuer=expected_issuer, priv_key=expected_key)

    assert cfg.issuer == expected_issuer
    assert cfg.priv_key == expected_key


def test_yivi_auth_config_immutable() -> None:
    key = JWK.generate(kty="RSA", size=1024)
    cfg = YiviAuthenticationConfig(issuer="issuer", priv_key=key)
    try:
        cfg.issuer = "changed"
        raise AssertionError("Expected FrozenInstanceError when modifying issuer")
    except FrozenInstanceError:
        pass
    try:
        cfg.priv_key = JWK.generate(kty="RSA", size=1024)
        raise AssertionError("Expected FrozenInstanceError when modifying priv_key")
    except FrozenInstanceError:
        pass
