import pytest
from unittest.mock import patch, MagicMock
from app.utils import load_oidc_well_known_config


@patch("app.utils.json_from_file")
@patch("app.utils.json_fetch_url")
@patch("app.utils.load_jwk")
def test_load_oidc_well_known_config_success(
    mock_load_jwk, mock_json_fetch_url, mock_json_from_file
):
    provider_config = [
        {
            "name": "test-provider",
            "issuer": "https://issuer.example.com",
            "client_id": "clientid",
            "client_secret": "secret",
            "scopes": ["openid"],
            "oidc_provider_public_key_path": "dummy/path",
            "token_endpoint_auth_method": "private_key_jwt",
            "verify_ssl": True,
        }
    ]
    mock_json_from_file.return_value = provider_config
    mock_json_fetch_url.return_value = {
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/auth",
        "token_endpoint": "https://issuer.example.com/token",
        "userinfo_endpoint": "https://issuer.example.com/userinfo",
        "jwks_uri": "https://issuer.example.com/jwks",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    mock_load_jwk.return_value = MagicMock()

    result = load_oidc_well_known_config("dummy.json", "production", 5)

    assert "test-provider" in result
    provider = result["test-provider"]

    assert provider.issuer_url == "https://issuer.example.com"
    assert provider.client_id == "clientid"
    assert provider.client_secret == "secret"
    assert provider.client_scopes == ["openid"]
    assert provider.token_endpoint_auth_method == "private_key_jwt"
    assert provider.verify_ssl is True
    assert provider.well_known_configuration.issuer == "https://issuer.example.com"
    assert (
        provider.well_known_configuration.authorization_endpoint
        == "https://issuer.example.com/auth"
    )
    assert (
        provider.well_known_configuration.token_endpoint
        == "https://issuer.example.com/token"
    )
    assert (
        provider.well_known_configuration.userinfo_endpoint
        == "https://issuer.example.com/userinfo"
    )
    assert (
        provider.well_known_configuration.jwks_uri == "https://issuer.example.com/jwks"
    )
    assert provider.well_known_configuration.scopes_supported == ["openid"]
    assert provider.well_known_configuration.response_types_supported == ["code"]
    assert provider.well_known_configuration.subject_types_supported == ["pairwise"]
    assert provider.well_known_configuration.id_token_signing_alg_values_supported == [
        "RS256"
    ]


@patch("app.utils.json_from_file")
@patch("app.utils.json_fetch_url", side_effect=Exception("fetch error"))
@patch("app.utils.load_jwk")
def test_load_oidc_well_known_config_exception(
    mock_load_jwk, mock_json_fetch_url, mock_json_from_file, caplog
):
    provider_config = [
        {
            "name": "test-provider",
            "issuer": "https://issuer.example.com",
            "client_id": "clientid",
            "client_secret": "secret",
            "scopes": ["openid"],
            "oidc_provider_public_key_path": "dummy/path",
            "token_endpoint_auth_method": "client_secret_basic",
            "verify_ssl": True,
        }
    ]
    mock_json_from_file.return_value = provider_config
    mock_load_jwk.return_value = MagicMock()

    result = load_oidc_well_known_config("dummy.json", "production", 5)
    assert "test-provider" in result

    provider = result["test-provider"]
    assert provider.well_known_configuration is None

    assert any(
        "Exception occurred while fetching OIDC config" in record.message
        for record in caplog.records
    )
