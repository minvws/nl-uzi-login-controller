from configparser import ConfigParser
from unittest.mock import MagicMock
import pytest
from pytest_mock import MockerFixture

from app.dependencies import create_yivi_service_from_config, _parse_hostname
from app.models.yivi_authentication_config import YiviAuthenticationConfig


@pytest.fixture
def config() -> ConfigParser:
    """A fixture to create a ConfigParser instance for testing."""
    config = ConfigParser()
    config.add_section("yivi")
    config.set("yivi", "yivi_internal_server_url", "http://dummy-yivi-internal-server")
    config.set("yivi", "yivi_disclose_prefix", "testprefix")
    return config


def test_yivi_service_auth_disabled(mocker: MockerFixture, config: ConfigParser):
    """
    Tests that YiviService is initialized without an authentication config when authentication is disabled.
    """
    # Arrange
    config.set("yivi", "yivi_authentication_enabled", "false")

    mock_load_jwk = mocker.patch("app.dependencies.load_jwk")

    # Act
    service = create_yivi_service_from_config(
        application_host="example-host", config_parser=config, timeout=30
    )

    # Assert
    mock_load_jwk.assert_not_called()
    assert service._authentication_config is None


def test_yivi_service_auth_enabled_no_key_path_raises_error(config: ConfigParser):
    """
    Tests that a ValueError is raised when auth is enabled but no key path is provided.
    """
    # Arrange
    config.set("yivi", "yivi_authentication_enabled", "true")
    # No key path is set

    # Act & Assert
    with pytest.raises(
        ValueError,
        match="Yivi authentication is enabled, but 'yivi_authentication_priv_key_path' is not configured.",
    ):
        create_yivi_service_from_config(
            application_host="example-host", config_parser=config, timeout=30
        )


def test_yivi_service_auth_enabled_with_key(
    mocker: MockerFixture, config: ConfigParser
):
    """
    Tests that YiviService is initialized with an authentication config when auth is enabled and a path is set.
    """
    # Arrange
    fake_key_path = "/fake/private_key.json"
    fake_jwk = MagicMock()
    config.set("yivi", "yivi_authentication_enabled", "true")
    config.set("yivi", "yivi_authentication_priv_key_path", fake_key_path)
    config.set("yivi", "yivi_authentication_issuer", "issuer-test")

    mock_load_jwk = mocker.patch("app.dependencies.load_jwk", return_value=fake_jwk)

    # Act
    service = create_yivi_service_from_config(
        application_host="example-host", config_parser=config, timeout=30
    )

    # Assert
    mock_load_jwk.assert_called_once_with(fake_key_path)
    assert isinstance(service._authentication_config, YiviAuthenticationConfig)
    assert service._authentication_config.priv_key == fake_jwk
    assert service._authentication_config.issuer == "issuer-test"


def test_yivi_service_auth_enabled_missing_issuer_raises_error(
    mocker: MockerFixture, config: ConfigParser
):
    """Auth enabled with key but no issuer should raise ValueError."""
    fake_key_path = "/fake/private_key.json"
    fake_jwk = MagicMock()
    config.set("yivi", "yivi_authentication_enabled", "true")
    config.set("yivi", "yivi_authentication_priv_key_path", fake_key_path)
    mocker.patch("app.dependencies.load_jwk", return_value=fake_jwk)

    with pytest.raises(ValueError, match="yivi_authentication_issuer' is missing."):
        create_yivi_service_from_config(
            application_host="example-host", config_parser=config, timeout=30
        )


def test_yivi_service_auth_enabled_empty_issuer_raises_error(
    mocker: MockerFixture, config: ConfigParser
):
    """Auth enabled with key and empty issuer (whitespace) should raise ValueError."""
    fake_key_path = "/fake/private_key.json"
    fake_jwk = MagicMock()
    config.set("yivi", "yivi_authentication_enabled", "true")
    config.set("yivi", "yivi_authentication_priv_key_path", fake_key_path)
    config.set("yivi", "yivi_authentication_issuer", "")
    mocker.patch("app.dependencies.load_jwk", return_value=fake_jwk)

    with pytest.raises(ValueError, match="yivi_authentication_issuer' is missing."):
        create_yivi_service_from_config(
            application_host="example-host", config_parser=config, timeout=30
        )


def test_parse_hostname_with_valid_url() -> None:
    """Tests that _parse_hostname correctly extracts hostname from a valid URL."""
    assert _parse_hostname("https://example.com") == "example.com"
    assert _parse_hostname("http://test.example.com:8080/path") == "test.example.com"
    assert _parse_hostname("http://localhost:3000") == "localhost"
    assert _parse_hostname("https://127.0.0.1:8000/api") == "127.0.0.1"


def test_parse_hostname_with_invalid_url() -> None:
    """Tests that _parse_hostname raises ValueError for invalid URLs."""
    with pytest.raises(ValueError, match="Invalid base URL:"):
        _parse_hostname("not-a-url")

    with pytest.raises(ValueError, match="Invalid base URL:"):
        _parse_hostname("")

    with pytest.raises(ValueError, match="Invalid base URL:"):
        _parse_hostname("invalid://")
