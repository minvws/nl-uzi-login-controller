from typing import List, Dict
from unittest.mock import MagicMock

import pytest
from jwcrypto.jwk import JWK
from pytest_mock import MockerFixture

from app.models.yivi_authentication_config import YiviAuthenticationConfig
from app.services.yivi_service import YiviService


@pytest.fixture(scope="module")
def application_host() -> str:
    """Returns a test application host string."""
    return "test-application-host"


@pytest.fixture(scope="session")
def yivi_issuer() -> str:
    """Returns a test issuer string for Yivi."""
    return "test-issuer"


@pytest.fixture(scope="session")
def yivi_disclose_prefix() -> str:
    """Returns a test disclose prefix, representing a credential ID."""
    return "irma-demo.uzi"


@pytest.fixture(scope="session")
def yivi_internal_server_url() -> str:
    """Returns the base URL for the dummy Yivi internal server."""
    return "http://dummy-yivi-internal-server"


@pytest.fixture(scope="session")
def yivi_internal_server_session_url(yivi_internal_server_url: str) -> str:
    """Returns the full session endpoint URL for the Yivi server."""
    return f"{yivi_internal_server_url}/session"


@pytest.fixture(scope="session")
def yivi_priv_key() -> JWK:
    """Generates a session-scoped RSA private key for signing."""
    return JWK.generate(kty="RSA", size=1024)


@pytest.fixture(scope="session")
def yivi_pub_key(yivi_priv_key: JWK) -> JWK:
    """Derives the public key from the session-scoped private key."""
    return yivi_priv_key.public()


@pytest.fixture(scope="session")
def requested_disclosures() -> List[Dict[str, str]]:
    """Returns a sample list of a single requested disclosure."""
    return [{"disclose_type": "uzi_id", "disclose_value": "12345"}]


@pytest.fixture(scope="session")
def requested_disclosures_multiple() -> List[Dict[str, str]]:
    """Returns a sample list of multiple disclosures, one with a value and one without."""
    return [
        {"disclose_type": "uzi_id", "disclose_value": "12345"},
        {"disclose_type": "roles"},
    ]


@pytest.fixture(scope="session")
def requested_disclosures_empty() -> List[Dict[str, str]]:
    """Returns an empty list of disclosures."""
    return []


@pytest.fixture(scope="session")
def yivi_signed_request_headers() -> Dict[str, str]:
    """Returns headers for a signed Yivi request (JWS)."""
    return {"Content-Type": "application/jose"}


@pytest.fixture(scope="session")
def yivi_unsigned_request_headers() -> Dict[str, str]:
    """Returns headers for an unsigned Yivi request (JSON)."""
    return {"Content-Type": "application/json"}


@pytest.fixture(scope="session")
def yivi_disclosure_request_context() -> str:
    """Returns the context URL for a Yivi disclosure request."""
    return "https://irma.app/ld/request/disclosure/v2"


@pytest.fixture(scope="session")
def expected_yivi_session_success_response() -> str:
    """Returns the expected raw text response for a successful Yivi session creation."""
    return '{"sessionPtr":"abc"}'


@pytest.fixture(scope="session")
def expected_yivi_result_success_response() -> Dict[str, str]:
    """Returns the expected JSON response for a successful Yivi result fetch."""
    return {"status": "DONE"}


@pytest.fixture(scope="session")
def yivi_auth_config(yivi_issuer: str, yivi_priv_key: JWK) -> YiviAuthenticationConfig:
    """Creates a YiviAuthenticationConfig instance from session-scoped fixtures."""
    return YiviAuthenticationConfig(issuer=yivi_issuer, priv_key=yivi_priv_key)


@pytest.fixture()
def yivi_service_with_auth(
    application_host: str,
    yivi_internal_server_url: str,
    yivi_disclose_prefix: str,
    yivi_auth_config: YiviAuthenticationConfig,
) -> YiviService:
    """Returns a YiviService instance with authentication configured."""
    return YiviService(
        application_host=application_host,
        yivi_internal_server_url=yivi_internal_server_url,
        yivi_disclose_prefix=yivi_disclose_prefix,
        request_nonrevocation_proof=False,
        http_timeout=30,
        authentication_config=yivi_auth_config,
    )


@pytest.fixture()
def yivi_service_with_auth_and_revocation(
    application_host: str,
    yivi_internal_server_url: str,
    yivi_disclose_prefix: str,
    yivi_auth_config: YiviAuthenticationConfig,
) -> YiviService:
    """Returns a YiviService instance configured for auth and non-revocation proofs."""
    return YiviService(
        application_host=application_host,
        yivi_internal_server_url=yivi_internal_server_url,
        yivi_disclose_prefix=yivi_disclose_prefix,
        request_nonrevocation_proof=True,
        http_timeout=30,
        authentication_config=yivi_auth_config,
    )


@pytest.fixture()
def yivi_service_without_auth(
    application_host: str,
    yivi_internal_server_url: str,
    yivi_disclose_prefix: str,
) -> YiviService:
    """Returns a YiviService instance without authentication configured."""
    return YiviService(
        application_host=application_host,
        yivi_internal_server_url=yivi_internal_server_url,
        yivi_disclose_prefix=yivi_disclose_prefix,
        request_nonrevocation_proof=False,
        http_timeout=30,
        authentication_config=None,
    )


@pytest.fixture()
def mock_yivi_session_post_success(
    mocker: MockerFixture, expected_yivi_session_success_response: str
) -> MagicMock:
    """Mocks requests.post for successful Yivi session creation responses."""
    mock = mocker.patch("app.services.yivi_service.requests.post")
    mock.return_value.status_code = 200
    mock.return_value.text = expected_yivi_session_success_response
    return mock


@pytest.fixture()
def mock_yivi_session_post_error(mocker: MockerFixture) -> MagicMock:
    """Mocks requests.post for failing Yivi session creation responses."""
    mock = mocker.patch("app.services.yivi_service.requests.post")
    mock.return_value.status_code = 500
    mock.return_value.text = "server error"
    return mock


@pytest.fixture()
def mock_yivi_result_get_success(
    mocker: MockerFixture, expected_yivi_result_success_response: str
) -> MagicMock:
    """Mocks requests.get for successful Yivi session result responses."""
    mock = mocker.patch("app.services.yivi_service.requests.get")
    mock.return_value.status_code = 200
    mock.return_value.json.return_value = expected_yivi_result_success_response
    return mock


@pytest.fixture()
def mock_yivi_result_get_error(mocker: MockerFixture) -> MagicMock:
    """Mocks requests.get for failing Yivi session result responses."""
    mock = mocker.patch("app.services.yivi_service.requests.get")
    mock.return_value.status_code = 404
    mock.return_value.text = "not found"
    return mock
