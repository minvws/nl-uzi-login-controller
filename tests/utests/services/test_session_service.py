import json
from unittest import mock

import pytest
from unittest.mock import MagicMock

from fastapi import HTTPException

from app.exceptions.app_exceptions import SessionExpired, YiviServerException
from app.models.session import SessionType, Session, SessionStatus
from app.services.jwt_service import create_jwt
from app.services.session_service import SessionService
from app.services.yivi_service import YiviService
from app.services.template_service import TemplateService
from jwcrypto.jwk import JWK


@pytest.fixture
def mock_redis():
    return MagicMock()


@pytest.fixture
def mock_yivi_service():
    return MagicMock(spec=YiviService)


@pytest.fixture()
def jwt_issuer_crt():
    return JWK.generate(kty="RSA", size=1024)


@pytest.fixture
def register_api_crt():
    return JWK.generate(kty="RSA", size=1024)


def create_valid_jwt(jwt_issuer_crt: JWK, session_type: str):
    claims = {
        "session_type": session_type,
        "login_title": "Test Login",
        "iss": "jwt_issuer",
        "aud": "jwt_audience",
    }
    return create_jwt(jwt_issuer_crt, "123", claims)


def session_service_create_get_token(
    session_type: SessionType, jwt_issuer_crt: JWK, session_service: SessionService
):
    # Create JWT signed with invalid JWT.
    jwt = create_valid_jwt(jwt_issuer_crt, session_type)

    # Mock request with Authorization header
    class DummyRequest:
        headers = {"Authorization": "Bearer " + jwt}

    # Test create
    response = session_service.create(DummyRequest())
    assert response.status_code == 200

    # Apparently the exchange token is a JSON string (string surrounded by ""), so we decode it and load it
    return json.loads(response.body.decode())


def mock_session_data_redis(mock_redis):
    # Get the session data that was set in Redis and mock the get call
    session_data = mock_redis.set.call_args[0][1]
    mock_redis.get.return_value = session_data


@pytest.fixture
def session_service(
    mock_redis, mock_yivi_service, jwt_issuer_crt, register_api_crt, oidc_service=None
):
    return SessionService(
        redis_client=mock_redis,
        yivi_service=mock_yivi_service,
        oidc_service=oidc_service,
        yivi_disclose_prefix="prefix",
        redis_namespace="testns",
        expires_in_s=3600,
        jwt_issuer="jwt_issuer",
        jwt_issuer_crt=jwt_issuer_crt,
        jwt_audience="jwt_audience",
        register_api_crt=register_api_crt,
        session_result_jwt_issuer="session_result_jwt_issuer",
        session_result_jwt_audience="session_result_jwt_audience",
        signed_userinfo_issuer="userinfo_issuer",
        template_service=MagicMock(spec=TemplateService),
    )


@pytest.mark.parametrize(
    "iss,aud,iss_cert_correct,session_type",
    {
        # Valid cases just for reference
        ### ("jwt_issuer", "jwt_audience", True, SessionType.YIVI.value), # Valid case
        ### ("jwt_issuer", "jwt_audience", True, SessionType.UZI_CARD.value), # Valid case
        ### ("jwt_issuer", "jwt_audience", True, SessionType.OIDC.value), # Valid case
        # Invalid cases
        (
            "invalid_jwt_issuer",
            "jwt_audience",
            True,
            SessionType.YIVI.value,
        ),  # Invalid issuer
        (
            "jwt_issuer",
            "invalid_audience",
            True,
            SessionType.YIVI.value,
        ),  # Invalid audience
        (
            "jwt_issuer",
            "jwt_audience",
            False,
            SessionType.YIVI.value,
        ),  # Incorrect issuer certificate
        ("jwt_issuer", "jwt_audience", True, ""),  # Session type not supported
        ("jwt_issuer", "jwt_audience", True, "UNKOWN"),  # Session type not supported
    },
)
def test_create_with_jwt_invalid_claims(
    jwt_issuer_crt, session_service, iss, aud, iss_cert_correct, session_type
):
    # Create JWT signed with invalid JWT.
    claims = {
        "session_type": session_type,
        "login_title": "Test Login",
        "iss": iss,
        "aud": aud,
    }

    # Create JWT with invalid issuer certificate
    issuer_cert = (
        jwt_issuer_crt if iss_cert_correct else JWK.generate(kty="RSA", size=1024)
    )
    jwt = create_jwt(issuer_cert, "123", claims)

    # Mock request with Authorization header
    class DummyRequest:
        headers = {"Authorization": "Bearer " + jwt}

    # Test create
    with pytest.raises(HTTPException) as exc_info:
        session_service.create(DummyRequest())
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid session JWT"


def test_create_with_oidc_without_oidc_service(jwt_issuer_crt, session_service):
    # Create JWT signed with invalid JWT.
    jwt = create_valid_jwt(jwt_issuer_crt, SessionType.OIDC)

    # Mock request with Authorization header
    class DummyRequest:
        headers = {"Authorization": "Bearer " + jwt}

    # Test create
    response = session_service.create(DummyRequest())
    assert response.status_code == 400
    assert response.body.decode() == '{"message":"Login method not allowed"}'


def test_create_success(mock_redis, jwt_issuer_crt, session_service):
    exchange_token_str = session_service_create_get_token(
        SessionType.UZI_CARD, jwt_issuer_crt, session_service
    )

    mock_redis.set.assert_called_once_with(
        "testns:session:" + exchange_token_str, mock.ANY, ex=3600
    )


def test_create_success_yivi(
    mock_redis, mock_yivi_service, jwt_issuer_crt, session_service
):
    mocked_yivi_response = "some_yivi_response"
    mock_yivi_service.create_disclose_session.return_value = mocked_yivi_response

    session_service_create_get_token(SessionType.YIVI, jwt_issuer_crt, session_service)

    mock_yivi_service.create_disclose_session.assert_called_with(
        [
            {"disclose_type": "uziId"},
            {"disclose_type": "roles"},
            {"disclose_type": "loaAuthn"},
        ]
    )

    session_data = mock_redis.set.call_args[0][1]

    session = Session.model_validate_json(session_data)
    assert session.yivi_disclose_response == mocked_yivi_response


def test_create_success_redis_session_data(mock_redis, jwt_issuer_crt, session_service):
    session_service_create_get_token(
        SessionType.UZI_CARD, jwt_issuer_crt, session_service
    )

    session_data = mock_redis.set.call_args[0][1]

    session = Session.model_validate_json(session_data)
    assert session.session_type == SessionType.UZI_CARD
    assert len(session.exchange_token) == 86
    assert session.session_status == SessionStatus.INITIALIZED
    assert session.login_title == "Test Login"
    assert session.oidc_provider_name is None


def test_yivi_return_session_ptr(
    mock_redis, mock_yivi_service, jwt_issuer_crt, session_service
):
    mocked_yivi_response = json.dumps(
        {
            "sessionPtr": "some_session_ptr",
        }
    )
    mock_yivi_service.create_disclose_session.return_value = mocked_yivi_response

    token = session_service_create_get_token(
        SessionType.YIVI, jwt_issuer_crt, session_service
    )

    # Get the session data that was set in Redis and mock the get call
    mock_session_data_redis(mock_redis)

    response = session_service.yivi(token)
    assert response.status_code == 200

    # Apparently the body is a JSON string (string surrounded by ""), so we decode it and load it
    # This should not be necessary, but it is how the code works with JSONResponse in the current implementation
    response_body = json.loads(response.body.decode())

    assert response_body == "some_session_ptr"


def test_yivi_non_existing_exchange_token(mock_redis, session_service):
    mocked_session_token = "non_existing_token"

    mock_redis.get.return_value = None

    with pytest.raises(SessionExpired) as exc_info:
        session_service.yivi(mocked_session_token)

    mock_redis.get.assert_called_once_with("testns:session:" + mocked_session_token)

    assert str(exc_info.value) == "Yivi session expired"


@pytest.mark.parametrize(
    "session_type",
    {
        SessionType.YIVI.value,
        SessionType.UZI_CARD.value,
    },
)
def test_yivi_with_token_no_yivi_disclose_response(
    mock_redis, mock_yivi_service, jwt_issuer_crt, session_service, session_type
):
    mock_yivi_service.create_disclose_session.return_value = None

    # Test with UZI card session type
    token = session_service_create_get_token(
        session_type, jwt_issuer_crt, session_service
    )

    mock_session_data_redis(mock_redis)

    with pytest.raises(YiviServerException) as exc_info:
        session_service.yivi(token)

    assert str(exc_info.value) == "Unable to fetch response from YiviServer"
