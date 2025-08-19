import json
import base64
from typing import List, Dict, Any
from unittest import mock
from unittest.mock import MagicMock

import pytest
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from jwcrypto.common import JWException
from app.exceptions.app_exceptions import YiviServerException
from app.services.yivi_service import YiviService


def _assert_disclosures(
    credential_id: str,
    disclosures: List[Dict[str, str]],
    expected_disclosures: List[Dict[str, str]],
) -> None:
    assert len(disclosures) == len(expected_disclosures), "Disclosures length mismatch"
    for disclosure, expected in zip(disclosures, expected_disclosures):
        expected_disclosure_type = f"{credential_id}.{expected['disclose_type']}"
        assert (
            disclosure["type"] == expected_disclosure_type
        ), "Disclosure type mismatch"
        if "value" in expected:
            assert (
                disclosure.get("value") == expected["disclose_value"]
            ), "Disclosure value mismatch"


def _assert_request(
    request: Dict[str, Any],
    credential_id: str,
    expected_context: str,
    expected_host: str,
    expected_disclosures: List[Dict[str, str]],
    expected_revocation: bool = False,
) -> None:
    assert request["@context"] == expected_context, "Context mismatch"
    assert request["host"] == expected_host, "Host mismatch"

    if expected_revocation:
        assert "revocation" in request, "Revocation key missing in request"
        assert request["revocation"] == [credential_id], "Revocation mismatch"

    assert "disclose" in request, "Disclose key missing in request"
    assert len(request["disclose"]) == 1, "Disclose should be a list with one item"
    discloses = request["disclose"][0][0]
    _assert_disclosures(credential_id, discloses, expected_disclosures)


def _base64url_decode(data: str) -> bytes:
    """Decodes a base64url encoded string, adding padding if necessary."""
    padding_needed = len(data) % 4
    match padding_needed:
        case 2:
            data += "=="
        case 3:
            data += "="
        case _:
            pass  # No padding needed
    return base64.urlsafe_b64decode(data)


def test_create_disclose_session_with_signed_jwt(
    yivi_service_with_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    expected_yivi_session_success_response: str,
    requested_disclosures: List[Dict[str, str]],
    yivi_pub_key: JWK,
    yivi_issuer: str,
    yivi_disclosure_request_context: str,
    yivi_disclose_prefix: str,
    yivi_internal_server_session_url: str,
    yivi_signed_request_headers: Dict[str, str],
    application_host: str,
) -> None:
    result_text = yivi_service_with_auth.create_disclose_session(requested_disclosures)

    mock_yivi_session_post_success.assert_called_once_with(
        url=yivi_internal_server_session_url,
        headers=yivi_signed_request_headers,
        data=mock.ANY,
        timeout=yivi_service_with_auth._http_timeout,
    )
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    assert result_text == expected_yivi_session_success_response

    verified_jws = JWT(key=yivi_pub_key, jwt=call_kwargs["data"])
    payload = json.loads(verified_jws.claims)

    assert payload["iss"] == yivi_issuer
    assert payload["sub"] == "verification_request"
    assert "iat" in payload

    yivi_request = payload["sprequest"]["request"]

    _assert_request(
        yivi_request,
        yivi_disclose_prefix,
        yivi_disclosure_request_context,
        application_host,
        requested_disclosures,
    )


def test_create_disclose_session_with_revocation(
    yivi_service_with_auth_and_revocation: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures: List[Dict[str, str]],
    yivi_pub_key: JWK,
    yivi_disclose_prefix: str,
    yivi_internal_server_session_url: str,
    yivi_signed_request_headers: Dict[str, str],
    yivi_disclosure_request_context: str,
    application_host: str,
) -> None:
    yivi_service_with_auth_and_revocation.create_disclose_session(requested_disclosures)
    mock_yivi_session_post_success.assert_called_once_with(
        url=yivi_internal_server_session_url,
        headers=yivi_signed_request_headers,
        data=mock.ANY,
        timeout=yivi_service_with_auth_and_revocation._http_timeout,
    )
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    verified_jws = JWT(key=yivi_pub_key, jwt=call_kwargs["data"])
    payload = json.loads(verified_jws.claims)

    yivi_request = payload["sprequest"]["request"]

    _assert_request(
        yivi_request,
        yivi_disclose_prefix,
        yivi_disclosure_request_context,
        application_host,
        requested_disclosures,
    )


def test_create_disclose_session_multiple_disclosures_signed(
    yivi_service_with_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures_multiple: List[Dict[str, str]],
    yivi_pub_key: JWK,
    yivi_disclose_prefix: str,
    yivi_internal_server_session_url: str,
    yivi_signed_request_headers: Dict[str, str],
    yivi_disclosure_request_context: str,
    application_host: str,
) -> None:
    yivi_service_with_auth.create_disclose_session(requested_disclosures_multiple)
    mock_yivi_session_post_success.assert_called_once_with(
        url=yivi_internal_server_session_url,
        headers=yivi_signed_request_headers,
        data=mock.ANY,
        timeout=yivi_service_with_auth._http_timeout,
    )
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    verified_jws = JWT(key=yivi_pub_key, jwt=call_kwargs["data"])
    payload = json.loads(verified_jws.claims)

    yivi_request = payload["sprequest"]["request"]

    _assert_request(
        yivi_request,
        yivi_disclose_prefix,
        yivi_disclosure_request_context,
        application_host,
        requested_disclosures_multiple,
    )


def test_create_disclose_session_multiple_disclosures_unsigned(
    yivi_service_without_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures_multiple: List[Dict[str, str]],
    yivi_disclose_prefix: str,
    yivi_internal_server_session_url: str,
    yivi_unsigned_request_headers: Dict[str, str],
    yivi_disclosure_request_context: str,
    application_host: str,
) -> None:
    yivi_service_without_auth.create_disclose_session(requested_disclosures_multiple)
    mock_yivi_session_post_success.assert_called_once_with(
        url=yivi_internal_server_session_url,
        headers=yivi_unsigned_request_headers,
        data=mock.ANY,
        timeout=yivi_service_without_auth._http_timeout,
    )
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    yivi_request = json.loads(call_kwargs["data"])

    _assert_request(
        yivi_request,
        yivi_disclose_prefix,
        yivi_disclosure_request_context,
        application_host,
        requested_disclosures_multiple,
    )


def test_create_disclose_session_empty_disclosures_signed(
    yivi_service_with_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures_empty: List[Dict[str, str]],
    yivi_pub_key: JWK,
    yivi_internal_server_session_url: str,
    yivi_signed_request_headers: Dict[str, str],
) -> None:
    yivi_service_with_auth.create_disclose_session(requested_disclosures_empty)
    mock_yivi_session_post_success.assert_called_once_with(
        url=yivi_internal_server_session_url,
        headers=yivi_signed_request_headers,
        data=mock.ANY,
        timeout=yivi_service_with_auth._http_timeout,
    )
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    verified_jws = JWT(key=yivi_pub_key, jwt=call_kwargs["data"])
    payload = json.loads(verified_jws.claims)
    assert payload["sprequest"]["request"]["disclose"] == [[[]]]


def test_create_disclose_session_empty_disclosures_unsigned(
    yivi_service_without_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures_empty: List[Dict[str, str]],
    yivi_internal_server_session_url: str,
    yivi_unsigned_request_headers: Dict[str, str],
) -> None:
    yivi_service_without_auth.create_disclose_session(requested_disclosures_empty)
    mock_yivi_session_post_success.assert_called_once_with(
        url=yivi_internal_server_session_url,
        headers=yivi_unsigned_request_headers,
        data=mock.ANY,
        timeout=yivi_service_without_auth._http_timeout,
    )
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    body = json.loads(call_kwargs["data"])
    assert body["disclose"] == [[[]]]


def test_create_disclose_session_error_raises(
    yivi_service_with_auth: YiviService,
    mock_yivi_session_post_error: MagicMock,
    requested_disclosures: List[Dict[str, str]],
) -> None:
    with pytest.raises(YiviServerException):
        yivi_service_with_auth.create_disclose_session(requested_disclosures)


def test_fetch_disclose_result_success(
    yivi_service_without_auth: YiviService,
    yivi_internal_server_session_url: str,
    mock_yivi_result_get_success: MagicMock,
    expected_yivi_result_success_response: Dict[str, Any],
) -> None:
    result = yivi_service_without_auth.fetch_disclose_result("sometoken")
    mock_yivi_result_get_success.assert_called_once_with(
        url=f"{yivi_internal_server_session_url}/sometoken/result",
        timeout=yivi_service_without_auth._http_timeout,
    )
    assert result == expected_yivi_result_success_response


def test_fetch_disclose_result_error(
    yivi_service_without_auth: YiviService, mock_yivi_result_get_error: MagicMock
) -> None:
    with pytest.raises(YiviServerException):
        yivi_service_without_auth.fetch_disclose_result("sometoken")


def test_jws_signature_tamper_detection(
    yivi_service_with_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures: List[Dict[str, str]],
    yivi_pub_key: JWK,
) -> None:
    yivi_service_with_auth.create_disclose_session(requested_disclosures)
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    original = call_kwargs["data"]

    # Split the JWS, decode the payload, modify a claim, and re-assemble.
    parts = original.split(".")
    assert len(parts) == 3
    header_b64, payload_b64, signature_b64 = parts

    payload = json.loads(_base64url_decode(payload_b64))
    payload["iss"] = "tampered-issuer"  # Modify a claim
    tampered_payload_json = json.dumps(payload).encode()
    tampered_payload_b64 = (
        base64.urlsafe_b64encode(tampered_payload_json).rstrip(b"=").decode()
    )

    tampered = ".".join([header_b64, tampered_payload_b64, signature_b64])

    # Verifying the tampered token should fail as the signature is no longer valid.
    with pytest.raises(JWException):
        JWT(key=yivi_pub_key, jwt=tampered)


def test_unsigned_request_has_json_structure(
    yivi_service_without_auth: YiviService,
    mock_yivi_session_post_success: MagicMock,
    requested_disclosures: List[Dict[str, str]],
) -> None:
    """Verify that an unsigned request has a valid JSON structure without JWS keys."""
    yivi_service_without_auth.create_disclose_session(requested_disclosures)
    _args, call_kwargs = mock_yivi_session_post_success.call_args
    data = call_kwargs["data"]

    # Unsigned path should be valid JSON, not a JWS string.
    try:
        body = json.loads(data)
        assert isinstance(body, dict)
    except json.JSONDecodeError:
        pytest.fail("Request data for unsigned request is not valid JSON.")

    # Ensure no JWS-specific keys are present.
    assert "sprequest" not in body
    assert "iss" not in body
    assert "sub" not in body

    # Ensure standard Yivi request keys are present.
    assert "@context" in body
    assert "disclose" in body
