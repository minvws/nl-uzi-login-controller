import json
import logging
import time
from typing import Dict, List, Optional, Any
from jwcrypto.jwt import JWT

import requests

from app.exceptions.app_exceptions import YiviServerException
from app.models.yivi_authentication_config import YiviAuthenticationConfig


logger = logging.getLogger(__name__)


class YiviService:
    def __init__(
        self,
        application_host: str,
        yivi_internal_server_url: str,
        yivi_disclose_prefix: str,
        request_nonrevocation_proof: bool,
        http_timeout: int,
        authentication_config: Optional[YiviAuthenticationConfig] = None,
    ):
        """Service for interacting with the Yivi server.

        application_host: External hostname / domain of the login controller.
        yivi_internal_server_url: Base URL for the internal Yivi server (no trailing slash).
        yivi_disclose_prefix: Prefix used when constructing disclose attribute types.
        request_nonrevocation_proof: Whether nonrevocation proof should be requested for the disclose session.
        http_timeout: Timeout (seconds) for HTTP calls to the Yivi server.
        authentication_config: Optional config containing issuer + private key for
            signing disclose session requests. When absent, requests are sent unsigned.
        """
        self._application_host = application_host
        self._yivi_internal_server_url = yivi_internal_server_url
        self._yivi_disclose_prefix = yivi_disclose_prefix
        self._request_nonrevocation_proof = request_nonrevocation_proof
        self._http_timeout = http_timeout
        self._authentication_config = authentication_config

    def create_disclose_session(
        self, requested_disclosures: List[Dict[str, str]]
    ) -> str:
        discloses = []
        for item in requested_disclosures:
            disclose = {"type": f"{self._yivi_disclose_prefix}.{item['disclose_type']}"}
            if "disclose_value" in item:
                disclose["value"] = item["disclose_value"]
            discloses.append(disclose)
        yivi_session_request: Dict[str, Any] = {
            "@context": "https://irma.app/ld/request/disclosure/v2",
            "host": self._application_host,
            "disclose": [[discloses]],
        }

        if self._request_nonrevocation_proof:
            yivi_session_request["revocation"] = [self._yivi_disclose_prefix]

        headers = {"Content-Type": "application/json"}
        data = json.dumps(yivi_session_request)

        if self._authentication_config:
            payload = {
                "iss": self._authentication_config.issuer,
                "iat": int(time.time()),
                "sub": "verification_request",
                "sprequest": {"request": yivi_session_request},
            }
            jws_token = JWT(header={"alg": "RS256"}, claims=payload)
            jws_token.make_signed_token(self._authentication_config.priv_key)
            data = jws_token.serialize()
            headers["Content-Type"] = "application/jose"

        yivi_response = requests.post(
            url=f"{self._yivi_internal_server_url}/session",
            headers=headers,
            data=data,
            timeout=self._http_timeout,
        )
        if yivi_response.status_code >= 400:
            logger.error(
                "Error while fetching YiviResponse, Yivi server returned: %s, %s",
                yivi_response.status_code,
                yivi_response.text,
            )
            raise YiviServerException()
        return yivi_response.text

    def fetch_disclose_result(self, token: str) -> Dict:
        yivi_response = requests.get(
            url=f"{self._yivi_internal_server_url}/session/{token}/result",
            timeout=self._http_timeout,
        )

        if yivi_response.status_code >= 400:
            logger.error(
                "Error while fetching YiviResponse, Yivi server returned: %s, %s",
                yivi_response.status_code,
                yivi_response.text,
            )
            raise YiviServerException()
        yivi_json_response = yivi_response.json()
        return yivi_json_response
