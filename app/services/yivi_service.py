import json
import logging
from typing import Dict, List

import requests

from app.exceptions.app_exceptions import YiviServerException


logger = logging.getLogger(__name__)


class YiviService:
    def __init__(
        self,
        yivi_internal_server_url: str,
        yivi_disclose_prefix: str,
        yivi_revocation: bool,
        http_timeout: int,
    ):
        self._yivi_internal_server_url = yivi_internal_server_url
        self._yivi_disclose_prefix = yivi_disclose_prefix
        self._yivi_revocation = yivi_revocation
        self._http_timeout = http_timeout

    def create_disclose_session(
        self, requested_disclosures: List[Dict[str, str]]
    ) -> str:
        discloses = []
        for item in requested_disclosures:
            disclose = {"type": f"{self._yivi_disclose_prefix}.{item['disclose_type']}"}
            if "disclose_value" in item:
                disclose["value"] = item["disclose_value"]
            discloses.append(disclose)
        yivi_session_request = {
            "@context": "https://irma.app/ld/request/disclosure/v2",
            "disclose": [[discloses]],
        }

        if self._yivi_revocation:
            yivi_session_request["revocation"] = [self._yivi_disclose_prefix]

        yivi_response = requests.post(
            f"{self._yivi_internal_server_url}/session",
            headers={"Content-Type": "application/json"},
            data=json.dumps(yivi_session_request),
            timeout=60,
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
            f"{self._yivi_internal_server_url}" + f"/session/{token}/result",
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
