import json
import logging
from typing import Dict, List

import requests

from app.exceptions import (
    IrmaServerException,
)


logger = logging.getLogger(__name__)


class IrmaService:
    def __init__(
        self,
        irma_internal_server_url: str,
        irma_disclose_prefix: str,
    ):
        self._irma_internal_server_url = irma_internal_server_url
        self._irma_disclose_prefix = irma_disclose_prefix

    def create_disclose_session(
        self, requested_disclosures: List[Dict[str, str]]
    ) -> str:
        discloses = []
        for item in requested_disclosures:
            disclose = {"type": f"{self._irma_disclose_prefix}.{item['disclose_type']}"}
            if "disclose_value" in item:
                disclose["value"] = item["disclose_value"]
            discloses.append(disclose)
        irma_session_request = {
            "@context": "https://irma.app/ld/request/disclosure/v2",
            "disclose": [[discloses]],
        }
        irma_response = requests.post(
            f"{self._irma_internal_server_url}/session",
            headers={"Content-Type": "application/json"},
            data=json.dumps(irma_session_request),
            timeout=60,
        )
        if irma_response.status_code >= 400:
            logger.error(
                "Error while fetching IrmaResponse, Irma server returned: %s, %s",
                irma_response.status_code,
                irma_response.text,
            )
            raise IrmaServerException()
        return irma_response.text

    def fetch_disclose_result(self, token: str):
        irma_response = requests.get(
            f"{self._irma_internal_server_url}" + f"/session/{token}/result",
            timeout=30,
        )
        if irma_response.status_code >= 400:
            logger.error(
                "Error while fetching IrmaResponse, Irma server returned: %s, %s",
                irma_response.status_code,
                irma_response.text,
            )
            raise IrmaServerException()
        irma_json_response = irma_response.json()
        return irma_json_response
