import json
import logging
import random
import string
from typing import Union

import requests
from fastapi.responses import JSONResponse
from redis import Redis
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK

from app.exceptions import (
    IrmaServerException,
    IrmaSessionExpired,
    IrmaSessionNotCompleted,
)

REDIS_IRMA_SESSION_KEY = "irma_session"


logger = logging.getLogger(__name__)


def rand_pass(size):
    generate_pass = "".join(
        [random.choice(string.ascii_lowercase + string.digits) for n in range(size)]
    )
    return generate_pass


class IrmaService:
    def __init__(
        self,
        redis_client: Redis,
        irma_internal_server_url: str,
        irma_disclose_prefix: str,
        redis_namespace: str,
        expires_in_s: int,
        jwt_issuer: str,
        jwt_issuer_crt_path: str,
        jwt_audience: str,
    ):
        self._redis_client = redis_client
        self._irma_internal_server_url = irma_internal_server_url
        self._irma_disclose_prefix = irma_disclose_prefix
        self._redis_namespace = redis_namespace
        self._expires_in_s = expires_in_s
        self._jwt_issuer = jwt_issuer
        self._jwt_audience = jwt_audience
        with open(jwt_issuer_crt_path, encoding="utf-8") as file:
            self._jwt_issuer_crt_path = JWK.from_pem(file.read().encode("utf-8"))

    def create_session(self, raw_jwt: str):
        exchange_token = rand_pass(64)
        discloses = []
        print(raw_jwt)
        jwt = JWT(
            jwt=raw_jwt,
            key=self._jwt_issuer_crt_path,
            check_claims={"iss": self._jwt_issuer, "aud": self._jwt_audience},
        )
        requested_disclosures = json.loads(jwt.claims)["disclosures"]
        print(requested_disclosures)
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
        self._redis_client.set(
            f"{self._redis_namespace}:{REDIS_IRMA_SESSION_KEY}:{exchange_token}",
            irma_response.text,
            ex=self._expires_in_s,
        )
        return JSONResponse(exchange_token)

    def fetch(self, exchange_token: str):
        fetched_irma_session: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_IRMA_SESSION_KEY}:{exchange_token}"
        )
        if not fetched_irma_session:
            raise IrmaSessionExpired()
        irma_session = json.loads(fetched_irma_session)
        return JSONResponse(irma_session["sessionPtr"])

    def result(self, exchange_token):
        fetched_irma_session: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_IRMA_SESSION_KEY}:{exchange_token}",
        )
        if not fetched_irma_session:
            raise IrmaSessionExpired()
        irma_session = json.loads(fetched_irma_session)
        irma_response = requests.get(
            f"{self._irma_internal_server_url}"
            + f"/session/{irma_session['token']}/result",
            timeout=60,
        )
        if irma_response.status_code >= 400:
            logger.error(
                "Error while fetching IrmaResponse, Irma server returned: %s, %s",
                irma_response.status_code,
                irma_response.text,
            )
            raise IrmaServerException()
        irma_json_response = irma_response.json()
        if irma_json_response["status"] != "DONE":
            logger.warning(
                "Fetching session result without finished irma session: irma_repsonse is: %s",
                irma_json_response,
            )
            raise IrmaSessionNotCompleted()
        disclosed_response = {}
        for item in irma_json_response["disclosed"][0]:
            disclosed_response[
                item["id"].replace(self._irma_disclose_prefix + ".", "")
            ] = item["rawvalue"]
        return JSONResponse(disclosed_response)
