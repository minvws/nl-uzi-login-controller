import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode
from typing import Union, Tuple, Dict

import requests
from fastapi.exceptions import RequestValidationError
from redis import Redis
from starlette.responses import RedirectResponse
from app.exceptions import InvalidStateException
from app.models import OIDCProviderConfiguration
from app.utils import rand_pass, nonce


class OidcService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        redis_client: Redis,
        oidc_providers_well_known_config: Dict[str, OIDCProviderConfiguration],
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        http_timeout: int,
        cache_expire: int,
    ):
        self._redis_client = redis_client
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._http_timeout = http_timeout
        self._cache_expire = cache_expire
        self.oidc_providers_config = oidc_providers_well_known_config

    def get_authorize_response(
        self,
        oidc_provider_name: str,
        exchange_token: str,
        state: str,
        redirect_url: str,
    ) -> RedirectResponse:
        code_verifier = secrets.token_urlsafe(96)[:64]
        hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode("ascii")[:-1]

        oidc_state = rand_pass(100)
        login_state = {
            "exchange_token": exchange_token,
            "state": state,
            "code_verifier": code_verifier,
            "redirect_url": redirect_url,
        }

        redis_key = "oidc_state_" + oidc_state
        self._redis_client.set(redis_key, json.dumps(login_state))
        self._redis_client.expire(redis_key, self._cache_expire)

        provider = self.oidc_providers_config[oidc_provider_name]

        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "scope": " ".join(provider["scopes_supported"]),
            "redirect_uri": self._redirect_uri,
            "state": oidc_state,
            "nonce": nonce(50),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }
        authorize_endpoint = provider["authorize_endpoint"]
        url = authorize_endpoint + "?" + urlencode(params)
        return RedirectResponse(
            url=url,
            status_code=303,
        )

    def get_userinfo(
        self, oidc_provider_name: str, state: str, code: str
    ) -> Tuple[str, dict]:
        login_state_from_redis: Union[str, None] = self._redis_client.get(
            "oidc_state_" + state
        )
        if not login_state_from_redis:
            raise InvalidStateException()
        login_state: dict = json.loads(login_state_from_redis)
        if not login_state:
            raise InvalidStateException()

        # TODO GB: error handling
        oidc_provider = self.oidc_providers_config[oidc_provider_name]
        token_endpoint = oidc_provider["token_endpoint"]
        userinfo_endpoint = oidc_provider["userinfo_endpoint"]

        resp = requests.post(
            token_endpoint,
            timeout=self._http_timeout,
            data={
                "code": code,
                "code_verifier": login_state["code_verifier"],
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "authorization_code",
                "redirect_uri": self._redirect_uri,
            },
        )

        resp = requests.get(
            userinfo_endpoint,
            timeout=self._http_timeout,
            headers={"Authorization": "Bearer " + resp.json()["access_token"]},
        )
        if resp.headers["Content-Type"] != "application/jwt":
            raise RequestValidationError("Unsupported media type")
        # TODO GB: move redis cache to session_service
        return resp.text, login_state
