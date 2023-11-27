import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode
from typing import Union, Tuple, Dict

import requests
from fastapi.exceptions import RequestValidationError
from redis import Redis
from starlette.responses import RedirectResponse, JSONResponse
from app.exceptions import InvalidStateException, GeneralServerException
from app.models import OIDCProviderConfiguration
from app.utils import rand_pass, nonce, load_jwk
from app.services.jwt_service import JwtService

from configparser import ConfigParser

class OidcService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        redis_client: Redis,
        oidc_providers_well_known_config: Dict[str, OIDCProviderConfiguration],
        jwt_service: JwtService,
        client_secret: str,
        redirect_uri: str,
        http_timeout: int,
        cache_expire: int,
    ):
        self._redis_client = redis_client
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._http_timeout = http_timeout
        self._cache_expire = cache_expire
        self._oidc_providers_config = oidc_providers_well_known_config
        self._jwt_service = jwt_service


    def get_authorize_response(
        self,
        oidc_provider_name: str,
        exchange_token: str,
        state: str,
        scope: str,
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

        oidc_provider = self._oidc_providers_config[oidc_provider_name]["discovery"]
        client_id = self._oidc_providers_config[oidc_provider_name]["client_id"]

        if scope not in oidc_provider["scopes_supported"]:
            # TODO: FS add HTTP exceptions to the application
            raise GeneralServerException()

        params = {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(scope),
            "redirect_uri": self._redirect_uri,
            "state": oidc_state,
            "nonce": nonce(50),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }
        url = oidc_provider["authorization_endpoint"] + "?" + urlencode(params)
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
        oidc_provider = self._oidc_providers_config[oidc_provider_name]["discovery"]
        client_id = self._oidc_providers_config[oidc_provider_name]["client_id"]

        resp = requests.post(
            oidc_provider.token_endpoint,
            timeout=self._http_timeout,
            data={
                "code": code,
                "code_verifier": login_state["code_verifier"],
                "client_id": client_id,
                "client_secret": self._client_secret,
                "grant_type": "authorization_code",
                "redirect_uri": self._redirect_uri,
            },
        )

        resp = requests.get(
            oidc_provider.userinfo_endpoint,
            timeout=self._http_timeout,
            headers={"Authorization": "Bearer " + resp.json()["access_token"]},
        )
        if resp.headers["Content-Type"] != "application/jwt":
            raise RequestValidationError("Unsupported media type")
        # TODO GB: move redis cache to session_service
        return resp.text, login_state


    def test_jwe(self):
        config = ConfigParser()
        config.read("app.conf")

        oidc_jwt_key_path = config.get("oidc_provider", "jwt_pub_key_path")
        jwk = load_jwk(oidc_jwt_key_path)

        response = requests.get("http://localhost:8003/test", timeout=30)
        data = response.json()

        decrypted_data = self._jwt_service.from_jwe(jwk, data)


        return JSONResponse(
            decrypted_data
        )
