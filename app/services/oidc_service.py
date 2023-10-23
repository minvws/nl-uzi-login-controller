import base64
import hashlib
import json
import secrets
from urllib.parse import urlencode
from typing import List

import requests
from redis import Redis
from starlette.responses import RedirectResponse

from app.utils import rand_pass, nonce


class OidcService:
    def __init__(
        self,
        redis_client: Redis,
        authorize_endpoint: str,  # TODO GB: Use wellkown endpoint
        token_endpoint: str,
        userinfo_endpoint: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: List[str],
    ):
        self._redis_client = redis_client
        self._authorize_endpoint = authorize_endpoint
        self._token_endpoint = token_endpoint
        self._userinfo_endpoint = userinfo_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes

    def get_authorize_response(
        self,
        exchange_token: str,
        state: str,
        redirect_url: str,
    ):
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
        self._redis_client.expire(redis_key, 60 * 5)

        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "scope": " ".join(self._scopes),
            "redirect_uri": self._redirect_uri,
            "state": oidc_state,
            "nonce": nonce(50),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }
        url = self._authorize_endpoint + "?" + urlencode(params)
        return RedirectResponse(
            url=url,
            status_code=303,
        )

    def get_userinfo(self, state, code):
        login_state = self._redis_client.get("oidc_state_" + state)
        login_state = json.loads(login_state)

        # TODO GB: error handling
        resp = requests.post(
            self._token_endpoint,
            timeout=30,
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
            self._userinfo_endpoint,
            timeout=30,
            headers={"Authorization": "Bearer " + resp.json()["access_token"]},
        )
        if resp.headers["Content-Type"] != "application/jwt":
            return Exception("Unsupported media type")
        # TODO GB: move redis cache to session_service
        return (resp.text, login_state)
