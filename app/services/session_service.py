import base64
import hashlib
import json
import logging
import random
import secrets
import string
import time
from typing import Union
import requests

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from redis import Redis
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from app.exceptions import (
    IrmaSessionExpired,
    IrmaSessionNotCompleted,
    IrmaServerException,
    GeneralServerException,
)
from app.models import Session, SessionType, SessionStatus, SessionLoa
from app.services.irma_service import IrmaService

REDIS_SESSION_KEY = "session"
SESSION_NOT_FOUND_ERROR = "session%20not%20found"


logger = logging.getLogger(__name__)


def rand_pass(size):
    generate_pass = "".join(
        [random.choice(string.ascii_lowercase + string.digits) for _ in range(size)]
    )
    return generate_pass


templates = Jinja2Templates(directory="jinja2")


# pylint: disable=too-many-instance-attributes
class SessionService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        redis_client: Redis,
        irma_service: IrmaService,
        irma_disclose_prefix: str,
        redis_namespace: str,
        expires_in_s: int,
        jwt_issuer: str,
        jwt_issuer_crt_path: str,
        jwt_audience: str,
        mock_enabled: bool,
        session_server_events_enabled: bool = False,
        session_server_events_timeout: int = 2000,
        session_polling_interval: int = 1000,
    ):
        self._redis_client = redis_client
        self._irma_service = irma_service
        self._irma_disclose_prefix = irma_disclose_prefix
        self._redis_namespace = redis_namespace
        self._expires_in_s = expires_in_s
        self._jwt_issuer = jwt_issuer
        self._jwt_audience = jwt_audience
        with open(jwt_issuer_crt_path, encoding="utf-8") as file:
            self._jwt_issuer_crt_path = JWK.from_pem(file.read().encode("utf-8"))
        self._mock_enabled = mock_enabled
        self._session_server_events_enabled = session_server_events_enabled
        self._session_server_events_timeout = session_server_events_timeout
        self._session_polling_interval = session_polling_interval

    def create(self, raw_jwt: str):
        jwt = JWT(
            jwt=raw_jwt,
            key=self._jwt_issuer_crt_path,
            check_claims={
                "iss": self._jwt_issuer,
                "aud": self._jwt_audience,
                "exp": time.time(),
                "nbf": time.time(),
            },
        )
        claims = json.loads(jwt.claims)
        session = Session(
            exchange_token=rand_pass(64),
            session_status=SessionStatus.INITIALIZED,
            **claims,
        )

        if session.session_type == SessionType.IRMA:
            session.irma_disclose_response = self._irma_service.create_disclose_session(
                [
                    {"disclose_type": "uziId"},
                    {"disclose_type": "roles"},
                    {"disclose_type": "loaAuthn"},
                ],
            )

        self._redis_client.set(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{session.exchange_token}",
            session.json(),
            ex=self._expires_in_s,
        )
        return JSONResponse(session.exchange_token)

    def irma(self, exchange_token: str):
        session = self._token_to_session(exchange_token)
        if session.irma_disclose_response is None:
            raise IrmaServerException()
        irma_session = json.loads(session.irma_disclose_response)
        return JSONResponse(irma_session["sessionPtr"])

    def status(self, exchange_token):
        session = self._token_to_session(exchange_token)
        self._poll_status_irma(session)
        return JSONResponse(session.session_status)

    def _token_to_session(self, token: str) -> Session:
        session_str: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{token}",
        )
        if not session_str:
            raise IrmaSessionExpired()
        session = Session.parse_raw(session_str)
        return session

    def _poll_status_irma(self, session: Session):
        if session.session_status == SessionStatus.DONE:
            return

        if session.session_type == SessionType.IRMA:
            if session.irma_disclose_response is None:
                raise IrmaServerException()
            irma_session_result = self._irma_service.fetch_disclose_result(
                json.loads(session.irma_disclose_response)["token"]
            )
            if irma_session_result["status"] == "DONE":
                session.irma_session_result = irma_session_result
                for item in session.irma_session_result["disclosed"][0]:  # type: ignore
                    if (
                        item["id"].replace(self._irma_disclose_prefix + ".", "")
                        == "uziId"
                    ):
                        session.uzi_id = item["rawvalue"]

                    if (
                        item["id"].replace(self._irma_disclose_prefix + ".", "")
                        == "loaAuthn"
                    ):
                        session.loa_authn = item["rawvalue"]

                self._redis_client.set(
                    f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{session.exchange_token}",
                    session.json(),
                    ex=self._expires_in_s,
                )
                session.session_status = SessionStatus.DONE

    def result(self, exchange_token) -> Response:
        if self._mock_enabled and exchange_token == "mocked_exchange_token":
            return JSONResponse(
                {"uzi_id": "123456789", "loa_authn": SessionLoa.SUBSTANTIAL}
            )
        session = self._token_to_session(exchange_token)
        self._poll_status_irma(session)
        if session.session_status != SessionStatus.DONE:
            raise IrmaSessionNotCompleted()
        if session.uzi_id is None:
            raise GeneralServerException()
        return JSONResponse({"uzi_id": session.uzi_id, "loa_authn": session.loa_authn})

    def login_irma(self, exchange_token, state, request, redirect_url) -> Response:
        session_str: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{exchange_token}",
        )
        if not session_str:
            return RedirectResponse(
                url=f"{redirect_url}?state={state}&error={SESSION_NOT_FOUND_ERROR}",
                status_code=403,
            )
        session = Session.parse_raw(session_str)
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "exchange_token": session.exchange_token,
                "login_title": session.login_title,
                "state": state,
                "redirect_url": redirect_url,
                "session_polling_interval": self._session_polling_interval,
                "session_server_events_enabled": self._session_server_events_enabled,
                "session_server_events_timeout": self._session_server_events_timeout,
            },
        )

    def login_uzi(
        self, exchange_token, state, redirect_url, uzi_id
    ) -> Union[RedirectResponse, HTTPException]:
        session_str: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{exchange_token}",
        )
        if not session_str:
            return RedirectResponse(
                url=f"{redirect_url}?state={state}&error={SESSION_NOT_FOUND_ERROR}",
                status_code=403,
            )

        session: Session = Session.parse_raw(session_str)
        if not session.session_type == SessionType.UZI_CARD:
            return HTTPException(status_code=404)
        session.session_status = SessionStatus.DONE
        session.uzi_id = uzi_id
        session.loa_authn = SessionLoa.HIGH

        self._redis_client.set(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{session.exchange_token}",
            session.json(),
            ex=self._expires_in_s,
        )

        return RedirectResponse(
            url=f"{redirect_url}?state={state}&exchange_token={session.exchange_token}",
            status_code=303,
        )

    def login_oidc(self):
        # code_verifier = secrets.token_urlsafe(96)[:64]
        # hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()
        # encoded = base64.urlsafe_b64encode(hashed)
        # code_challenge = encoded.decode('ascii')[:-1]
        # print("code:" + code_verifier)
        # print("challenge:" + code_challenge)
        # raise HTTPException(status_code=404)
        # code:EqRtmQ-m0hG7S6uJjQIyQYMze9lEDch0UbRJ9jmMyYFgbORMRdzrA4wE9F2cEqtK
        # challenge:2wsLrZz80Ez11hD5nV4ygJ8HiwoI3oWTj9wISurXcnk
        return RedirectResponse(
            url="https://accounts.google.com/o/oauth2/v2/auth?client_id=857185457066-vtl87j07d7e7f1783ma5u5u4c83ck56s.apps.googleusercontent.com&response_type=code&scope=openid%20email&redirect_uri=http://localhost:12003/login/oidc/callback&state=c3RhdGU=&nonce=M_lY4gz2tEAzm65Ql7_5-1X7CpNwbuDijhjeDbn4Hgk&code_challenge_method=S256&code_challenge=2wsLrZz80Ez11hD5nV4ygJ8HiwoI3oWTj9wISurXcnk",
            status_code=303,
        )

    def login_oidc_callback(self, code: str):
        print("code", code)
        print("code_verifier", "EqRtmQ-m0hG7S6uJjQIyQYMze9lEDch0UbRJ9jmMyYFgbORMRdzrA4wE9F2cEqtK")
        resp = requests.post(
            "https://oauth2.googleapis.com/token",
            timeout=30,
            data={
                "code": code,
                "code_verifier": "EqRtmQ-m0hG7S6uJjQIyQYMze9lEDch0UbRJ9jmMyYFgbORMRdzrA4wE9F2cEqtK",
                "client_id": "857185457066-vtl87j07d7e7f1783ma5u5u4c83ck56s.apps.googleusercontent.com",
                "client_secret": "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",
                "grant_type": "authorization_code",
                "redirect_uri": "http://localhost:12003/login/oidc/callback",
            }
        )

        resp = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            timeout=30,
            headers={
                "Authorization": "Bearer " + resp.json()["access_token"]
            }
        )

        # https://openidconnect.googleapis.com/v1/userinfo
        result = resp.json()
        print(resp.status_code)
        print(result["email"])
        raise HTTPException(status_code=404)
