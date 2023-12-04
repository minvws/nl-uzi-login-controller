import json
import logging
import time
from typing import Union

from configparser import ConfigParser
from fastapi.responses import JSONResponse
from fastapi import Request, HTTPException
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
    InvalidStateException,
)
from app.models.session import Session, SessionType, SessionStatus, SessionLoa
from app.services.irma_service import IrmaService
from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from app.utils import rand_pass

REDIS_SESSION_KEY = "session"
SESSION_NOT_FOUND_ERROR = "session%20not%20found"


logger = logging.getLogger(__name__)
config = ConfigParser()
config.read("app.conf")

templates = Jinja2Templates(directory="jinja2")


# pylint: disable=too-many-instance-attributes
class SessionService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        redis_client: Redis,
        irma_service: IrmaService,
        oidc_service: OidcService,
        jwt_service: JwtService,
        irma_disclose_prefix: str,
        redis_namespace: str,
        expires_in_s: int,
        jwt_issuer: str,
        jwt_issuer_crt_path: str,
        jwt_audience: str,
        mock_enabled: bool,
        oidc_provider_pub_key: JWK,
        session_server_events_enabled: bool = False,
        session_server_events_timeout: int = 2000,
        session_polling_interval: int = 1000,
    ):
        self._redis_client = redis_client
        self._irma_service = irma_service
        self._oidc_service = oidc_service
        self._jwt_service = jwt_service
        self._irma_disclose_prefix = irma_disclose_prefix
        self._redis_namespace = redis_namespace
        self._expires_in_s = expires_in_s
        self._jwt_issuer = jwt_issuer
        self._jwt_audience = jwt_audience
        with open(jwt_issuer_crt_path, encoding="utf-8") as file:
            self._jwt_issuer_crt_path = JWK.from_pem(file.read().encode("utf-8"))
        self._mock_enabled = mock_enabled
        self._oidc_provider_pub_key = oidc_provider_pub_key
        self._session_server_events_enabled = session_server_events_enabled
        self._session_server_events_timeout = session_server_events_timeout
        self._session_polling_interval = session_polling_interval

    def create(self, raw_jwt: str) -> JSONResponse:
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

    def irma(self, exchange_token: str) -> JSONResponse:
        session = self._token_to_session(exchange_token)
        if session.irma_disclose_response is None:
            raise IrmaServerException()
        irma_session = json.loads(session.irma_disclose_response)
        return JSONResponse(irma_session["sessionPtr"])

    def status(self, exchange_token: str) -> JSONResponse:
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

    def _poll_status_irma(self, session: Session) -> None:
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

    def result(self, exchange_token: str) -> Response:
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

    def login_irma(
        self, exchange_token: str, state: str, request: Request, redirect_url: str
    ) -> Response:
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
                "base_url": config.get("app", "base_url"),
                "session_polling_interval": self._session_polling_interval,
                "session_server_events_enabled": self._session_server_events_enabled,
                "session_server_events_timeout": self._session_server_events_timeout,
            },
        )

    def login_uzi(
        self, exchange_token: str, state: str, redirect_url: str, uzi_id: str
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

    def login_oidc(
        self,
        exchange_token: str,
        state: str,
        redirect_url: str,
    ) -> Union[RedirectResponse, HTTPException]:
        session: Session = self._get_session_from_redis(exchange_token)
        oidc_provider_name = session.oidc_provider_name

        if not oidc_provider_name:
            logger.warning("OIDC Provider name not found")
            return HTTPException(status_code=404)

        return self._oidc_service.get_authorize_response(
            oidc_provider_name, exchange_token, state, redirect_url
        )

    def login_oidc_callback(
        self, state: str, code: str
    ) -> Union[RedirectResponse, HTTPException]:
        login_state = self._get_login_state_from_redis(state)
        exchange_token = login_state["exchange_token"]
        redirect_url = login_state["redirect_url"]
        state = login_state["state"]

        session = self._get_session_from_redis(exchange_token)
        if not session:
            return RedirectResponse(
                url=f"{redirect_url}?state={state}&error={SESSION_NOT_FOUND_ERROR}",
                status_code=403,
            )
        if not session.session_type == SessionType.OIDC:
            logger.warning("Session type is not OIDC")
            return HTTPException(status_code=404)

        oidc_provider_name: str = session.oidc_provider_name  # type: ignore
        userinfo_jwt = self._oidc_service.get_userinfo(
            oidc_provider_name, code, login_state
        )
        claims = self._jwt_service.from_jwe(self._oidc_provider_pub_key, userinfo_jwt)

        session.session_status = SessionStatus.DONE
        session.uzi_id = claims["signed_uzi_number"]
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

    def _get_session_from_redis(self, exchange_token: str) -> Session:
        session_str: Union[str, bytes] = self._redis_client.get(  # type: ignore
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{exchange_token}",
        )
        session: Session = Session.parse_raw(session_str)
        return session

    def _get_login_state_from_redis(self, state: str) -> dict:
        login_state_from_redis: Union[str, None] = self._redis_client.get(
            "oidc_state_" + state
        )
        if not login_state_from_redis:
            raise InvalidStateException()

        login_state: dict = json.loads(login_state_from_redis)
        if not login_state:
            raise InvalidStateException()

        return login_state
