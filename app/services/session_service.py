import json
import logging
import time
from typing import Union, Optional
import secrets
import hashlib
import base64

from configparser import ConfigParser

from fastapi.responses import JSONResponse
from fastapi import Request, HTTPException
from redis import Redis
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from app.exceptions.app_exceptions import (
    GeneralServerException,
    IrmaServerException,
    IrmaSessionExpired,
    IrmaSessionNotCompleted,
    LoginStateNotFoundException,
    SessionNotFoundException,
    InvalidJWTException,
    ServiceUnavailableException,
    InvalidRequestException,
    ProviderPublicKeyNotFound,
)

from app.models.session import Session, SessionType, SessionStatus, SessionLoa
from app.services.irma_service import IrmaService
from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from app.utils import rand_pass
from app.models.login_state import LoginState

REDIS_SESSION_KEY = "session"

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
        oidc_service: Optional[OidcService],
        jwt_service: Optional[JwtService],
        irma_disclose_prefix: str,
        redis_namespace: str,
        expires_in_s: int,
        jwt_issuer: str,
        jwt_issuer_crt_path: str,
        jwt_audience: str,
        register_api_crt: Optional[JWK],
        register_api_issuer: Optional[str],
        mock_enabled: bool,
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
        self._session_server_events_enabled = session_server_events_enabled
        self._session_server_events_timeout = session_server_events_timeout
        self._session_polling_interval = session_polling_interval
        self._register_api_crt = register_api_crt
        self._register_api_issuer = register_api_issuer

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
            raise SessionNotFoundException(state=state)

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
            raise SessionNotFoundException(state=state)

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
    ) -> Union[Response, HTTPException]:
        # check if oidc_login_method_feature is enabled
        if self._oidc_service is None or self._jwt_service is None:
            return Response(status_code=404)

        session = self._get_session_from_redis(exchange_token)
        if session is None:
            raise SessionNotFoundException(state)

        oidc_provider_name = session.oidc_provider_name
        if not oidc_provider_name:
            logger.warning("OIDC Provider name not found")
            return HTTPException(status_code=404)

        code_verifier = secrets.token_urlsafe(96)[:64]
        hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
        encoded = base64.urlsafe_b64encode(hashed)
        code_challenge = encoded.decode("ascii")[:-1]

        oidc_state = rand_pass(100)
        login_state = LoginState(
            exchange_token=exchange_token,
            state=state,
            code_verifier=code_verifier,
            redirect_url=redirect_url,
        )

        redis_key = "oidc_state_" + oidc_state
        self._redis_client.set(redis_key, json.dumps(login_state.to_dict()))
        self._redis_client.expire(redis_key, self._expires_in_s)

        return self._oidc_service.get_authorize_response(
            oidc_provider_name, code_challenge, oidc_state, state
        )

    def login_oidc_callback(
        self, oidc_state: str, code: str
    ) -> Union[Response, HTTPException]:
        # check if oidc_login_method_feature is enabled
        if (
            self._oidc_service is None
            or self._jwt_service is None
            or self._register_api_crt is None
        ):
            return Response(status_code=404)

        login_state = self._get_login_state_from_redis(oidc_state)
        if login_state is None:
            raise LoginStateNotFoundException()

        (
            exchange_token,
            state,
            code_verifier,
            redirect_url,
        ) = login_state.to_dict().values()

        session = self._get_session_from_redis(exchange_token)
        if not session:
            raise SessionNotFoundException(state)

        if not session.session_type == SessionType.OIDC:
            logger.warning("Session type is not OIDC")
            return HTTPException(status_code=404)

        oidc_provider_name: str = session.oidc_provider_name  # type: ignore
        userinfo_jwt = self._oidc_service.get_userinfo(
            oidc_provider_name, code, code_verifier, state
        )

        oidc_provider_public_key = self._oidc_service.get_oidc_provider_public_key(
            oidc_provider_name
        )
        if oidc_provider_public_key is None:
            raise ProviderPublicKeyNotFound(state)

        claims = self._jwt_service.from_jwe(oidc_provider_public_key, userinfo_jwt)
        if claims is None:
            raise InvalidJWTException(state=state)

        signed_userinfo = self._jwt_service.from_jwt(
            self._register_api_crt,
            claims["signed_userinfo"],
            {"iss": self._register_api_issuer, "exp": time.time(), "nbf": time.time()},
        )
        if signed_userinfo is None:
            raise InvalidJWTException(state=state)

        session.session_status = SessionStatus.DONE
        session.uzi_id = signed_userinfo["uzi_id"]
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

    def handle_oidc_callback(
        self,
        oidc_state: str,
        code: Optional[str] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ) -> Union[Response, HTTPException]:
        login_state = self._get_login_state_from_redis(oidc_state)
        if login_state is None:
            raise LoginStateNotFoundException()

        if error is not None:
            raise ServiceUnavailableException(login_state.state, error_description)

        if oidc_state is not None and code is not None:
            return self.login_oidc_callback(oidc_state, code)

        raise InvalidRequestException(login_state.state, error_description)

    def _get_session_from_redis(self, exchange_token: str) -> Optional[Session]:
        session_str: Union[str, bytes] = self._redis_client.get(  # type: ignore
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{exchange_token}",
        )
        if not session_str:
            return None

        session: Session = Session.parse_raw(session_str)
        return session

    def _get_login_state_from_redis(self, state: str) -> Optional[LoginState]:
        login_state_from_redis: Union[str, None] = self._redis_client.get(
            "oidc_state_" + state
        )
        if not login_state_from_redis:
            return None

        login_state = LoginState(**json.loads(login_state_from_redis))
        return login_state
