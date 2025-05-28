# pylint: disable=too-many-lines
import json
import logging
import time
from typing import Union, Optional, Dict, Any
import secrets
import hashlib
import base64

from configparser import ConfigParser

from fastapi.responses import JSONResponse
from fastapi import Request, HTTPException
from redis import Redis
from jwcrypto.jwk import JWK
from starlette.responses import RedirectResponse, Response

from app.constants import EXP_LEAP_SECONDS, NBF_LEAP_SECONDS
from app.exceptions.app_exceptions import (
    GeneralServerException,
    YiviServerException,
    SessionExpired,
    SessionNotCompleted,
    LoginStateNotFoundException,
    SessionNotFoundException,
    InvalidJWTException,
    ServiceUnavailableException,
    InvalidRequestException,
)

from app.models.session import (
    Session,
    SessionType,
    SessionStatus,
    SessionLoa,
    parse_session_type,
)
from app.services.yivi_service import YiviService
from app.services.jwt_service import from_jwt
from app.services.oidc_service import OidcService
from app.services.template_service import TemplateService
from app.utils import rand_pass
from app.models.login_state import LoginState

REDIS_SESSION_KEY = "session"

logger = logging.getLogger(__name__)
config = ConfigParser()
config.read("app.conf")


# pylint: disable=too-many-instance-attributes
class SessionService:
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        redis_client: Redis,
        yivi_service: YiviService,
        oidc_service: Optional[OidcService],
        yivi_disclose_prefix: str,
        redis_namespace: str,
        expires_in_s: int,
        jwt_issuer: str,
        jwt_issuer_crt: JWK,
        jwt_audience: str,
        register_api_crt: JWK,
        session_result_jwt_issuer: str,
        session_result_jwt_audience: str,
        signed_userinfo_issuer: Optional[str],
        template_service: TemplateService,
        session_server_events_enabled: bool = False,
        session_server_events_timeout: int = 2000,
        session_polling_interval: int = 1000,
    ):
        self._templates = template_service.templates
        self._redis_client = redis_client
        self._yivi_service = yivi_service
        self._oidc_service = oidc_service
        self._yivi_disclose_prefix = yivi_disclose_prefix
        self._redis_namespace = redis_namespace
        self._expires_in_s = expires_in_s
        self._jwt_issuer = jwt_issuer
        self._jwt_issuer_crt = jwt_issuer_crt
        self._jwt_audience = jwt_audience
        self._session_server_events_enabled = session_server_events_enabled
        self._session_server_events_timeout = session_server_events_timeout
        self._session_polling_interval = session_polling_interval
        self._register_api_crt = register_api_crt
        self._session_result_jwt_issuer = session_result_jwt_issuer
        self._session_result_jwt_audience = session_result_jwt_audience
        self._signed_userinfo_issuer = signed_userinfo_issuer

    def create(self, request: Request) -> JSONResponse:
        raw_jwt = self._get_token_from_header(request)
        claims = from_jwt(
            jwt_pub_key=self._jwt_issuer_crt,
            jwt_str=raw_jwt,
            check_claims={
                "iss": self._jwt_issuer,
                "aud": self._jwt_audience,
                "exp": time.time(),
                "nbf": time.time(),
            },
        )

        session = self._create_session_from_claims(claims)

        if session.session_type == SessionType.OIDC and self._oidc_service is None:
            return JSONResponse(
                status_code=400, content={"message": "Login method not allowed"}
            )

        if session.session_type == SessionType.YIVI:
            session.yivi_disclose_response = self._yivi_service.create_disclose_session(
                [
                    {"disclose_type": "uziId"},
                    {"disclose_type": "roles"},
                    {"disclose_type": "loaAuthn"},
                ],
            )

        self._redis_client.set(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{session.exchange_token}",
            session.model_dump_json(),
            ex=self._expires_in_s,
        )
        return JSONResponse(session.exchange_token)

    def yivi(self, exchange_token: str) -> JSONResponse:
        session = self._token_to_session(exchange_token)
        if session.yivi_disclose_response is None:
            raise YiviServerException()
        yivi_session = json.loads(session.yivi_disclose_response)
        return JSONResponse(yivi_session["sessionPtr"])

    def status(self, request: Request) -> Response:
        exchange_token_jwt = self._get_token_from_header(request)

        exchange_token_claims = from_jwt(
            jwt_pub_key=self._jwt_issuer_crt,
            jwt_str=exchange_token_jwt,
            check_claims={
                "iss": self._jwt_issuer,
                "aud": self._jwt_audience,
                "nbf": int(time.time()) - NBF_LEAP_SECONDS,
                "exp": int(time.time()) + EXP_LEAP_SECONDS,
            },
        )
        if exchange_token_claims is None:
            logger.error("Exchange token claims are invalid")
            raise GeneralServerException()

        exchange_token = exchange_token_claims.get("exchange_token", "")
        session = self._token_to_session(exchange_token)
        self._poll_status_yivi(session)
        return JSONResponse(session.session_status)

    def _token_to_session(self, token: str) -> Session:
        session_str: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{token}",
        )
        if not session_str:
            raise SessionExpired()
        session = Session.model_validate_json(session_str)
        return session

    def _poll_status_yivi(self, session: Session) -> None:
        if session.session_status == SessionStatus.DONE:
            return

        if session.session_type == SessionType.YIVI:
            if session.yivi_disclose_response is None:
                raise YiviServerException()
            yivi_session_result = self._yivi_service.fetch_disclose_result(
                json.loads(session.yivi_disclose_response)["token"]
            )
            if yivi_session_result["status"] == "DONE":
                session.yivi_session_result = yivi_session_result
                for item in session.yivi_session_result["disclosed"][0]:  # type: ignore
                    if (
                        item["id"].replace(self._yivi_disclose_prefix + ".", "")
                        == "uziId"
                    ):
                        session.uzi_id = item["rawvalue"]

                    if (
                        item["id"].replace(self._yivi_disclose_prefix + ".", "")
                        == "loaAuthn"
                    ):
                        session.loa_authn = item["rawvalue"]

                self._redis_client.set(
                    f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{session.exchange_token}",
                    session.model_dump_json(),
                    ex=self._expires_in_s,
                )
                session.session_status = SessionStatus.DONE

    def result(self, request: Request) -> Response:
        exchange_token_jwt = self._get_token_from_header(request)
        exchange_token_claims = from_jwt(
            jwt_pub_key=self._register_api_crt,
            jwt_str=exchange_token_jwt,
            check_claims={
                "iss": self._session_result_jwt_issuer,
                "aud": self._session_result_jwt_audience,
                "nbf": int(time.time()) - NBF_LEAP_SECONDS,
                "exp": int(time.time()) + EXP_LEAP_SECONDS,
            },
        )

        if exchange_token_claims is None:
            logger.error("Exchange token claims are invalid")
            raise GeneralServerException()

        exchange_token: str = exchange_token_claims["exchange_token"]

        session = self._token_to_session(exchange_token)

        self._poll_status_yivi(session)
        if session.session_status != SessionStatus.DONE:
            raise SessionNotCompleted()
        if session.uzi_id is None:
            raise GeneralServerException()
        return JSONResponse({"uzi_id": session.uzi_id, "loa_authn": session.loa_authn})

    def login_yivi(
        self, exchange_token: str, state: str, request: Request, redirect_url: str
    ) -> Response:
        session_str: Union[str, None] = self._redis_client.get(
            f"{self._redis_namespace}:{REDIS_SESSION_KEY}:{exchange_token}",
        )
        if not session_str:
            raise SessionNotFoundException(state=state)

        session = Session.model_validate_json(session_str)
        return self._templates.TemplateResponse(
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

        session: Session = Session.model_validate_json(session_str)
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
        if self._oidc_service is None:
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
        if self._oidc_service is None:
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

        oidc_provider_name = session.oidc_provider_name
        if oidc_provider_name is None:
            raise InvalidRequestException(
                state=state, error_description="missing OIDC provider name in session"
            )

        oidc_provider_userinfo_jwt = self._oidc_service.get_userinfo(
            oidc_provider_name, code, code_verifier, state
        )

        signed_userinfo = from_jwt(
            self._register_api_crt,
            oidc_provider_userinfo_jwt["signed_userinfo"],
            {
                "iss": self._signed_userinfo_issuer,
                "exp": time.time(),
                "nbf": time.time(),
            },
        )
        if signed_userinfo is None:
            raise InvalidJWTException(
                state=state, error_description="Invalid signed_userinfo claim"
            )

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

        session: Session = Session.model_validate_json(session_str)
        return session

    def _get_login_state_from_redis(self, state: str) -> Optional[LoginState]:
        login_state_from_redis: Union[str, None] = self._redis_client.get(
            "oidc_state_" + state
        )
        if not login_state_from_redis:
            return None

        login_state = LoginState(**json.loads(login_state_from_redis))
        return login_state

    def _create_session_from_claims(
        self, claims: Optional[Dict[str, Any]] = None
    ) -> Session:
        if claims is None:
            raise HTTPException(status_code=400, detail="Invalid session JWT")

        session_type = parse_session_type(claims.get("session_type"))
        if session_type is None:
            raise HTTPException(status_code=400, detail="Invalid session JWT")

        return Session(
            exchange_token=rand_pass(64),
            session_status=SessionStatus.INITIALIZED,
            session_type=session_type,
            login_title=claims["login_title"],
            oidc_provider_name=claims.get("oidc_provider_name"),
        )

    @staticmethod
    def _get_token_from_header(request: Request) -> str:
        token = request.headers.get("Authorization")
        if token is None:
            logger.error("Token jwt is not found in header")
            raise GeneralServerException()

        jwt = token.split("Bearer ")[1]
        return jwt
