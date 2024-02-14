from typing import Union, Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import Response, RedirectResponse

from uzireader.uzipassuser import UziPassUser  # type: ignore
from app.dependencies import session_service_, redirect_url_
from app.services.session_service import SessionService
from app.utils import enforce_cert_newlines

router = APIRouter(prefix="/login", tags=["Login"])


@router.get("/yivi/{exchange_token}")
def page(
    exchange_token: str,
    state: str,
    request: Request,
    redirect_url: str = Depends(lambda: redirect_url_),
    session_service: SessionService = Depends(lambda: session_service_),
) -> Response:
    """
    Fetch the login page
    """
    return session_service.login_irma(exchange_token, state, request, redirect_url)


@router.get("/uzi/{exchange_token}", response_model=None)
async def uzi_login(
    exchange_token: str,
    state: str,
    request: Request,
    redirect_url: str = Depends(lambda: redirect_url_),
    session_service: SessionService = Depends(lambda: session_service_),
) -> Union[RedirectResponse, HTTPException]:
    """
    Read cert from uzi card and login
    """
    cert = request.headers["x-proxy-ssl_client_cert"]
    if not cert:
        raise HTTPException(status_code=404)

    formatted_cert = enforce_cert_newlines(cert)
    user = UziPassUser(verify="SUCCESS", cert=formatted_cert)
    return session_service.login_uzi(
        exchange_token, state, redirect_url, user["UziNumber"]
    )


@router.get("/oidc/start/{exchange_token}", response_model=None)
async def oidc_login(
    exchange_token: str,
    state: str,
    redirect_url: str = Depends(lambda: redirect_url_),
    session_service: SessionService = Depends(lambda: session_service_),
) -> Union[Response, HTTPException]:
    return session_service.login_oidc(exchange_token, state, redirect_url)


@router.get("/oidc/callback", response_model=None)
async def callback_login(
    state: Optional[str] = None,
    code: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    session_service: SessionService = Depends(lambda: session_service_),
) -> Union[Response, HTTPException]:
    if error is not None:
        return session_service.fallback_error(error, error_description)

    if (state is not None) and (code is not None):
        return session_service.login_oidc_callback(state, code)

    return session_service.fallback_error("invalid_request")
