import textwrap
from typing import Union

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, Response, RedirectResponse

from uzireader.uzipassuser import UziPassUser  # type: ignore
from app.dependencies import session_service_, redirect_url_
from app.exceptions import IrmaSessionExpired
from app.services.session_service import SessionService

router = APIRouter()


@router.post("/session")
async def session(
    request: Request,
    session_service: SessionService = Depends(lambda: session_service_),
) -> JSONResponse:
    """
    Create a new IRMA session
    """
    request_body = await request.body()
    if isinstance(request_body, bytes):
        return session_service.create(request_body.decode("utf-8"))
    raise HTTPException(status_code=403, detail="No valid content provided")


@router.get("/session/{exchange_token}/status")
async def session_status(
    exchange_token: str,
    session_service: SessionService = Depends(lambda: session_service_),
) -> JSONResponse:
    """
    Get the status of a session
    """
    try:
        return session_service.status(exchange_token)
    except IrmaSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/session/{exchange_token}/yivi")
def irma_session(
    exchange_token: str,
    session_service: SessionService = Depends(lambda: session_service_),
) -> JSONResponse:
    """
    Get the IRMA response from a session
    """
    try:
        return session_service.irma(exchange_token)
    except IrmaSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/session/{exchange_token}/result")
def result(
    exchange_token: str,
    session_service: SessionService = Depends(lambda: session_service_),
) -> Response:
    """
    Fetch the session result
    """
    try:
        return session_service.result(exchange_token)
    except IrmaSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/login/yivi/{exchange_token}")
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


def enforce_cert_newlines(cert_data: str) -> str:
    cert_data = (
        cert_data.split("-----BEGIN CERTIFICATE-----")[-1]
        .split("-----END CERTIFICATE-----")[0]
        .strip()
    )
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(textwrap.wrap(cert_data.replace(" ", ""), 64))
        + "\n-----END CERTIFICATE-----"
    )


@router.get("/login/uzi/{exchange_token}", response_model=None)
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


@router.get("/login/oidc/{exchange_token}")
async def oidc_login(
    # oidc_provider_name: str,
    exchange_token: str,
    state: str,
    redirect_url: str = Depends(lambda: redirect_url_),
    session_service: SessionService = Depends(lambda: session_service_),
) -> RedirectResponse:
    return session_service.login_oidc(exchange_token, state, redirect_url)


@router.get("/login/oidc/callback/{oidc_provider_name}", response_model=None)
async def callback_login(
    oidc_provider_name: str,
    state: str,
    code: str,
    session_service: SessionService = Depends(lambda: session_service_),
) -> Union[RedirectResponse, HTTPException]:
    return session_service.login_oidc_callback(oidc_provider_name, state, code)
