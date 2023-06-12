import textwrap
from fastapi import APIRouter, Depends, Request, HTTPException

from uzireader.uzipassuser import UziPassUser  # type: ignore
from app.dependencies import session_service_, redirect_url_
from app.exceptions import IrmaSessionExpired
from app.services.session_service import SessionService

router = APIRouter()


@router.post("/session")
async def session(
    request: Request,
    session_service: SessionService = Depends(lambda: session_service_),
):
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
):
    """
    Get the status of a session
    """
    try:
        return session_service.status(exchange_token)
    except IrmaSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/session/{exchange_token}/irma")
def irma_session(
    exchange_token: str,
    session_service: SessionService = Depends(lambda: session_service_),
):
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
):
    """
    Fetch the session result
    """
    try:
        return session_service.result(exchange_token)
    except IrmaSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/login/irma/{exchange_token}")
def page(
    exchange_token: str,
    state: str,
    request: Request,
    redirect_url: str = Depends(lambda: redirect_url_),
    session_service: SessionService = Depends(lambda: session_service_),
):
    """
    Fetch the login page
    """
    return session_service.login_irma(exchange_token, state, request, redirect_url)


def enforce_cert_newlines(cert_data):
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


@router.get("/login/uzi/{exchange_token}")
async def uzi_login(
    exchange_token: str,
    state: str,
    request: Request,
    redirect_url: str = Depends(lambda: redirect_url_),
    session_service: SessionService = Depends(lambda: session_service_),
):
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
