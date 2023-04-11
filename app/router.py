from fastapi import APIRouter, Depends, Request, HTTPException

from app.dependencies import session_service_, redirect_url_
from app.exceptions import IrmaSessionExpired
from app.services.session_service import SessionService

router = APIRouter()


@router.post("/session")
async def session(
    request: Request,
    irma_service: SessionService = Depends(lambda: session_service_),
):
    """
    Create a new IRMA session
    """
    request_body = await request.body()
    if isinstance(request_body, bytes):
        return irma_service.create(request_body.decode("utf-8"))
    raise HTTPException(status_code=403, detail="No valid content provided")


@router.get("/session/{exchange_token}/status")
async def session_status(
    exchange_token: str,
    irma_service: SessionService = Depends(lambda: session_service_)
):
    """
    Get the status of a session
    """
    try:
        return irma_service.status(exchange_token)
    except IrmaSessionExpired:
        raise HTTPException(status_code=404, detail="Session expired")


@router.get("/session/{exchange_token}/irma")
def irma_session(
    exchange_token: str, irma_service: SessionService = Depends(lambda: session_service_)
):
    """
    Get the IRMA response from a session
    """
    return irma_service.irma(exchange_token)


@router.get("/session/{exchange_token}/result")
def result(
    exchange_token: str, irma_service: SessionService = Depends(lambda: session_service_)
):
    """
    Fetch the session result
    """
    return irma_service.result(exchange_token)


@router.get("/login/{exchange_token}")
def page(
    exchange_token: str,
    state: str,
    request: Request,
    redirect_url: str = Depends(lambda: redirect_url_),
    irma_service: SessionService = Depends(lambda: session_service_)
):
    """
    Fetch the login page
    """
    return irma_service.login(exchange_token, state, request, redirect_url)
