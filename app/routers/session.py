from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, Response

from app.dependencies import session_service_
from app.services.session_service import SessionService
from app.exceptions.irma import IrmaSessionExpired


router = APIRouter(prefix="/session", tags=["Session"])


@router.post("")
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


@router.get("/{exchange_token}/status")
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


@router.get("/{exchange_token}/yivi")
def irma_session(
    exchange_token: str,
    session_service: SessionService = Depends(lambda: session_service_),
) -> JSONResponse:
    """
    Get the YIFI response from a session
    """
    try:
        return session_service.irma(exchange_token)
    except IrmaSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/{exchange_token}/result")
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
