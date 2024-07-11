from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import Response, JSONResponse

from app.dependencies import session_service_
from app.services.session_service import SessionService
from app.exceptions.app_exceptions import YiviSessionExpired


router = APIRouter(prefix="/session", tags=["Session"])


@router.post("")
async def session(
    request: Request,
    session_service: SessionService = Depends(lambda: session_service_),
) -> JSONResponse:
    """
    Create a new YIVI session
    """
    return session_service.create(request)


@router.get("/status")
async def session_status(
    request: Request,
    session_service: SessionService = Depends(lambda: session_service_),
) -> Response:
    """
    Get the status of a session
    """
    try:
        return session_service.status(request)
    except YiviSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/{exchange_token}/yivi")
def yivi_session(
    exchange_token: str,
    session_service: SessionService = Depends(lambda: session_service_),
) -> JSONResponse:
    """
    Get the YIFI response from a session
    """
    try:
        return session_service.yivi(exchange_token)
    except YiviSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp


@router.get("/results")
def result(
    request: Request,
    session_service: SessionService = Depends(lambda: session_service_),
) -> Response:
    """
    Fetch the session result
    """
    try:
        return session_service.result(request)
    except YiviSessionExpired as exp:
        raise HTTPException(status_code=404, detail="Session expired") from exp
