from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from app.dependencies import irma_service_, redirect_url_
from app.services.irma_service import IrmaService
from app.models import SessionRequest

router = APIRouter()
templates = Jinja2Templates(directory="jinja2")


@router.post("/session")
def session(
    session_request: SessionRequest,
    irma_service: IrmaService = Depends(lambda: irma_service_),
):
    return irma_service.create_session(session_request)


@router.get("/session/{exchange_token}")
def fetch_session(
    exchange_token: str, irma_service: IrmaService = Depends(lambda: irma_service_)
):
    return irma_service.fetch(exchange_token)


@router.get("/result/{exchange_token}")
def result(
    exchange_token: str, irma_service: IrmaService = Depends(lambda: irma_service_)
):
    return irma_service.result(exchange_token)


@router.get("/login/{exchange_token}")
def page(
    exchange_token: str,
    state: str,
    request: Request,
    redirect_url: str = Depends(lambda: redirect_url_),
):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "exchange_token": exchange_token,
            "state": state,
            "redirect_url": redirect_url,
        },
    )
