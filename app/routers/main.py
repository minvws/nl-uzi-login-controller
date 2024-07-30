from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter()


@router.get("/")
async def root() -> PlainTextResponse:
    return PlainTextResponse("Welcome to the login controller!")
