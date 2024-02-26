from starlette.requests import Request
from starlette.responses import RedirectResponse, JSONResponse, Response

from app.exceptions.app_exceptions import RedirectBaseException


def general_exception_handler(_request: Request, exception: Exception) -> Response:
    if isinstance(exception, RedirectBaseException):
        return RedirectResponse(url=exception.redirect_url, status_code=302)

    return JSONResponse("Internal Server Error", status_code=500)
