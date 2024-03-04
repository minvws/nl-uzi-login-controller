import logging

from starlette.requests import Request
from starlette.responses import RedirectResponse, JSONResponse, Response

from app.exceptions.app_exceptions import RedirectBaseException

logger = logging.getLogger(__name__)


def general_exception_handler(_request: Request, exception: Exception) -> Response:
    if logger.isEnabledFor(logging.DEBUG):
        logger.error(exception)

    if isinstance(exception, RedirectBaseException):
        return RedirectResponse(url=exception.redirect_url, status_code=302)

    return JSONResponse("Internal Server Error", status_code=500)
