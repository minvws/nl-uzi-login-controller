from fastapi import Request
from fastapi.responses import JSONResponse


class IrmaServerException(Exception):
    def __init__(self):
        super().__init__("Unable to fetch response from IrmaServer")


class IrmaSessionExpired(Exception):
    def __init__(self):
        super().__init__("Irma session expired")


class IrmaSessionNotCompleted(Exception):
    def __init__(self):
        super().__init__("Irma session not completed")


async def general_exception_handler(_: Request, exception: Exception):
    return JSONResponse(str(exception), status_code=500)
