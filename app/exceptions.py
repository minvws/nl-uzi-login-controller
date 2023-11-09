from fastapi import Request
from fastapi.responses import JSONResponse


class InvalidStateException(Exception):
    def __init__(self) -> None:
        super().__init__("Invalid state")


class GeneralServerException(Exception):
    def __init__(self) -> None:
        super().__init__("Unable to fetch response from Server")


class IrmaServerException(Exception):
    def __init__(self) -> None:
        super().__init__("Unable to fetch response from IrmaServer")


class IrmaSessionExpired(Exception):
    def __init__(self) -> None:
        super().__init__("Irma session expired")


class IrmaSessionNotCompleted(Exception):
    def __init__(self) -> None:
        super().__init__("Irma session not completed")


async def general_exception_handler(
    _request: Request, _exception: Exception
) -> JSONResponse:
    return JSONResponse("Internal Server Error", status_code=500)
