from typing import List, Optional
from abc import ABC

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse, Response


class RedirectBaseException(Exception, ABC):
    def __init__(
        self,
        redirect_url: str,
        error: str,
        state: str,
        error_description: Optional[str] = None,
    ) -> None:
        super().__init__(error_description)
        self.error = error
        self.error_description = error_description
        self.state = state
        self.redirect_url = self._build_redirect_url(redirect_url)

    def _build_redirect_url(self, redirect_url: str) -> str:
        return (
            f"{redirect_url}?state={self.state}&error={self.error}&error_description={self.error_description}"
            if self.error_description
            else f"{redirect_url}?state={self}&error={self.error}"
        )


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


class ProviderNotFound(Exception):
    def __init__(self) -> None:
        super().__init__("Provider not found")


class ProviderConfigNotFound(Exception):
    def __init__(self) -> None:
        super().__init__("Provider well known configuration not found")


class ClientScopeException(Exception):
    def __init__(self, unsupported_scopes: List[str]) -> None:
        self.unsupported_scopes = " ".join(unsupported_scopes)
        super().__init__(f"Client scope is not supported: {self.unsupported_scopes}")


class UnexpectedResponseCode(Exception):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Unexpected code received: {self.status_code}")


class InvalidRequestException(RedirectBaseException):
    def __init__(
        self, redirect_url: str, state: str, error_description: Optional[str] = None
    ) -> None:
        super().__init__(
            error="invalid_request",
            error_description=error_description,
            state=state,
            redirect_url=redirect_url,
        )


def general_exception_handler(_request: Request, exception: Exception) -> Response:
    if isinstance(exception, RedirectBaseException):
        return RedirectResponse(url=exception.redirect_url, status_code=302)

    return JSONResponse("Internal Server Error", status_code=500)
