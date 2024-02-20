from urllib.parse import urlencode
from typing import List, Optional
from abc import ABC
from configparser import ConfigParser

from app.exceptions.oidc_error_constants import (
    INVALID_REQUEST,
    ACCESS_DENIED,
    INVALID_SCOPE,
    SESSION_NOT_FOUND_ERROR,
    TEMPORARILY_UNAVAILABLE,
)

config = ConfigParser()
config.read("app.conf")


class RedirectBaseException(Exception, ABC):
    base_redirect_url: str = config.get("app", "redirect_url")

    def __init__(
        self,
        error: str,
        state: str,
        error_description: Optional[str] = None,
    ) -> None:
        super().__init__(error_description)
        self.error = error
        self.error_description = error_description
        self.state = state
        self.redirect_url = self._build_redirect_url(self.base_redirect_url)

    def _build_redirect_url(self, redirect_url: str) -> str:
        params = (
            urlencode(
                {
                    "state": self.state,
                    "error": self.error,
                    "error_description": self.error_description,
                }
            )
            if self.error_description is not None
            else urlencode({"state": self.state, "error": self.error})
        )

        return redirect_url + "?" + params


class ProviderNotFound(RedirectBaseException):
    def __init__(self, state: str) -> None:
        super().__init__(
            error=INVALID_REQUEST, error_description="Provider not found", state=state
        )


class ClientScopeException(RedirectBaseException):
    def __init__(self, state: str, unsupported_scopes: List[str]) -> None:
        self.unsupported_scopes = " ".join(unsupported_scopes)
        super().__init__(
            error=INVALID_SCOPE,
            state=state,
            error_description=f"Client scope is not supported: {self.unsupported_scopes}",
        )


class InvalidJWTException(RedirectBaseException):
    def __init__(self, state: str, error_description: Optional[str] = None) -> None:
        super().__init__(
            error=ACCESS_DENIED,
            error_description=error_description,
            state=state,
        )


class SessionNotFoundException(RedirectBaseException):
    def __init__(self, state: str) -> None:
        super().__init__(
            error=ACCESS_DENIED, state=state, error_description=SESSION_NOT_FOUND_ERROR
        )


class ServiceUnavailableException(RedirectBaseException):
    def __init__(self, state: str, error_description: Optional[str] = None) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            state=state,
            error_description=error_description,
        )


class ProviderConfigNotFound(RedirectBaseException):
    def __init__(self, state: str) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Provider well known configuration not found",
            state=state,
        )


class InvalidRequestException(RedirectBaseException):
    def __init__(self, state: str, error_description: Optional[str] = None) -> None:
        super().__init__(
            error=INVALID_REQUEST, state=state, error_description=error_description
        )


class UnexpectedResponseCode(Exception):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Unexpected code received: {self.status_code}")


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


class InvalidStateException(Exception):
    def __init__(self) -> None:
        super().__init__("State is invalid or expired")
