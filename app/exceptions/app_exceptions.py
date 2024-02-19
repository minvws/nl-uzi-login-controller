from typing import List, Optional
from abc import ABC
from configparser import ConfigParser

from app.exceptions.oidc_error_constants import (
    INVALID_REQUEST,
    ACCESS_DENIED,
    INVALID_SCOPE,
    SESSION_NOT_FOUND_ERROR
)

config = ConfigParser()
config.read("app.conf")


class RedirectBaseException(Exception, ABC):
    base_redirect_url: str = config.get("app", "redirect_url")

    def __init__(
        self,
        # redirect_url: str,
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
        return (
            f"{self.base_redirect_url}?state={self.state}&error={self.error}&error_description={self.error_description}"
            if self.error_description
            else f"{redirect_url}?state={self}&error={self.error}"
        )


class InvalidStateException(RedirectBaseException):
    def __init__(self, state: str) -> None:
        super().__init__(
            error=ACCESS_DENIED, error_description="Invalid state", state=state
        )


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


class UnexpectedResponseCode(Exception):
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Unexpected code received: {self.status_code}")


class ProviderConfigNotFound(Exception):
    def __init__(self) -> None:
        super().__init__("Provider well known configuration not found")


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
