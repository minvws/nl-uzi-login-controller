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
    SERVER_ERROR,
)

config = ConfigParser()
config.read("app.conf")


class RedirectBaseException(Exception, ABC):
    """
    Base class for all redirect exceptions in the login contronller

    :param state: state coming from MAX
    :param error: error name based on OAUTH defined errors
    :param error_description: extra error description sent to the client
    :param log_message: an exception message logged in the terminal
    """

    base_redirect_url: str = config.get("app", "redirect_url")
    include_log_message_in_error_response: str = config.get(
        "app", "include_log_message_in_error_response"
    )

    def __init__(
        self,
        error: str,
        state: str,
        error_description: Optional[str] = None,
        log_message: Optional[str] = None,
    ) -> None:
        super().__init__(log_message if log_message is not None else error_description)
        self.error = error
        self.error_description = error_description
        self.state = state
        self.log_message = log_message
        self.redirect_url = self._build_redirect_url(self.base_redirect_url)

    def _build_redirect_url(self, redirect_url: str) -> str:
        params = {
            "state": self.state,
            "error": self.error,
        }
        if self.error_description is not None:
            params["error_description"] = self.error_description
        if self.log_message is not None:
            params["error_details"] = self.log_message

        return redirect_url + "?" + urlencode(params)


class ProviderNotFound(RedirectBaseException):
    def __init__(self, state: str) -> None:
        super().__init__(
            error=INVALID_REQUEST,
            state=state,
            error_description="Illegal or bad request",
            log_message="Provider not found",
        )


class ProviderPublicKeyNotFound(RedirectBaseException):
    def __init__(self, state: str, provider_name: str) -> None:
        self.provider_name = provider_name
        super().__init__(
            error=SERVER_ERROR,
            state=state,
            log_message=f"OIDC Provider {provider_name} certificates not found",
            error_description="Something went wrong",
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
    def __init__(
        self,
        state: str,
        log_message: Optional[str] = None,
        error_description: Optional[str] = None,
    ) -> None:
        super().__init__(
            error=ACCESS_DENIED,
            error_description=error_description,
            state=state,
            log_message=log_message if log_message is not None else error_description,
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


class YiviServerException(Exception):
    def __init__(self) -> None:
        super().__init__("Unable to fetch response from YiviServer")


class YiviSessionExpired(Exception):
    def __init__(self) -> None:
        super().__init__("Yivi session expired")


class YiviSessionNotCompleted(Exception):
    def __init__(self) -> None:
        super().__init__("Yivi session not completed")


class InvalidStateException(Exception):
    def __init__(self) -> None:
        super().__init__("State is invalid or expired")


class LoginStateNotFoundException(RedirectBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=ACCESS_DENIED,
            state="NOTFOUND",
            error_description="Login state not found or expired",
        )
