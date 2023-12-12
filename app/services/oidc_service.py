from urllib.parse import urlencode
from typing import Dict
import requests
from fastapi.exceptions import RequestValidationError
from starlette.responses import RedirectResponse
from app.exceptions import (
    ProviderConfigNotFound,
    ProviderNotFound,
    ClientScopeException,
)
from app.models.oidc import OIDCProvider, OIDCProviderDiscovery
from app.utils import nonce, json_fetch_url, validate_response_code
from app.services.jwt_service import JwtService


class OidcService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        oidc_providers: Dict[str, OIDCProvider],
        jwt_service: JwtService,
        redirect_uri: str,
        http_timeout: int,
        http_retries: int,
        http_backof_time: int,
    ):
        self._redirect_uri = redirect_uri
        self._http_timeout = http_timeout
        self._oidc_providers = oidc_providers
        self._jwt_service = jwt_service
        self._http_retries = http_retries
        self._http_backof_time = http_backof_time

    def get_authorize_response(
        self,
        oidc_provider_name: str,
        code_challenge: str,
        oidc_state: str,
    ) -> RedirectResponse:
        provider = self._get_oidc_provider(oidc_provider_name)
        if provider.well_known_configuration is None:
            raise ProviderConfigNotFound()

        client_id = self._oidc_providers[oidc_provider_name].client_id
        client_scopes = self._oidc_providers[oidc_provider_name].client_scopes

        unsupported_scopes = list(
            set(client_scopes) - set(provider.well_known_configuration.scopes_supported)
        )
        if unsupported_scopes:
            raise ClientScopeException(unsupported_scopes)

        params = {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(self._oidc_providers[oidc_provider_name].client_scopes),
            "redirect_uri": self._redirect_uri,
            "state": oidc_state,
            "nonce": nonce(50),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }
        url = (
            provider.well_known_configuration.authorization_endpoint
            + "?"
            + urlencode(params)
        )
        return RedirectResponse(
            url=url,
            status_code=303,
        )

    def get_userinfo(
        self, oidc_provider_name: str, code: str, code_verifier: str
    ) -> str:
        # TODO GB: error handling
        oidc_provider = self._oidc_providers[
            oidc_provider_name
        ].well_known_configuration
        client_id = self._oidc_providers[oidc_provider_name].client_id
        client_secret = self._oidc_providers[oidc_provider_name].client_secret

        data = {
            "code": code,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "grant_type": "authorization_code",
            "redirect_uri": self._redirect_uri,
        }

        if client_secret is not None and isinstance(client_secret, str):
            data["client_secret"] = client_secret

        resp = requests.post(
            oidc_provider.token_endpoint,  # type: ignore
            timeout=self._http_timeout,
            data=data,
            verify=self._oidc_providers[oidc_provider_name].verify_ssl,
        )
        validate_response_code(resp.status_code)

        resp = requests.get(
            oidc_provider.userinfo_endpoint,  # type: ignore
            timeout=self._http_timeout,
            headers={"Authorization": "Bearer " + resp.json()["access_token"]},
            verify=self._oidc_providers[oidc_provider_name].verify_ssl,
        )
        validate_response_code(resp.status_code)

        if resp.headers["Content-Type"] != "application/jwt":
            raise RequestValidationError("Unsupported media type")
        return resp.text

    def _get_oidc_provider(self, oidc_provider_name: str) -> OIDCProvider:
        if oidc_provider_name in self._oidc_providers:
            provider = self._oidc_providers[oidc_provider_name]
            if provider.well_known_configuration is None:
                self._update_provider_discovery(provider)
            return provider
        raise ProviderNotFound()

    def _update_provider_discovery(self, oidc_provider: OIDCProvider) -> None:
        well_known_url = "".join(
            [oidc_provider.issuer_url, "/.well-known/openid-configuration"]
        )
        oidc_provider.well_known_configuration = OIDCProviderDiscovery(
            **json_fetch_url(
                well_known_url,
                self._http_backof_time,
                self._http_retries,
                oidc_provider.verify_ssl,
            )
        )
