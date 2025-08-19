import logging
from typing import Dict, Optional, Any
import requests

from fastapi.exceptions import RequestValidationError
from jwcrypto.jwk import JWK
from starlette.responses import RedirectResponse

from app.constants import CLIENT_ASSERTION_TYPE
from app.exceptions.app_exceptions import (
    ProviderConfigNotFound,
    ProviderNotFound,
    ClientScopeException,
    ProviderPublicKeyNotFound,
    InvalidJWTException,
)
from app.models.enums import TokenEndpointAuthenticationMethods
from app.models.oidc_provider import OIDCProvider, OIDCProviderDiscovery
from app.models.authorization_params import AuthorizationParams
from app.utils import nonce, json_fetch_url, validate_response_code
from app.services.jwt_service import JwtService

logger = logging.getLogger(__name__)


class OidcService:
    # pylint: disable=too-many-positional-arguments
    def __init__(
        self,
        oidc_providers: Dict[str, OIDCProvider],
        jwt_service: JwtService,
        base_url: str,
        http_timeout: int,
        http_retries: int,
        http_backof_time: int,
    ):
        # The url of the oidc callback route
        self._redirect_uri = base_url + "/login/oidc/callback"
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
        max_state: str,
    ) -> RedirectResponse:
        provider = self._get_oidc_provider(oidc_provider_name)
        if provider is None:
            raise ProviderNotFound(max_state)

        if provider.well_known_configuration is None:
            raise ProviderConfigNotFound(max_state)

        client_id = provider.client_id
        client_scopes = provider.client_scopes

        unsupported_scopes = list(
            set(client_scopes) - set(provider.well_known_configuration.scopes_supported)
        )
        if unsupported_scopes:
            raise ClientScopeException(max_state, unsupported_scopes)

        params = AuthorizationParams(
            client_id=client_id,
            response_type="code",
            scope=" ".join(provider.client_scopes),
            redirect_uri=self._redirect_uri,
            state=oidc_state,
            nonce=nonce(50),
            code_challenge_method="S256",
            code_challenge=code_challenge,
        )
        url = self._update_and_get_authorization_url(
            oidc_provider_name, params, max_state
        )

        return RedirectResponse(
            url=url,
            status_code=303,
        )

    def get_userinfo(
        self, oidc_provider_name: str, code: str, code_verifier: str, max_state: str
    ) -> Dict[str, Any]:
        provider = self._get_oidc_provider(oidc_provider_name)
        if provider is None:
            raise ProviderNotFound(max_state)

        provider_well_known_config = provider.well_known_configuration
        if provider_well_known_config is None:
            raise ProviderConfigNotFound(max_state)

        client_id = provider.client_id
        client_secret = provider.client_secret

        data = {
            "code": code,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "grant_type": "authorization_code",
            "redirect_uri": self._redirect_uri,
        }

        if (
            provider.token_endpoint_auth_method
            == TokenEndpointAuthenticationMethods.PRIVATE_KEY_JWT.value
        ):
            data["client_assertion_type"] = CLIENT_ASSERTION_TYPE
            data["client_assertion"] = self._jwt_service.create_jwt(
                {
                    "iss": provider.client_id,
                    "sub": provider.client_id,
                    "aud": provider_well_known_config.issuer,
                }
            )

        if client_secret is not None and isinstance(client_secret, str):
            data["client_secret"] = client_secret

        resp = requests.post(
            url=provider_well_known_config.token_endpoint,
            timeout=self._http_timeout,
            data=data,
            verify=provider.verify_ssl,
        )
        validate_response_code(resp.status_code)

        resp = requests.get(
            provider_well_known_config.userinfo_endpoint,  # type: ignore
            timeout=self._http_timeout,
            headers={"Authorization": "Bearer " + resp.json()["access_token"]},
            verify=provider.verify_ssl,
        )
        validate_response_code(resp.status_code)

        if resp.headers["Content-Type"] != "application/jwt":
            raise RequestValidationError("Unsupported media type")

        oidc_provider_userinfo_jwe = resp.text

        oidc_provider_public_key = self.get_oidc_provider_public_key(oidc_provider_name)
        if oidc_provider_public_key is None:
            raise ProviderPublicKeyNotFound(
                state=max_state,
                provider_name=oidc_provider_name,
            )

        try:
            oidc_provider_userinfo_jwt = self._jwt_service.from_jwe(
                oidc_provider_public_key,
                oidc_provider_userinfo_jwe,
            )
        except Exception as exception:
            raise InvalidJWTException(
                state=max_state, log_message="Unable to decrypt userinfo JWE"
            ) from exception
        if oidc_provider_userinfo_jwt is None:
            raise InvalidJWTException(
                state=max_state, log_message="Invalid claims from userinfo JWE"
            )

        return oidc_provider_userinfo_jwt

    def _update_and_get_authorization_url(
        self, oidc_provider_name: str, params: AuthorizationParams, max_state: str
    ) -> str:
        provider = self._get_oidc_provider(oidc_provider_name)
        if provider is None:
            raise ProviderNotFound(max_state)

        if provider.well_known_configuration is not None:
            updated_url = (
                provider.well_known_configuration.authorization_endpoint
                + "?"
                + params.to_url_encoded()
            )
            return updated_url

        raise ProviderConfigNotFound(max_state)

    def _get_oidc_provider(self, oidc_provider_name: str) -> Optional[OIDCProvider]:
        if oidc_provider_name in self._oidc_providers:
            provider = self._oidc_providers[oidc_provider_name]
            if provider.well_known_configuration is None:
                try:
                    self._update_provider_discovery(provider)
                except Exception as e:  # pylint: disable=broad-except
                    logger.error("Failed to update provider discovery: %s", e)
            return provider
        return None

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

    def get_oidc_provider_public_key(self, oidc_provider_name: str) -> Optional[JWK]:
        oidc_provider = self._get_oidc_provider(oidc_provider_name)
        if oidc_provider is None:
            return None

        return oidc_provider.oidc_provider_public_key
