import time
from urllib.parse import urlencode
from typing import Dict, Optional

import logging
import requests
from fastapi.exceptions import RequestValidationError
from starlette.responses import RedirectResponse
from app.exceptions import GeneralServerException
from app.models.oidc import OIDCProviderConfiguration, OIDCProviderDiscovery
from app.utils import nonce
from app.services.jwt_service import JwtService


class OidcService:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        oidc_providers_well_known_config: Dict[str, OIDCProviderConfiguration],
        jwt_service: JwtService,
        redirect_uri: str,
        http_timeout: int,
    ):
        self._redirect_uri = redirect_uri
        self._http_timeout = http_timeout
        self._oidc_providers_config = oidc_providers_well_known_config
        self._jwt_service = jwt_service

    def get_authorize_response(
        self,
        oidc_provider_name: str,
        code_challenge: str,
        oidc_state: str,
    ) -> RedirectResponse:
        self._check_and_update_provider_discovery(oidc_provider_name)

        client_id = self._oidc_providers_config[oidc_provider_name].client_id
        oidc_provider = self._oidc_providers_config[oidc_provider_name].discovery

        if not oidc_provider:
            raise GeneralServerException()

        for scope in self._oidc_providers_config[oidc_provider_name].client_scopes:
            if scope not in oidc_provider.scopes_supported:
                # TODO: FS add HTTP exceptions to the application
                raise GeneralServerException()

        params = {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(
                self._oidc_providers_config[oidc_provider_name].client_scopes
            ),
            "redirect_uri": self._redirect_uri,
            "state": oidc_state,
            "nonce": nonce(50),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }
        url = oidc_provider.authorization_endpoint + "?" + urlencode(params)
        return RedirectResponse(
            url=url,
            status_code=303,
        )

    def get_userinfo(
        self, oidc_provider_name: str, code: str, code_verifier: str
    ) -> str:
        # TODO GB: error handling
        oidc_provider = self._oidc_providers_config[oidc_provider_name].discovery
        client_id = self._oidc_providers_config[oidc_provider_name].client_id
        client_secret = self._oidc_providers_config[oidc_provider_name].client_secret

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
            verify=self._oidc_providers_config[oidc_provider_name].verify_ssl,
        )

        resp = requests.get(
            oidc_provider.userinfo_endpoint,  # type: ignore
            timeout=self._http_timeout,
            headers={"Authorization": "Bearer " + resp.json()["access_token"]},
            verify=self._oidc_providers_config[oidc_provider_name].verify_ssl,
        )
        if resp.headers["Content-Type"] != "application/jwt":
            raise RequestValidationError("Unsupported media type")
        return resp.text

    def _check_and_update_provider_discovery(self, oidc_provider_name: str) -> None:
        oidc_provider = self._oidc_providers_config[oidc_provider_name]
        if not oidc_provider.discovery:
            oidc_provider_well_known_url = "".join(
                [oidc_provider.issuer_url, "/.well-known/openid-configuration"]
            )
            oidc_provider_discovery = self._fetch_oidc_provider_discovery_config(
                oidc_provider_well_known_url, 1000
            )
            self._oidc_providers_config[
                oidc_provider_name
            ].discovery = oidc_provider_discovery

    def _fetch_oidc_provider_discovery_config(
        self, provider_well_known_url: str, nb_of_retries: int
    ) -> Optional[OIDCProviderDiscovery]:
        retries = 1
        while retries < nb_of_retries:
            try:
                data = requests.get(
                    provider_well_known_url, timeout=self._http_timeout, verify=False
                )
                provider_discovery = OIDCProviderDiscovery(**data.json())
                return provider_discovery
            except requests.ConnectionError:
                logging.error(
                    "request to %s failed, reattempting to connect number %s",
                    provider_well_known_url,
                    retries,
                )
                time.sleep(1)
                retries += 1
        return None
