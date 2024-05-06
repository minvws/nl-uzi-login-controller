from typing import Optional, List

from pydantic import BaseModel, Field, ConfigDict

from jwcrypto.jwk import JWK

from app.models.enums import TokenAuthenticationMethods


class OIDCProviderDiscovery(BaseModel):
    model_config = ConfigDict(extra="allow")

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    registration_endpoint: Optional[str] = None
    scopes_supported: List[str]
    response_types_supported: List[str]
    response_modes_supported: Optional[List[str]] = None
    grant_types_supported: Optional[List[str]] = None
    cr_values_supported: Optional[List[str]] = None
    subject_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    id_token_encryption_alg_values_supported: Optional[List[str]] = None
    id_token_encryption_enc_values_supported: Optional[List[str]] = None
    userinfo_signing_alg_values_supported: Optional[List[str]] = None
    userinfo_encryption_alg_values_supported: Optional[List[str]] = None
    userinfo_encryption_enc_values_supported: Optional[List[str]] = None
    request_object_signing_alg_values_supported: Optional[List[str]] = None
    request_object_encryption_alg_values_supported: Optional[List[str]] = None
    request_object_encryption_enc_values_supported: Optional[List[str]] = None
    token_endpoint_auth_methods_supported: Optional[List[str]] = None
    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None
    display_values_supported: Optional[List[str]] = None
    claim_types_supported: Optional[List[str]] = None
    claims_supported: Optional[List[str]] = None
    service_documentation: Optional[str] = None
    claims_locales_supported: Optional[List[str]] = None
    ui_locales_supported: Optional[List[str]] = None
    claims_parameter_supported: Optional[bool] = None
    request_parameter_supported: Optional[bool] = None
    request_uri_parameter_supported: Optional[bool] = None
    require_request_uri_registration: Optional[bool] = None
    op_policy_uri: Optional[str] = None
    op_tos_uri: Optional[str] = None
    check_session_iframe: Optional[str] = None
    end_session_endpoint: Optional[str] = None
    frontchannel_logout_supported: Optional[bool] = None
    frontchannel_logout_session_supported: Optional[bool] = None
    backchannel_logout_supported: Optional[bool] = None
    backchannel_logout_session_supported: Optional[bool] = None


class OIDCProvider:
    client_id: str
    client_scopes: List[str]
    well_known_configuration: Optional[OIDCProviderDiscovery] = Field(
        None, alias="well_known_configuration"
    )
    issuer_url: str
    client_secret: Optional[str] = None
    verify_ssl: bool = True
    oidc_provider_public_key: JWK
    token_authentication_method: str

    def __init__(
        self,
        client_id: str,
        client_scopes: List[str],
        well_known_configuration: Optional[OIDCProviderDiscovery],
        issuer_url: str,
        client_secret: Optional[str],
        verify_ssl: bool,
        oidc_provider_public_key: JWK,
        token_authentication_method: str,
    ) -> None:
        self.client_id = client_id
        self.client_scopes = client_scopes
        self.well_known_configuration = well_known_configuration
        self.issuer_url = issuer_url
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.oidc_provider_public_key = oidc_provider_public_key
        try:
            self.token_authentication_method = getattr(
                TokenAuthenticationMethods, token_authentication_method.upper()
            )
        except AttributeError:
            print(
                f"{token_authentication_method} is not a valid method, make sure token_authentication_method is present in oidc-providers file with values {TokenAuthenticationMethods.to_list()}"
            )
