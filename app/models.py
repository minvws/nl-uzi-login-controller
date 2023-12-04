from enum import Enum
from typing import Union, Dict, Any, Optional, List

from pydantic import BaseModel, Field


class SessionLoa(str, Enum):
    LOW = "http://eidas.europa.eu/LoA/low"
    SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial"
    HIGH = "http://eidas.europa.eu/LoA/high"


class SessionType(str, Enum):
    IRMA = "irma"
    UZI_CARD = "uzi_card"
    OIDC = "oidc"


class SessionStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    DONE = "DONE"
    CANCELLED = "CANCELLED"


class Session(BaseModel):
    exchange_token: Union[str, None]
    session_type: SessionType
    login_title: str
    session_status: SessionStatus
    irma_disclose_response: Union[str, None]
    irma_session_result: Union[Dict[str, Any], None]
    uzi_id: Union[str, None]
    loa_authn: Optional[SessionLoa]
    oidc_provider_name: Union[str, None]


class OIDCProviderDiscoveryBase(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    registration_endpoint: Optional[str]
    scopes_supported: List[str]
    response_types_supported: List[str]
    response_modes_supported: Optional[List[str]]
    grant_types_supported: Optional[List[str]]
    cr_values_supported: Optional[List[str]]
    subject_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    id_token_encryption_alg_values_supported: Optional[List[str]]
    id_token_encryption_enc_values_supported: Optional[List[str]]
    userinfo_signing_alg_values_supported: Optional[List[str]]
    userinfo_encryption_alg_values_supported: Optional[List[str]]
    userinfo_encryption_enc_values_supported: Optional[List[str]]
    request_object_signing_alg_values_supported: Optional[List[str]]
    request_object_encryption_alg_values_supported: Optional[List[str]]
    request_object_encryption_enc_values_supported: Optional[List[str]]
    token_endpoint_auth_methods_supported: Optional[List[str]]
    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]]
    display_values_supported: Optional[List[str]]
    claim_types_supported: Optional[List[str]]
    claims_supported: Optional[List[str]]
    service_documentation: Optional[str]
    claims_locales_supported: Optional[List[str]]
    ui_locales_supported: Optional[List[str]]
    claims_parameter_supported: Optional[bool]
    request_parameter_supported: Optional[bool]
    request_uri_parameter_supported: Optional[bool]
    require_request_uri_registration: Optional[bool]
    op_policy_uri: Optional[str]
    op_tos_uri: Optional[str]
    check_session_iframe: Optional[str]
    end_session_endpoint: Optional[str]
    frontchannel_logout_supported: Optional[bool]
    frontchannel_logout_session_supported: Optional[bool]
    backchannel_logout_supported: Optional[bool]
    backchannel_logout_session_supported: Optional[bool]


class OIDCProviderConfiguration(BaseModel):
    client_id: str
    client_scopes: List[str]
    discovery: OIDCProviderDiscoveryBase = Field(None, alias="discovery")
    client_secret: Optional[str] = None
    verify_ssl: bool = True
