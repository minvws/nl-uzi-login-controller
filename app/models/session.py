from enum import Enum
from typing import Union, Dict, Any, Optional

from pydantic import BaseModel


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
