from enum import Enum
from typing import Dict, Any, Optional

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
    exchange_token: str
    session_type: SessionType
    login_title: str
    session_status: SessionStatus
    irma_disclose_response: Optional[str] = None
    irma_session_result: Optional[Dict[str, Any]] = None
    uzi_id: Optional[str] = None
    loa_authn: Optional[SessionLoa] = None
    oidc_provider_name: Optional[str] = None


def parse_session_type(session_type: Optional[str] = None) -> Optional[SessionType]:
    if session_type is None:
        return None

    try:
        return SessionType(session_type)
    except ValueError:
        return None
