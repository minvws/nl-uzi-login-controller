from enum import Enum
from typing import Union, Dict, Any

from pydantic import BaseModel


class SessionType(str, Enum):
    IRMA = "irma"
    UZI_PAS = "uzi_pas"


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
