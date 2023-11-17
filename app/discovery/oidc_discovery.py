from typing import List, Optional, TypedDict
# from pydantic import BaseModel

class OIDCDiscovery(TypedDict):
    issuer: str
    authorize_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwk_urk: str
    scopes_supported: List[str]
    token_endpoint_auth_methods_supported: Optional[List[str]]