from urllib.parse import urlencode
from pydantic import BaseModel


class AuthorizationParams(BaseModel):
    client_id: str
    response_type: str
    scope: str
    redirect_uri: str
    state: str
    nonce: str
    code_challenge_method: str
    code_challenge: str

    def to_dict(self) -> dict:
        return dict(self)

    def to_url_encoded(self) -> str:
        return urlencode(self.to_dict())
