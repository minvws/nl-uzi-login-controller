from pydantic import BaseModel


class LoginState(BaseModel):
    exchange_token: str
    state: str
    code_verifier: str
    redirect_url: str

    def to_dict(self) -> dict:
        return {
            "exchange_token": self.exchange_token,
            "state": self.state,
            "code_verifier": self.code_verifier,
            "redirect_url": self.redirect_url,
        }
