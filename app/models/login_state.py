from pydantic import BaseModel


class LoginState(BaseModel):
    exchange_token: str
    state: str
    code_verifier: str
    redirect_url: str

    def __getitem__(self, key):
        return getattr(self, key)

    def to_dict(self):
        return {
            "exchange_token": self.exchange_token,
            "state": self.state,
            "code_verifier": self.code_verifier,
            "redirect_url": self.redirect_url,
        }
