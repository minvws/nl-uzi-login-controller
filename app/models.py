from typing import List, Union

from pydantic import BaseModel


class Disclose(BaseModel):
    disclose_type: str
    disclose_value: Union[str, None]


class SessionRequest(BaseModel):
    requested_disclosures: List[Disclose]
