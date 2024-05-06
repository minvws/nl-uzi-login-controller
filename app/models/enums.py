# pylint:disable=no-member
from enum import Enum


class TokenAuthenticationMethods(str, Enum):
    PRIVATE_KEY_JWT = "private_key_jwt"
    NONE = "none"

    @classmethod
    def to_list(cls):
        return list(map(lambda member: member.value, cls._member_map_.values()))
