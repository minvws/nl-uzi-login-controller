import base64
import secrets
import string
from os import path
from random import random
from typing import Union
from Cryptodome.IO import PEM
from Cryptodome.Hash import SHA256


from jwcrypto.jwk import JWK

alphabet = string.ascii_letters + string.digits

def rand_pass(size):
    return secrets.token_urlsafe(size)
def nonce(size):
    return secrets.token_urlsafe(size)

def load_jwk(path: str) -> JWK:
    with open(path, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))

def file_content_raise_if_none(filepath: str) -> str:
    optional_file_content = file_content(filepath)
    if optional_file_content is None:
        raise ValueError(f"file_content for {filepath} shouldn't be None")
    return optional_file_content

def file_content(filepath: str) -> Union[str, None]:
    if filepath is not None and path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    return None


def kid_from_certificate(certificate: str) -> str:
    der = PEM.decode(certificate)
    sha = SHA256.new()
    sha.update(der[0])
    return base64.b64encode(sha.digest()).decode("utf-8")
