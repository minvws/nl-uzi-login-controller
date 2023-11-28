import base64
import json
import secrets
from os import path
from typing import Union, Any, Dict
from configparser import ConfigParser
from Cryptodome.IO import PEM
from Cryptodome.Hash import SHA256
from jwcrypto.jwk import JWK

import requests

from app.models import OIDCProviderConfiguration

config = ConfigParser()
config.read("app.conf")

HTTP_TIMEOUT = int(config.get("app", "http_timeout"))


def rand_pass(size: int) -> str:
    return secrets.token_urlsafe(size)


def nonce(size: int) -> str:
    return rand_pass(size)


def load_jwk(filepath: str) -> JWK:
    with open(filepath, encoding="utf-8") as file:
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


def read_json(file_path: str) -> Any:
    data = json.loads(file_content_raise_if_none(file_path))
    return data


def load_oidc_well_known_config(
    providers_config_path: str,
) -> Dict[str, OIDCProviderConfiguration]:
    providers = read_json(providers_config_path)
    well_known_configs = {}

    for provider in providers:
        provider_config_url = "".join(
            [provider["issuer"], "/.well-known/openid-configuration"]
        )
        response = requests.get(
            provider_config_url, timeout=HTTP_TIMEOUT, verify=False
        ).json()
        config_data = {"client_id": provider["client_id"], "discovery": response}

        provider_data = OIDCProviderConfiguration(**config_data)
        well_known_configs[provider["name"]] = provider_data

    return well_known_configs
