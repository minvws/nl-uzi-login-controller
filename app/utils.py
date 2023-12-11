import textwrap
import base64
import json
import secrets
import time
from os import path
from typing import Union, Any, Dict
from configparser import ConfigParser
from Cryptodome.IO import PEM
from Cryptodome.Hash import SHA256
from jwcrypto.jwk import JWK

import requests

from app.models.oidc import OIDCProvider
from app.exceptions import UnexpectedResponseCode

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


def enforce_cert_newlines(cert_data: str) -> str:
    cert_data = (
        cert_data.split("-----BEGIN CERTIFICATE-----")[-1]
        .split("-----END CERTIFICATE-----")[0]
        .strip()
    )
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(textwrap.wrap(cert_data.replace(" ", ""), 64))
        + "\n-----END CERTIFICATE-----"
    )


def validate_response_code(status_code: int) -> Any:
    if status_code >= 400:
        raise UnexpectedResponseCode()


def json_fetch_url(
    url: str, backof_time: int = 5, retries: int = 0, verify_ssl: bool = False
) -> Any:
    retry = 0
    previous_exception = None
    while retry <= retries:
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT, verify=verify_ssl)
            validate_response_code(response.status_code)
            return response.json()
        except requests.ConnectionError as request_exception:
            previous_exception = request_exception
            time.sleep(backof_time ^ (retry + 1))
            retry += 1

    if isinstance(previous_exception, BaseException):
        raise previous_exception


def load_oidc_well_known_config(
    providers_config_path: str, environment: str
) -> Dict[str, OIDCProvider]:
    providers = read_json(providers_config_path)
    well_known_configs = {}

    for provider in providers:
        provider_config_url = "".join(
            [provider["issuer"], "/.well-known/openid-configuration"]
        )
        client_secret = (
            provider["client_secret"] if "client_secret" in provider else None
        )
        verify_ssl = (
            environment == "production" or provider["verify_ssl"]
            if "verify_ssl" in provider
            else True
        )
        discovery = None
        try:
            discovery = json_fetch_url(provider_config_url, 2, provider["verify_ssl"])
        except requests.ConnectionError:
            pass

        provider_data = OIDCProvider(
            verify_ssl=verify_ssl,
            well_known_configuration=discovery if discovery else None,
            issuer_url=provider["issuer"],
            client_id=provider["client_id"],
            client_secret=client_secret,
            client_scopes=provider["scopes"],
        )
        well_known_configs[provider["name"]] = provider_data

    return well_known_configs
