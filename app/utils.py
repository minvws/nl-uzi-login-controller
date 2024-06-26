import random
import textwrap
import base64
import json
import secrets
import time
from os import path
from typing import Union, Any, Dict, Optional
from configparser import ConfigParser
from Cryptodome.IO import PEM
from Cryptodome.Hash import SHA256
from jwcrypto.jwk import JWK
import requests

from app.models.oidc_provider import OIDCProvider, OIDCProviderDiscovery
from app.exceptions.app_exceptions import UnexpectedResponseCode


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


def json_from_file(file_path: str) -> Any:
    return json.loads(file_content_raise_if_none(file_path))


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
        raise UnexpectedResponseCode(status_code)


def json_fetch_url(
    url: str,
    backoff_time: int = 0,
    retries: int = 0,
    verify_ssl: bool = True,
    http_timeout: int = 60,
) -> Any:
    retry = 0
    previous_exception = requests.ConnectionError(
        "This error will be overwritten with the actual error if it occurs."
    )
    while retry <= retries:
        try:
            if retry > 0:
                time.sleep((backoff_time + random.randint(1, 3)) ^ retry)
            response = requests.get(url, timeout=http_timeout, verify=verify_ssl)
            validate_response_code(response.status_code)
            return response.json()
        except requests.ConnectionError as request_exception:
            previous_exception = request_exception
            retry += 1
    raise previous_exception


def load_oidc_well_known_config(
    providers_config_path: str, environment: str, http_timout: int
) -> Dict[str, OIDCProvider]:
    providers = json_from_file(providers_config_path)
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
        oidc_provider_public_key = load_jwk(provider["oidc_provider_public_key_path"])
        discovery: Union[dict, None] = None

        try:
            discovery = json_fetch_url(
                url=provider_config_url,
                verify_ssl=provider["verify_ssl"],
                http_timeout=http_timout,
            )
        except requests.ConnectionError:
            pass

        provider_data = OIDCProvider(
            verify_ssl=verify_ssl,
            well_known_configuration=(
                OIDCProviderDiscovery(**discovery) if discovery else None
            ),
            issuer_url=provider["issuer"],
            client_id=provider["client_id"],
            client_secret=client_secret,
            client_scopes=provider["scopes"],
            oidc_provider_public_key=oidc_provider_public_key,
            token_endpoint_auth_method=provider["token_endpoint_auth_method"],
        )
        well_known_configs[provider["name"]] = provider_data

    return well_known_configs


def get_version_from_file(file_path: Optional[str] = None) -> str:
    _default_version = "v0.0.0"

    if file_path is None:
        return _default_version

    _version_dict = json_from_file(file_path)
    return _version_dict.get("version", _default_version)


def get_version_from_config(config: ConfigParser) -> str:
    return get_version_from_file(config.get("app", "version_file_path"))
