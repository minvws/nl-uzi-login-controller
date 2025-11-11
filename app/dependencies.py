from configparser import ConfigParser
from typing import Optional
import urllib.parse

from app.services.yivi_service import YiviService
from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from app.services.session_service import SessionService
from app.services.vite_manifest_service import ViteManifestService
from app.services.template_service import TemplateService
from app.storage.redis.redis_client import create_redis_client
from app.utils import (
    load_jwk,
    file_content_raise_if_none,
    kid_from_certificate,
    load_oidc_well_known_config,
    json_from_file,
)
from app.models.yivi_authentication_config import YiviAuthenticationConfig


def _parse_hostname(raw_base_url: str) -> str:
    """Extracts the hostname from a base URL."""
    parsed_url = urllib.parse.urlparse(raw_base_url)
    if not parsed_url.hostname:
        raise ValueError(f"Invalid base URL: {raw_base_url}")
    return parsed_url.hostname


def _parse_yivi_auth_config(
    config_parser: ConfigParser,
) -> Optional[YiviAuthenticationConfig]:
    """Parse Yivi authentication configuration.

    Returns a YiviAuthenticationConfig if authentication is enabled; otherwise None.

    Raises:
        ValueError: if authentication is enabled but required fields are missing/invalid.
    """
    if not config_parser.getboolean(
        "yivi", "yivi_authentication_enabled", fallback=False
    ):
        return None

    priv_key_path = config_parser.get(
        "yivi", "yivi_authentication_priv_key_path", fallback=None
    )
    if not priv_key_path:
        raise ValueError(
            "Yivi authentication is enabled, but 'yivi_authentication_priv_key_path' is not configured."
        )
    issuer = config_parser.get("yivi", "yivi_authentication_issuer", fallback=None)
    if not isinstance(issuer, str) or len(issuer) == 0:
        raise ValueError(
            "Yivi authentication is enabled, but 'yivi_authentication_issuer' is missing."
        )
    priv_key = load_jwk(priv_key_path)
    return YiviAuthenticationConfig(issuer=issuer, priv_key=priv_key)


def create_yivi_service_from_config(
    application_host: str, config_parser: ConfigParser, timeout: int
) -> YiviService:
    """Creates and configures the YiviService from a config object."""
    auth_config = _parse_yivi_auth_config(config_parser)

    return YiviService(
        application_host=application_host,
        yivi_internal_server_url=config_parser["yivi"]["yivi_internal_server_url"],
        yivi_disclose_prefix=config_parser["yivi"]["yivi_disclose_prefix"],
        request_nonrevocation_proof=config_parser.getboolean(
            "yivi", "yivi_revocation", fallback=False
        ),
        http_timeout=timeout,
        authentication_config=auth_config,
    )


config = ConfigParser()
config.read("app.conf")

http_timeout = config.getint("app", "http_timeout", fallback=30)
environment = config.get("app", "environment")

base_url = config.get("app", "base_url")
host = _parse_hostname(base_url)
redirect_url_ = config.get("app", "redirect_url")

_redis_client = create_redis_client(config["redis"])
_jwt_issuer_cert = load_jwk(config["session"]["jwt_issuer_crt_path"])

oidc_login_method_feature = config.getboolean("app", "oidc_login_method_feature")

_register_api_crt = load_jwk(config.get("register", "register_api_crt_path"))
_session_result_jwt_issuer = config.get("register", "session_result_jwt_issuer")
_session_result_jwt_audience = config.get("register", "session_result_jwt_audience")

_oidc_service: Optional[OidcService] = None
_signed_userinfo_issuer: Optional[str] = None

if oidc_login_method_feature:
    jwt_priv_key = load_jwk(config.get("oidc_provider", "jwt_priv_key_path"))
    jwt_crt_content = file_content_raise_if_none(
        config.get("oidc_provider", "jwt_crt_path")
    )
    JWT_SERVICE = JwtService(
        jwt_priv_key=jwt_priv_key, crt_kid=kid_from_certificate(jwt_crt_content)
    )

    _signed_userinfo_issuer = config.get("oidc_provider", "signed_userinfo_issuer")

    providers_conf_path = config.get("oidc_provider", "config_list_path")
    oidc_providers = load_oidc_well_known_config(
        providers_config_path=providers_conf_path,
        environment=environment,
        http_timout=http_timeout,
    )

    _oidc_service = OidcService(
        oidc_providers=oidc_providers,
        base_url=base_url,
        http_timeout=http_timeout,
        jwt_service=JWT_SERVICE,
        http_retries=config.getint("app", "http_retries", fallback=20),
        http_backof_time=config.getint("app", "http_backof_time", fallback=5),
    )

vite_manifest_service = ViteManifestService(
    base_url=base_url,
    manifest=json_from_file(config.get("templates", "vite_manifest_path")),
)

template_service = TemplateService(
    jinja_template_directory=config.get("templates", "jinja_path"),
    vite_manifest_service=vite_manifest_service,
)

yivi_service = create_yivi_service_from_config(host, config, http_timeout)

session_service_ = SessionService(
    redis_client=_redis_client,
    yivi_service=yivi_service,
    oidc_service=_oidc_service,
    yivi_disclose_prefix=config["yivi"]["yivi_disclose_prefix"],
    redis_namespace=config["redis"]["namespace"],
    expires_in_s=config.getint("redis", "expire", fallback=60),
    jwt_issuer=config["session"]["jwt_issuer"],
    jwt_issuer_crt=_jwt_issuer_cert,
    jwt_audience=config["session"]["jwt_audience"],
    register_api_crt=_register_api_crt,
    session_result_jwt_issuer=_session_result_jwt_issuer,
    session_result_jwt_audience=_session_result_jwt_audience,
    signed_userinfo_issuer=_signed_userinfo_issuer,
    template_service=template_service,
    session_server_events_enabled=config.getboolean(
        "yivi", "session_server_events_enabled", fallback=False
    ),
    session_server_events_timeout=config.getint(
        "yivi", "session_server_events_timeout", fallback=2000
    ),
    session_polling_interval=config.getint(
        "yivi", "session_polling_interval", fallback=1000
    ),
)
