from configparser import ConfigParser
from typing import Optional

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

config = ConfigParser()
config.read("app.conf")

http_timeout = config.getint("app", "http_timeout", fallback=30)
environment = config.get("app", "environment")

base_url = config.get("app", "base_url")
redirect_url_ = config.get("app", "redirect_url")

_redis_client = create_redis_client(config["redis"])
_jwt_issuer_cert = load_jwk(config["session"]["jwt_issuer_crt_path"])

oidc_login_method_feature = config.getboolean("app", "oidc_login_method_feature")

REGISTER_API_CRT = load_jwk(config.get("register", "register_api_crt_path"))
SESSION_RESULT_JWT_ISSUER = config.get("register", "session_result_jwt_issuer")
SESSION_RESULT_JWT_AUDIENCE = config.get("register", "session_result_jwt_audience")

OIDC_SERVICE: Optional[OidcService] = None
SIGNED_USERINFO_ISSUER: Optional[str] = None

if oidc_login_method_feature:
    jwt_priv_key = load_jwk(config.get("oidc_provider", "jwt_priv_key_path"))
    jwt_crt_content = file_content_raise_if_none(
        config.get("oidc_provider", "jwt_crt_path")
    )
    JWT_SERVICE = JwtService(
        jwt_priv_key=jwt_priv_key, crt_kid=kid_from_certificate(jwt_crt_content)
    )

    SIGNED_USERINFO_ISSUER = config.get("oidc_provider", "signed_userinfo_issuer")

    providers_conf_path = config.get("oidc_provider", "config_list_path")
    oidc_providers = load_oidc_well_known_config(
        providers_config_path=providers_conf_path,
        environment=environment,
        http_timout=http_timeout,
    )

    OIDC_SERVICE = OidcService(
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

yivi_service = YiviService(
    yivi_internal_server_url=config["yivi"]["yivi_internal_server_url"],
    yivi_disclose_prefix=config["yivi"]["yivi_disclose_prefix"],
    yivi_revocation=bool(config["yivi"]["yivi_revocation"]),
    http_timeout=http_timeout,
)

session_service_ = SessionService(
    redis_client=_redis_client,
    yivi_service=yivi_service,
    oidc_service=OIDC_SERVICE,
    yivi_disclose_prefix=config["yivi"]["yivi_disclose_prefix"],
    redis_namespace=config["redis"]["namespace"],
    expires_in_s=config.getint("redis", "expire", fallback=60),
    jwt_issuer=config["session"]["jwt_issuer"],
    jwt_issuer_crt=_jwt_issuer_cert,
    jwt_audience=config["session"]["jwt_audience"],
    register_api_crt=REGISTER_API_CRT,
    session_result_jwt_issuer=SESSION_RESULT_JWT_ISSUER,
    session_result_jwt_audience=SESSION_RESULT_JWT_AUDIENCE,
    signed_userinfo_issuer=SIGNED_USERINFO_ISSUER,
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
