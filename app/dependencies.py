from configparser import ConfigParser


from app.services.irma_service import IrmaService
from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from app.services.session_service import SessionService
from app.storage.redis.redis_client import create_redis_client
from app.utils import (
    load_jwk,
    file_content_raise_if_none,
    kid_from_certificate,
    load_oidc_well_known_config,
)

config = ConfigParser()
config.read("app.conf")

redirect_url_ = config.get("app", "redirect_url")

jwt_priv_key = load_jwk(config.get("app", "jwt_priv_key_path"))
oidc_provider_pub_key = load_jwk(config.get("oidc_provider", "jwt_pub_key_path"))

jwt_crt_content = file_content_raise_if_none(config.get("app", "jwt_crt_path"))

_redis_client = create_redis_client(config["redis"])

# fetch and load providers
providers_conf_path = config.get("oidc_provider", "config_list_path")
providers_well_known_configs = load_oidc_well_known_config(providers_conf_path)

jwt_service = JwtService(
    jwt_priv_key=jwt_priv_key, crt_kid=kid_from_certificate(jwt_crt_content)
)

irma_service = IrmaService(
    irma_internal_server_url=config["irma"]["irma_internal_server_url"],
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    irma_revocation=bool(config["irma"]["irma_revocation"]),
    http_timeout=config.getint("app", "http_timeout", fallback=30),
)

oidc_service = OidcService(
    redis_client=_redis_client,
    oidc_providers_well_known_config=providers_well_known_configs,
    client_secret=config["oidc_provider"]["client_secret"],
    redirect_uri=config["oidc_provider"]["redirect_uri"],
    http_timeout=config.getint("app", "http_timeout", fallback=30),
    cache_expire=config.getint("redis", "expire", fallback=60),
    jwt_service=jwt_service,
)

session_service_ = SessionService(
    redis_client=_redis_client,
    irma_service=irma_service,
    oidc_service=oidc_service,
    jwt_service=jwt_service,
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    redis_namespace=config["redis"]["namespace"],
    expires_in_s=int(config["redis"]["expire"]),
    jwt_issuer=config["session"]["jwt_issuer"],
    jwt_issuer_crt_path=config["session"]["jwt_issuer_crt_path"],
    jwt_audience=config["session"]["jwt_audience"],
    mock_enabled=config.getboolean("app", "mock_enabled"),
    oidc_provider_pub_key=oidc_provider_pub_key,
    session_server_events_enabled=config.getboolean(
        "irma", "session_server_events_enabled", fallback=False
    ),
    session_server_events_timeout=config.getint(
        "irma", "session_server_events_timeout", fallback=2000
    ),
    session_polling_interval=config.getint(
        "irma", "session_polling_interval", fallback=1000
    ),
)
