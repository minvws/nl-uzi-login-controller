from configparser import ConfigParser


from app.services.irma_service import IrmaService
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

redirect_url_ = config.get("app", "redirect_url")

_redis_client = create_redis_client(config["redis"])
_jwt_issuer_cert = load_jwk(config["session"]["jwt_issuer_crt_path"])

oidc_login_method_feature = config.getboolean("app", "oidc_login_method_feature")

JWT_SERVICE = None
OIDC_SERVICE = None
REGISTER_API_CRT = None
REGISTER_API_ISSUER = None

if oidc_login_method_feature:
    jwt_priv_key = load_jwk(config.get("app", "jwt_priv_key_path"))
    jwt_crt_content = file_content_raise_if_none(config.get("app", "jwt_crt_path"))
    REGISTER_API_CRT = load_jwk(config.get("oidc_provider", "register_api_crt_path"))
    REGISTER_API_ISSUER = config.get("oidc_provider", "register_api_jwt_issuer")

    # fetch and load providers
    providers_conf_path = config.get("oidc_provider", "config_list_path")
    oidc_providers = load_oidc_well_known_config(
        providers_config_path=providers_conf_path,
        environment=environment,
        http_timout=http_timeout,
    )

    JWT_SERVICE = JwtService(
        jwt_priv_key=jwt_priv_key, crt_kid=kid_from_certificate(jwt_crt_content)
    )

    OIDC_SERVICE = OidcService(
        oidc_providers=oidc_providers,
        redirect_uri=config["oidc_provider"]["redirect_uri"],
        http_timeout=http_timeout,
        jwt_service=JWT_SERVICE,
        http_retries=config.getint("app", "http_retries", fallback=20),
        http_backof_time=config.getint("app", "http_backof_time", fallback=5),
    )

vite_manifest_service = ViteManifestService(
    base_url=config["app"]["base_url"],
    manifest=json_from_file(config.get("templates", "vite_manifest_path")),
)

template_service = TemplateService(
    jinja_template_directory=config.get("templates", "jinja_path"),
    vite_manifest_service=vite_manifest_service,
)

irma_service = IrmaService(
    irma_internal_server_url=config["irma"]["irma_internal_server_url"],
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    irma_revocation=bool(config["irma"]["irma_revocation"]),
    http_timeout=http_timeout,
)

session_service_ = SessionService(
    redis_client=_redis_client,
    irma_service=irma_service,
    oidc_service=OIDC_SERVICE,
    jwt_service=JWT_SERVICE,
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    redis_namespace=config["redis"]["namespace"],
    expires_in_s=config.getint("redis", "expire", fallback=60),
    jwt_issuer=config["session"]["jwt_issuer"],
    jwt_issuer_crt=_jwt_issuer_cert,
    jwt_audience=config["session"]["jwt_audience"],
    register_api_crt=REGISTER_API_CRT,
    register_api_issuer=REGISTER_API_ISSUER,
    template_service=template_service,
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
