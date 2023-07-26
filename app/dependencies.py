from configparser import ConfigParser


from app.services.irma_service import IrmaService
from app.services.session_service import SessionService
from app.storage.redis.redis_client import create_redis_client


config = ConfigParser()
config.read("app.conf")

redirect_url_ = config.get("app", "redirect_url")

_redis_client = create_redis_client(config["redis"])

irma_service = IrmaService(
    irma_internal_server_url=config["irma"]["irma_internal_server_url"],
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    irma_revocation=bool(config["irma"]["irma_revocation"]),
)

session_service_ = SessionService(
    redis_client=_redis_client,
    irma_service=irma_service,
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    redis_namespace=config["redis"]["namespace"],
    expires_in_s=int(config["redis"]["expire"]),
    jwt_issuer=config["session"]["jwt_issuer"],
    jwt_issuer_crt_path=config["session"]["jwt_issuer_crt_path"],
    jwt_audience=config["session"]["jwt_audience"],
    mock_enabled=config.getboolean("app", "mock_enabled"),
    session_server_events_enabled=config.getboolean(
        "irma", "session_server_events_enabled", fallback=False
    ),
    session_server_events_timeout=config.get(
        "irma", "session_server_events_timeout", fallback=2000
    ),
    session_polling_interval=config.get(
        "irma", "session_polling_interval", fallback=1000
    ),
)
