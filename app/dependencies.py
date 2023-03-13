from configparser import ConfigParser

from redis import Redis

from app.services.irma_service import IrmaService

config = ConfigParser()
config.read("app.conf")

redirect_url_ = config.get("app", "redirect_url")

_redis_client = Redis(host=config["redis"]["host"], port=int(config["redis"]["port"]))


irma_service_ = IrmaService(
    redis_client=_redis_client,
    irma_internal_server_url=config["irma"]["irma_internal_server_url"],
    irma_disclose_prefix=config["irma"]["irma_disclose_prefix"],
    redis_namespace=config["redis"]["namespace"],
    expires_in_s=int(config["redis"]["expire"]),
    jwt_issuer=config["session"]["jwt_issuer"],
    jwt_issuer_crt_path=config["session"]["jwt_issuer_crt_path"],
    jwt_audience=config["session"]["jwt_audience"]
)
